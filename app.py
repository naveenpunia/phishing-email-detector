import os
import re
import urllib.parse
from flask import Flask, request, jsonify, render_template
import database
import classifier
import domain_verifier

app = Flask(__name__)

# Heuristic list definitions for regex scanner
URGENCY_KEYWORDS = [
    r'\baction\s+required\b', r'\bsuspended\b', r'\bunauthorized\b', r'\bverify\b',
    r'\bimmediately\b', r'\bsecurity\s+alert\b', r'\bbilling\s+issue\b', r'\boverdue\b',
    r'\blast\s+warning\b', r'\burgent\b', r'\bterminate\b', r'\bdeactivated\b'
]

SENSITIVE_KEYWORDS = [
    r'\bpassword\b', r'\bcredential\b', r'\bsocial\s+security\b', r'\bssn\b',
    r'\bcredit\s+card\b', r'\bpin\b', r'\bbank\s+details\b', r'\brouting\b',
    r'\blogin\b', r'\bverify\s+identity\b', r'\binvoice\b'
]

DANGEROUS_EXTENSIONS = ['.exe', '.scr', '.js', '.vbs', '.bat', '.zip', '.rar', '.docm', '.xlsm', '.jar', '.com']

BRAND_KEYWORDS = ['paypal', 'netflix', 'amazon', 'google', 'apple', 'microsoft', 'chase', 'bankofamerica', 'wellsFargo', 'instagram', 'facebook']

SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']

# Common phishing grammar and misspelling indicators
GRAMMAR_ERRORS = [
    (r'\brecieve\b', 'recieve (receive)'),
    (r'\bimmediatly\b', 'immediatly (immediately)'),
    (r'\bverifcation\b', 'verifcation (verification)'),
    (r'\bacount\b', 'acount (account)'),
    (r'\bupdate\s+your\s+inboxs\b', 'inboxs (inbox)'),
    (r'\bdeactived\b', 'deactived (deactivated)'),
    (r'\bpaypent\b', 'paypent (payment)'),
    (r'\bsecurty\b', 'securty (security)'),
    (r'\bclick\s+here\s+to\s+confirm\s+you\b', 'missing object (confirm you -> confirm yourself/your account)'),
    (r'!!{2,}', 'Multiple exclamation marks'),
    (r'\b[a-zA-Z]+\s+,\s+[a-zA-Z]+\b', 'Spacing preceding punctuation'),
    (r'\b[a-zA-Z]+\s+\.\s+[a-zA-Z]+\b', 'Spacing preceding punctuation')
]

def extract_urls(text):
    """Helper to extract raw URLs from plain text body."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def check_link_safety(url):
    """Checks URL metrics and returns a list of risk flags."""
    flags = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ''
    except Exception:
        return [{'type': 'invalid_url', 'message': 'Malformed link detected.'}]

    # Insecure Protocol
    if parsed.scheme == 'http':
        flags.append({
            'type': 'insecure_link',
            'message': f'Link targets insecure HTTP address: {url}'
        })
        
    # IP Domain Hostname
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname):
        flags.append({
            'type': 'ip_host',
            'message': f'Link hosts raw IP instead of domain name: {hostname}'
        })
        
    # URL Shorteners
    if any(s in hostname.lower() for s in SHORTENER_DOMAINS):
        flags.append({
            'type': 'shortener',
            'message': f'Link masks destination using URL shortener service: {hostname}'
        })
            
    return flags

def parse_and_highlight_body(body):
    """
    Parses the email body text, extracts phishing keywords, urgency triggers,
    grammar issues, and mismatching links, then returns highlighted HTML content.
    """
    highlighted = body
    detected_flags = []
    
    # 1. Check and highlight links
    raw_urls = list(set(extract_urls(body)))
    link_flags = []
    for url in raw_urls:
        url_flags = check_link_safety(url)
        if url_flags:
            link_flags.extend(url_flags)
            safe_url_esc = re.escape(url)
            highlighted = re.sub(
                safe_url_esc,
                f'<mark class="flag-url" title="{url_flags[0]["message"]}">{url}</mark>',
                highlighted
            )

    # 2. Highlight urgency keywords
    for keyword_regex in URGENCY_KEYWORDS:
        matches = re.findall(keyword_regex, highlighted, re.IGNORECASE)
        for match in set(matches):
            highlighted = re.sub(
                rf'\b{re.escape(match)}\b',
                f'<mark class="flag-urgency" title="Urgency trigger detected">{match}</mark>',
                highlighted,
                flags=re.IGNORECASE
            )
            detected_flags.append({
                'category': 'Urgent Language',
                'message': f'Urgent/Coercive keyword detected: "{match}"'
            })

    # 3. Highlight sensitive keywords
    for keyword_regex in SENSITIVE_KEYWORDS:
        matches = re.findall(keyword_regex, highlighted, re.IGNORECASE)
        for match in set(matches):
            highlighted = re.sub(
                rf'\b{re.escape(match)}\b',
                f'<mark class="flag-keyword" title="Sensitive data request">{match}</mark>',
                highlighted,
                flags=re.IGNORECASE
            )
            detected_flags.append({
                'category': 'Sensitive Request',
                'message': f'Sensitive keyword requesting credentials/private info: "{match}"'
            })

    # 4. Highlight Grammar / Spelling issues
    for grammar_regex, desc in GRAMMAR_ERRORS:
        matches = re.findall(grammar_regex, highlighted, re.IGNORECASE)
        for match in set(matches):
            highlighted = re.sub(
                re.escape(match) if 'Multiple' in desc or 'Spacing' in desc else rf'\b{re.escape(match)}\b',
                f'<mark class="flag-grammar" title="Potential grammatical error: {desc}">{match}</mark>',
                highlighted,
                flags=re.IGNORECASE
            )
            detected_flags.append({
                'category': 'Poor Grammar',
                'message': f'Common phishing grammatical typo or casing mismatch: "{match}" ({desc})'
            })

    for lf in link_flags:
        detected_flags.append({
            'category': 'Suspicious Link',
            'message': lf['message']
        })

    # Convert linebreaks to HTML tags for rendering previews
    highlighted = highlighted.replace('\n', '<br>')
    
    return highlighted, detected_flags

def analyze_email_details(subject, sender, body, attachments):
    """
    Evaluates email parameters using combined machine learning confidence
    and heuristic analysis rules.
    """
    heuristic_score = 0
    analysis_findings = []
    
    # --- 1. SENDER DOMAIN DIAGNOSTICS (WHOIS & SPF) ---
    domain_report = domain_verifier.analyze_domain(sender)
    
    # Sender spoofing look-alike check
    if domain_report['is_spoof_pattern']:
        heuristic_score += 30
        analysis_findings.append({
            'category': 'Sender Anomaly',
            'severity': 'high',
            'message': domain_report['message']
        })
    # Official brand check on free domains
    elif domain_report['is_free_provider'] and any(b in subject.lower() for b in BRAND_KEYWORDS):
        heuristic_score += 20
        analysis_findings.append({
            'category': 'Sender Anomaly',
            'severity': 'medium',
            'message': 'Sender uses free email hosting (gmail/yahoo) while subject mimics corporate billing claims.'
        })
        
    # SPF Record check
    if not domain_report['spf_found']:
        heuristic_score += 10
        analysis_findings.append({
            'category': 'SPF Check',
            'severity': 'medium',
            'message': 'No Sender Policy Framework (SPF) record found. The sender domain can be easily spoofed.'
        })
    else:
        analysis_findings.append({
            'category': 'SPF Check',
            'severity': 'low',
            'message': f"SPF authentication found: {domain_report['spf_record']}"
        })

    # Domain Age WHOIS check
    if domain_report['domain_age_years'] <= 2:
        heuristic_score += 15
        analysis_findings.append({
            'category': 'WHOIS Check',
            'severity': 'medium',
            'message': f"Domain is newly registered (Age: {domain_report['domain_age_years']} year/s, Date: {domain_report['registration_date']})."
        })
    else:
        analysis_findings.append({
            'category': 'WHOIS Check',
            'severity': 'low',
            'message': f"Domain WHOIS record is stable (Age: {domain_report['domain_age_years']} years)."
        })

    # --- 2. SUBJECT HEURISTICS ---
    subject_urgency = False
    for regex in URGENCY_KEYWORDS:
        if re.search(regex, subject, re.IGNORECASE):
            subject_urgency = True
            break
            
    if subject_urgency:
        heuristic_score += 15
        analysis_findings.append({
            'category': 'Subject Threat',
            'severity': 'medium',
            'message': 'Urgent wording in subject line induces panic.'
        })
        
    if len(subject) > 8 and subject.isupper():
        heuristic_score += 10
        analysis_findings.append({
            'category': 'Subject Threat',
            'severity': 'low',
            'message': 'Subject uses ALL CAPS pressure cues.'
        })

    # --- 3. ATTACHMENT HEURISTICS ---
    found_dangerous_ext = []
    if attachments:
        att_list = [a.strip() for a in attachments.split(',') if a.strip()]
        for att in att_list:
            _, ext = os.path.splitext(att.lower())
            if ext in DANGEROUS_EXTENSIONS:
                found_dangerous_ext.append(att)
                
    if found_dangerous_ext:
        heuristic_score += 25
        analysis_findings.append({
            'category': 'Dangerous Attachment',
            'severity': 'high',
            'message': f"Dangerous attachment format: {', '.join(found_dangerous_ext)}. Could contain executable payload scripts."
        })

    # --- 4. BODY SCANNING ---
    highlighted_body, body_findings = parse_and_highlight_body(body)
    
    # Add body findings
    for bf in body_findings:
        severity = 'medium'
        if bf['category'] == 'Suspicious Link':
            severity = 'high'
            heuristic_score += 15
        elif bf['category'] == 'Sensitive Request':
            severity = 'medium'
            heuristic_score += 10
        elif bf['category'] == 'Poor Grammar':
            severity = 'medium'
            heuristic_score += 10
        else:
            heuristic_score += 5
            
        analysis_findings.append({
            'category': bf['category'],
            'severity': severity,
            'message': bf['message']
        })

    heuristic_score = min(heuristic_score, 100)

    # --- 5. NLP MACHINE LEARNING CLASSIFIER ---
    ml_probability = classifier.predict(subject, body)
    
    # Combined score weights: 60% Heuristics & 40% Naive Bayes NLP Model
    final_score = int((0.6 * heuristic_score) + (0.4 * ml_probability))
    final_score = min(final_score, 100)

    # Risk level classification
    if final_score >= 70:
        classification = 'HIGH RISK'
    elif final_score >= 35:
        classification = 'WARNING'
    else:
        classification = 'SAFE'

    # Build findings list (include ML insight at the top)
    ml_severity = 'low'
    if ml_probability >= 70:
        ml_severity = 'high'
    elif ml_probability >= 35:
        ml_severity = 'medium'
        
    analysis_findings.insert(0, {
        'category': 'ML NLP Classifier',
        'severity': ml_severity,
        'message': f"Scikit-learn Naive Bayes model predicts phishing confidence at {round(ml_probability, 1)}% based on text token patterns."
    })

    # Recommendation list compilation
    recommendations = []
    if final_score >= 70:
        recommendations.append('Do NOT click any links, open attachments, or reply to this message.')
        recommendations.append('Immediately delete or report this email to your organization\'s security center.')
    if domain_report['is_spoof_pattern']:
        recommendations.append('The sender display name is mimicking a brand, but domain handles are fake. Contact the service directly via a browser bookmarks.')
    if not domain_report['spf_found']:
        recommendations.append('Verify the email headers. Lack of SPF indicates the sender email domain could be spoofed.')
    if found_dangerous_ext:
        recommendations.append('Do NOT download or extract attachments ending in script or package extensions (.exe, .zip).')
    if any(bf['category'] == 'Poor Grammar' for bf in body_findings):
        recommendations.append('Be suspicious of official corporate correspondence written with spelling mistakes and incorrect punctuation spacing.')
    if len(recommendations) == 0:
        recommendations.append('Maintain caution and inspect message requests before revealing account credentials.')
        recommendations.append('Keep your operating system and web browser security extensions up to date.')

    return {
        'subject': subject,
        'sender': sender,
        'score': final_score,
        'classification': classification,
        'findings': analysis_findings,
        'highlighted_body': highlighted_body,
        'recommendations': recommendations
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    data = request.get_json() or {}
    subject = data.get('subject', '').strip()
    sender = data.get('sender', '').strip()
    body = data.get('body', '').strip()
    attachments = data.get('attachments', '').strip()
    
    if not subject or not sender or not body:
        return jsonify({'error': 'Subject, Sender, and Email Body are all required.'}), 400

    # Validate that sender contains a valid email address format
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
    if not email_match:
        return jsonify({'error': 'Invalid sender details. Please include a valid email address (e.g. sender@domain.com or Brand <sender@domain.com>).'}), 400

    report = analyze_email_details(subject, sender, body, attachments)
    
    # Return report directly (history is stored device-based client-side)
    return jsonify(report)

@app.route('/api/history', methods=['GET'])
def get_history_api():
    history = database.get_history(limit=15)
    return jsonify(history)

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_history_detail(scan_id):
    detail = database.get_scan_detail(scan_id)
    if not detail:
        return jsonify({'error': 'Scan record not found.'}), 404
        
    report = analyze_email_details(
        subject=detail['subject'],
        sender=detail['sender'],
        body=detail['body'],
        attachments=''
    )
    report['id'] = detail['id']
    report['timestamp'] = detail['timestamp']
    report['original_body'] = detail['body']
    return jsonify(report)

@app.route('/api/stats', methods=['GET'])
def get_stats_api():
    stats = database.get_stats()
    return jsonify(stats)

@app.route('/api/quiz', methods=['POST'])
def submit_quiz_score():
    data = request.get_json() or {}
    username = data.get('username', 'Anonymous').strip()
    score = data.get('score', 0)
    total = data.get('total', 5)
    
    database.save_quiz_score(username, score, total)
    leaderboard = database.get_leaderboard(limit=5)
    return jsonify({
        'status': 'success',
        'leaderboard': leaderboard
    })

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard_api():
    leaderboard = database.get_leaderboard(limit=10)
    return jsonify(leaderboard)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
