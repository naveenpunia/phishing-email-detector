/**
 * MailArmor - Frontend Logic & Dashboard Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    // Theme Management
    const themeToggleBtn = document.getElementById('theme-toggle');
    const htmlElement = document.documentElement;
    
    const savedTheme = localStorage.getItem('theme') || 'dark';
    htmlElement.setAttribute('data-theme', savedTheme);

    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = htmlElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        htmlElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });

    // View Switching (Tab Navigation)
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const viewTitle = document.getElementById('view-title');
    const viewSubtitle = document.getElementById('view-subtitle');

    const viewMeta = {
        'dashboard': { title: 'Dashboard Overview', subtitle: 'Analyzing email threats & statistics' },
        'analyze': { title: 'Threat Analyzer', subtitle: 'Scan email parameters for security indicators' },
        'history': { title: 'History Log', subtitle: 'Review previously analyzed emails and alerts' },
        'quiz': { title: 'Awareness Quiz', subtitle: 'Test your phishing identification skills' },
        'awareness': { title: 'Security Guides', subtitle: 'Learn how to identify email fraud patterns' }
    };

    function switchView(viewName) {
        // Toggle Nav active state
        navItems.forEach(btn => {
            if (btn.getAttribute('data-view') === viewName) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Toggle Section display
        sections.forEach(sec => {
            if (sec.id === `view-${viewName}`) {
                sec.classList.remove('hidden');
            } else {
                sec.classList.add('hidden');
            }
        });

        // Update titles
        if (viewMeta[viewName]) {
            viewTitle.textContent = viewMeta[viewName].title;
            viewSubtitle.textContent = viewMeta[viewName].subtitle;
        }

        // Fetch data if entering dashboard or history views
        if (viewName === 'dashboard') {
            loadDashboardStats();
        } else if (viewName === 'history') {
            loadHistoryTable();
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetView = item.getAttribute('data-view');
            switchView(targetView);
        });
    });

    // Handle dashboard link button
    document.getElementById('nav-to-quiz-btn').addEventListener('click', () => {
        switchView('quiz');
    });

    // Device-Based LocalStorage History Helpers
    function getHistory() {
        const history = localStorage.getItem('email_scan_history');
        return history ? JSON.parse(history) : [];
    }

    function saveHistory(history) {
        localStorage.setItem('email_scan_history', JSON.stringify(history));
    }

    function addToHistory(record) {
        let history = getHistory();
        record.id = Date.now();
        record.timestamp = new Date().toISOString();
        history.unshift(record);
        if (history.length > 30) {
            history.pop();
        }
        saveHistory(history);
    }

    // Dashboard Data loading from local history
    function loadDashboardStats() {
        const history = getHistory();
        const total = history.length;
        
        let totalScore = 0;
        let highCount = 0;
        let warnCount = 0;
        let safeCount = 0;
        
        history.forEach(item => {
            totalScore += item.score;
            if (item.classification === 'HIGH RISK') highCount++;
            else if (item.classification === 'WARNING') warnCount++;
            else safeCount++;
        });
        
        const avgScore = total > 0 ? Math.round(totalScore / total) : 0;
        
        document.getElementById('stat-total').textContent = total;
        document.getElementById('stat-avg-score').textContent = `${avgScore}%`;
        document.getElementById('stat-high-risk').textContent = highCount;
        document.getElementById('stat-safe-warning').textContent = `${safeCount} / ${warnCount}`;

        // Calculate heights for threat distribution bar charts
        const highPct = total > 0 ? (highCount / total) * 100 : 0;
        const warnPct = total > 0 ? (warnCount / total) * 100 : 0;
        const safePct = total > 0 ? (safeCount / total) * 100 : 0;

        document.getElementById('bar-high').style.height = `${Math.max(highPct, 5)}%`;
        document.getElementById('bar-warn').style.height = `${Math.max(warnPct, 5)}%`;
        document.getElementById('bar-safe').style.height = `${Math.max(safePct, 5)}%`;

        // Load Leaderboard (remains global)
        loadLeaderboard();
    }

    async function loadLeaderboard() {
        const listContainer = document.getElementById('leaderboard-list');
        try {
            const response = await fetch('/api/leaderboard');
            const leaderboard = await response.json();
            
            if (leaderboard.length === 0) {
                listContainer.innerHTML = '<div class="empty-list">No scores posted yet. Be the first to score!</div>';
                return;
            }

            listContainer.innerHTML = leaderboard.map((row, idx) => `
                <div class="leaderboard-row">
                    <div class="leaderboard-user">
                        <span class="leaderboard-rank">${idx + 1}</span>
                        <span>${escapeHtml(row.username)}</span>
                    </div>
                    <span class="leaderboard-score">${row.score} / ${row.total}</span>
                </div>
            `).join('');
        } catch (err) {
            listContainer.innerHTML = '<div class="empty-list">Failed to load leaderboard.</div>';
        }
    }

    // Email Analysis handling
    const analyzeForm = document.getElementById('analyze-form');
    const analyzeSubmitBtn = document.getElementById('analyze-submit-btn');
    const submitBtnText = analyzeSubmitBtn.querySelector('.btn-text');
    const submitBtnSpinner = analyzeSubmitBtn.querySelector('.loader-spinner');
    
    const resultsPlaceholder = document.getElementById('analysis-results-placeholder');
    const resultsPanel = document.getElementById('analysis-results-panel');

    const senderInput = document.getElementById('sender-input');
    const subjectInput = document.getElementById('subject-input');
    const attachmentsInput = document.getElementById('attachments-input');
    const bodyInput = document.getElementById('body-input');
    const uploadedFilesList = document.getElementById('uploaded-files-list');
    const uploadLabelText = document.getElementById('upload-label-text');

    function resetAttachments() {
        attachmentsInput.value = '';
        uploadedFilesList.innerHTML = '';
        uploadLabelText.textContent = 'Select email attachments...';
    }

    attachmentsInput.addEventListener('change', () => {
        const files = Array.from(attachmentsInput.files);
        if (files.length === 0) {
            resetAttachments();
            return;
        }
        
        uploadLabelText.textContent = `${files.length} file(s) selected`;
        uploadedFilesList.innerHTML = files.map(file => {
            const sizeKB = (file.size / 1024).toFixed(1);
            return `
                <div class="file-item" style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-secondary); margin-top: 8px; background: rgba(255,255,255,0.02); padding: 6px 12px; border-radius: 8px; border: 1px solid var(--bg-card-border);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" style="color: var(--accent-blue); flex-shrink: 0;">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    <span style="font-weight: 500; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 240px;">${escapeHtml(file.name)}</span>
                    <span style="color: var(--text-muted); font-size: 11px; flex-shrink: 0;">(${sizeKB} KB)</span>
                </div>
            `;
        }).join('');
    });

    analyzeForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Loading states
        analyzeSubmitBtn.disabled = true;
        submitBtnText.classList.add('hidden');
        submitBtnSpinner.classList.remove('hidden');

        const attachmentNames = Array.from(attachmentsInput.files).map(file => file.name).join(', ');

        const payload = {
            sender: senderInput.value.trim(),
            subject: subjectInput.value.trim(),
            attachments: attachmentNames,
            body: bodyInput.value.trim()
        };

        try {
            const response = await fetch('/api/analyze-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error('Analysis request failed on server.');
            }

            const report = await response.json();
            report.original_body = payload.body;
            addToHistory(report);
            renderAnalysisReport(report);
            loadDashboardStats();
        } catch (err) {
            alert(err.message || 'Error communicating with analyzer server.');
        } finally {
            analyzeSubmitBtn.disabled = false;
            submitBtnText.classList.remove('hidden');
            submitBtnSpinner.classList.add('hidden');
        }
    });

    function renderAnalysisReport(report) {
        // Toggle view blocks
        resultsPlaceholder.classList.add('hidden');
        resultsPanel.classList.remove('hidden');

        // Set class badge based on risk level
        const classBadge = document.getElementById('results-classification');
        classBadge.className = 'results-badge'; // Reset
        classBadge.textContent = report.classification;
        if (report.classification === 'HIGH RISK') {
            classBadge.classList.add('high');
        } else if (report.classification === 'WARNING') {
            classBadge.classList.add('warning');
        } else {
            classBadge.classList.add('safe');
        }

        // Set numerical score
        document.getElementById('results-score').textContent = report.score;

        // Render highlighted email body
        // Note: report.highlighted_body contains parsed HTML tags generated by our server safely
        document.getElementById('results-highlighted-body').innerHTML = report.highlighted_body;

        // Render findings
        const findingsList = document.getElementById('results-findings-list');
        if (report.findings.length === 0) {
            findingsList.innerHTML = '<div class="finding-item">No suspicious heuristics triggered.</div>';
        } else {
            findingsList.innerHTML = report.findings.map(finding => `
                <div class="finding-item ${finding.severity}">
                    <div class="finding-title">${finding.category}</div>
                    <div class="finding-desc">${escapeHtml(finding.message)}</div>
                </div>
            `).join('');
        }

        // Render recommendations
        const recList = document.getElementById('results-recommendations-list');
        recList.innerHTML = report.recommendations.map(rec => `
            <li>${escapeHtml(rec)}</li>
        `).join('');
    }

    // Reset Analysis Panel button
    document.getElementById('new-analysis-btn').addEventListener('click', () => {
        analyzeForm.reset();
        resetAttachments();
        resultsPanel.classList.add('hidden');
        resultsPlaceholder.classList.remove('hidden');
    });

    // History Log loading from local storage
    const historyTableBody = document.getElementById('history-table-body');
    const emptyHistoryState = document.getElementById('empty-history-state');

    function loadHistoryTable() {
        const history = getHistory();
        
        if (history.length === 0) {
            historyTableBody.innerHTML = '';
            emptyHistoryState.classList.remove('hidden');
            return;
        }

        emptyHistoryState.classList.add('hidden');
        historyTableBody.innerHTML = history.map(row => {
            const dateObj = new Date(row.timestamp);
            const localDateStr = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            
            let badgeClass = 'safe';
            if (row.classification === 'HIGH RISK') badgeClass = 'high risk';
            else if (row.classification === 'WARNING') badgeClass = 'warning';

            return `
                <tr>
                    <td>${localDateStr}</td>
                    <td class="history-sender" title="${escapeHtml(row.sender)}">${escapeHtml(row.sender)}</td>
                    <td class="history-subject" title="${escapeHtml(row.subject)}">${escapeHtml(row.subject)}</td>
                    <td class="history-score-val">${row.score}%</td>
                    <td><span class="history-badge ${badgeClass}">${row.classification}</span></td>
                    <td>
                        <button class="btn btn-secondary inspect-history-btn" data-id="${row.id}">Inspect</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Add Click listeners for inspection buttons
        document.querySelectorAll('.inspect-history-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                inspectHistoryRecord(id);
            });
        });
    }

    function inspectHistoryRecord(id) {
        const history = getHistory();
        const record = history.find(item => item.id == id);
        if (!record) {
            alert('Record not found.');
            return;
        }
        
        // Populate form input boxes
        senderInput.value = record.sender;
        subjectInput.value = record.subject;
        resetAttachments(); // Reset file upload picker
        bodyInput.value = record.original_body;

        // Render details
        renderAnalysisReport(record);

        // Navigate view
        switchView('analyze');
    }

    document.getElementById('refresh-history-btn').addEventListener('click', loadHistoryTable);
    
    document.getElementById('clear-history-btn').addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all local scan logs?')) {
            saveHistory([]);
            loadHistoryTable();
            loadDashboardStats();
        }
    });

    // --- Interactive Cybersecurity Awareness Quiz Engine ---
    const quizQuestions = [
        {
            question: "You receive an email from 'Netflix Support' claiming your card payment failed. However, the sender address is 'noreply-billing@netflix-accounts-verify.com'. What should you check first?",
            options: [
                "The email subject line urgency.",
                "The spelling of the domain name (look-alike domain spoofing).",
                "How many links are in the body.",
                "If there is a profile picture next to the sender name."
            ],
            answer: 1, // 0-indexed, option 2
            explanation: "Look-alike domains are common spoofing tactics. Attackers replace letters or add hyphens (like 'netflix-accounts-verify.com') to confuse users. Legitimate companies send billing notifications from their primary company domain names."
        },
        {
            question: "If a text link in an email body displays 'https://chase.com/login', but hovering over it reveals it directs to 'http://login-chase-update.info/secure', what type of check did this URL fail?",
            options: [
                "Sender SPF record check.",
                "Text-versus-target destination mismatch check.",
                "Subject line threat keyword analysis.",
                "Subdomain depth verify check."
            ],
            answer: 1, // option 2
            explanation: "Link Hijacking occurs when the link label (what you see) differs from the actual hyperlink destination address (where it takes you). Hovering confirms the target host mismatch."
        },
        {
            question: "Why are attachment file extensions like '.exe', '.bat', '.scr', or '.xlsm' considered high security threats in emails?",
            options: [
                "They occupy too much storage space in the email server inbox.",
                "They are older file formats that modern browsers cannot open.",
                "They are executable scripts/macros capable of installing ransomware or malware directly onto your device.",
                "They prevent the browser from reloading CSS styles properly."
            ],
            answer: 2, // option 3
            explanation: "Executable files (.exe, .scr) or macro-enabled documents (.xlsm, .docm) can launch installers that execute script commands, download malware, or infect systems automatically."
        },
        {
            question: "An email contains the phrase 'Your account will be terminated within 24 hours if you do not verify your password immediately.' What is this tactic?",
            options: [
                "Urgent/Coercive pressure language designed to bypass logical caution.",
                "Official automated security reminder protocol.",
                "Standard user data clean up notification.",
                "Spam filter testing protocol."
            ],
            answer: 0, // option 1
            explanation: "Urgency cues (like threat of deactivation within 24h) trigger stress reactions, rushing the victim into typing credentials on malicious forms without validating domain handles."
        },
        {
            question: "What does an SPF (Sender Policy Framework) record do?",
            options: [
                "Encrypts the contents of the email body.",
                "Scans files attached to the email for hidden trojans.",
                "Permits specific IP addresses/servers to send emails on behalf of a domain name to prevent sender address spoofing.",
                "Provides the recipient with a secure password reset button."
            ],
            answer: 2, // option 3
            explanation: "SPF records are DNS indicators published by domain owners listing authorized mail servers. If a server not listed tries to spoof the domain, receivers flag it as failed SPF."
        }
    ];

    let currentQuestionIdx = 0;
    let quizUserScore = 0;
    let quizUserName = "";

    const quizStartCard = document.getElementById('quiz-start-card');
    const quizQuestionCard = document.getElementById('quiz-question-card');
    const quizScoreCard = document.getElementById('quiz-score-card');
    
    const quizUsernameInput = document.getElementById('quiz-username');
    const startQuizBtn = document.getElementById('start-quiz-btn');
    
    const quizProgressBarFill = document.getElementById('quiz-progress-fill');
    const quizQuestionNumber = document.getElementById('quiz-question-number');
    const quizQuestionText = document.getElementById('quiz-question-text');
    const quizOptionsList = document.getElementById('quiz-options-list');
    const nextQuestionBtn = document.getElementById('next-question-btn');

    startQuizBtn.addEventListener('click', () => {
        const username = quizUsernameInput.value.trim();
        if (!username) {
            alert('Please enter a username to record your score.');
            return;
        }
        quizUserName = username;
        currentQuestionIdx = 0;
        quizUserScore = 0;
        
        quizStartCard.classList.add('hidden');
        quizQuestionCard.classList.remove('hidden');
        renderQuizQuestion();
    });

    function renderQuizQuestion() {
        const q = quizQuestions[currentQuestionIdx];
        
        // Update Progress bar
        const progressPct = ((currentQuestionIdx) / quizQuestions.length) * 100;
        quizProgressBarFill.style.width = `${progressPct}%`;
        
        // Update Q number
        quizQuestionNumber.textContent = `Question ${currentQuestionIdx + 1} of ${quizQuestions.length}`;
        
        // Set text
        quizQuestionText.textContent = q.question;
        
        // Clear previous options
        quizOptionsList.innerHTML = '';
        nextQuestionBtn.classList.add('hidden');
        
        // Render options list
        q.options.forEach((opt, idx) => {
            const btn = document.createElement('button');
            btn.className = 'quiz-option';
            btn.innerHTML = opt;
            btn.addEventListener('click', () => handleOptionSelection(idx, btn));
            quizOptionsList.appendChild(btn);
        });
    }

    function handleOptionSelection(selectedIdx, selectedBtn) {
        const q = quizQuestions[currentQuestionIdx];
        const allOptionBtns = quizOptionsList.querySelectorAll('.quiz-option');
        
        // Disable further clicking on options
        allOptionBtns.forEach(btn => btn.disabled = true);
        
        const isCorrect = selectedIdx === q.answer;
        if (isCorrect) {
            quizUserScore++;
            selectedBtn.classList.add('correct');
        } else {
            selectedBtn.classList.add('incorrect');
            // Highlight correct option
            allOptionBtns[q.answer].classList.add('correct');
        }
        
        // Append explanation feedback block below options
        const feedback = document.createElement('div');
        feedback.className = `quiz-feedback-box ${isCorrect ? 'correct' : 'incorrect'}`;
        feedback.innerHTML = `<strong>${isCorrect ? '✓ Correct!' : '✗ Incorrect.'}</strong> ${q.explanation}`;
        quizOptionsList.appendChild(feedback);
        
        // Reveal next button
        nextQuestionBtn.classList.remove('hidden');
    }

    nextQuestionBtn.addEventListener('click', () => {
        currentQuestionIdx++;
        if (currentQuestionIdx < quizQuestions.length) {
            renderQuizQuestion();
        } else {
            finishQuiz();
        }
    });

    async function finishQuiz() {
        quizQuestionCard.classList.add('hidden');
        quizScoreCard.classList.remove('hidden');
        
        document.getElementById('final-score-val').textContent = quizUserScore;
        document.getElementById('final-score-total').textContent = quizQuestions.length;

        // Custom evaluator messages
        const evalText = document.getElementById('score-evaluation-text');
        if (quizUserScore === 5) {
            evalText.innerHTML = '🥇 Perfect Score! You are a Phishing Identification expert!';
        } else if (quizUserScore >= 3) {
            evalText.innerHTML = '🥈 Good job! You have solid foundational knowledge. Keep reviews up!';
        } else {
            evalText.innerHTML = '🛡️ Needs Improvement. Please read our security guide check-lists to raise awareness.';
        }

        // Post score to database
        try {
            const response = await fetch('/api/quiz', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: quizUserName,
                    score: quizUserScore,
                    total: quizQuestions.length
                })
            });
            const data = await response.json();
            
            // Render leaderboard inside score page
            const miniLeaderboard = document.getElementById('quiz-mini-leaderboard');
            if (data.leaderboard && data.leaderboard.length > 0) {
                miniLeaderboard.innerHTML = data.leaderboard.map((row, idx) => `
                    <div class="leaderboard-row">
                        <div class="leaderboard-user">
                            <span class="leaderboard-rank">${idx + 1}</span>
                            <span>${escapeHtml(row.username)}</span>
                        </div>
                        <span class="leaderboard-score">${row.score} / ${row.total}</span>
                    </div>
                `).join('');
            }
        } catch (err) {
            console.error('Leaderboard post error:', err);
        }
    }

    document.getElementById('retry-quiz-btn').addEventListener('click', () => {
        quizScoreCard.classList.add('hidden');
        quizStartCard.classList.remove('hidden');
        quizUsernameInput.value = quizUserName;
    });

    document.getElementById('exit-quiz-btn').addEventListener('click', () => {
        quizScoreCard.classList.add('hidden');
        switchView('dashboard');
    });

    // Helper functions
    function escapeHtml(text) {
        if (!text) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    // Initialize Dashboard data on page load
    loadDashboardStats();
});
