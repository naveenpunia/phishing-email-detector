import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_detector.db')

def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create scans history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            sender TEXT NOT NULL,
            body TEXT NOT NULL,
            score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            flags TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create quiz scores leaderboard table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def save_scan(subject, sender, body, score, classification, flags):
    """Saves an email scan result into the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (subject, sender, body, score, classification, flags)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (subject, sender, body, score, classification, json.dumps(flags)))
    conn.commit()
    conn.close()

def get_history(limit=50):
    """Retrieves list of previous scans."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, subject, sender, score, classification, timestamp 
        FROM scans 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            'id': row['id'],
            'subject': row['subject'],
            'sender': row['sender'],
            'score': row['score'],
            'classification': row['classification'],
            'timestamp': row['timestamp']
        })
    return history

def get_scan_detail(scan_id):
    """Fetches a detailed record of a single scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'subject': row['subject'],
            'sender': row['sender'],
            'body': row['body'],
            'score': row['score'],
            'classification': row['classification'],
            'flags': json.loads(row['flags']),
            'timestamp': row['timestamp']
        }
    return None

def get_stats():
    """Calculates aggregate statistics for the dashboard dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]
    
    if total_scans == 0:
        conn.close()
        return {
            'total_scans': 0,
            'avg_score': 0,
            'high_risk_count': 0,
            'warning_count': 0,
            'safe_count': 0,
            'recent_activity': []
        }
        
    # Average score
    cursor.execute('SELECT AVG(score) FROM scans')
    avg_score = round(cursor.fetchone()[0], 1)
    
    # Classification counts
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'HIGH RISK'")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'WARNING'")
    warning = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SAFE'")
    safe = cursor.fetchone()[0]
    
    # Get last 7 days scanning trend (mock dates or real sqlite groupings)
    # We will get counts grouped by date for the trend graph
    cursor.execute('''
        SELECT DATE(timestamp) as scan_date, COUNT(*) as count, AVG(score) as score
        FROM scans
        GROUP BY scan_date
        ORDER BY scan_date ASC
        LIMIT 7
    ''')
    trend_rows = cursor.fetchall()
    trend = [{'date': r['scan_date'], 'count': r['count'], 'avg_score': round(r['score'], 1)} for r in trend_rows]
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'avg_score': avg_score,
        'high_risk_count': high_risk,
        'warning_count': warning,
        'safe_count': safe,
        'trend': trend
    }

def save_quiz_score(username, score, total):
    """Saves a user's quiz score."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO quiz_scores (username, score, total)
        VALUES (?, ?, ?)
    ''', (username, score, total))
    conn.commit()
    conn.close()

def get_leaderboard(limit=10):
    """Retrieves top scores for the quiz leaderboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, score, total, timestamp 
        FROM quiz_scores 
        ORDER BY score DESC, timestamp DESC 
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    leaderboard = []
    for row in rows:
        leaderboard.append({
            'username': row['username'],
            'score': row['score'],
            'total': row['total'],
            'timestamp': row['timestamp']
        })
    return leaderboard

# Initialize database tables on module import
init_db()
