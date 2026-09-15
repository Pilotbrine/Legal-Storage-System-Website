import sqlite3
import hashlib
import uuid
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for external frontend domains

DB_NAME = "app.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            badge_id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT DEFAULT 'pending'
        )
    ''')

    # Documents Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            category TEXT NOT NULL,
            mimeType TEXT NOT NULL,
            uploader TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            originalHash TEXT NOT NULL,
            data TEXT NOT NULL,
            salt TEXT NOT NULL,
            iv TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    ''')

    # Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    ''')

    # Password Resets Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            request_id TEXT PRIMARY KEY,
            badge_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending'
        )
    ''')

    # Create default Admin if not exists
    cursor.execute("SELECT * FROM users WHERE badge_id = 'ADMIN-01'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (badge_id, password, role, status) VALUES (?, ?, ?, ?)",
                       ('ADMIN-01', 'admin123', 'Admin', 'approved'))

    conn.commit()
    conn.close()

init_db()

def log_action(user, action, details, reason):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    log_id = 'LOG-' + uuid.uuid4().hex[:8].upper()
    import time
    timestamp = int(time.time() * 1000)
    cursor.execute('''
        INSERT INTO audit_logs (id, user, action, details, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (log_id, user, action, details, reason, timestamp))
    conn.commit()
    conn.close()

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'FRONTEND.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    badge_id = data.get('badge_id', '').strip().upper()
    password = data.get('password', '')
    role = data.get('role', 'Investigator')

    if not badge_id or not password:
        return jsonify({"status": "error", "message": "Badge ID and password required."}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE badge_id = ?", (badge_id,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Badge ID already registered."}), 400

    # Auto-approve investigators and witnesses, require admin approval for supervisors/admins
    status = 'approved' if role in ['Investigator', 'External Witness'] else 'pending'
    
    cursor.execute("INSERT INTO users (badge_id, password, role, status) VALUES (?, ?, ?, ?)",
                   (badge_id, password, role, status))
    conn.commit()
    conn.close()

    msg = "Account created successfully." if status == 'approved' else "Registration submitted. Awaiting Admin approval."
    log_action(badge_id, "USER_REGISTER", f"Registered new account with role {role}", "New Account Registration")
    return jsonify({"status": "success", "message": msg})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    badge_id = data.get('badge_id', '').strip().upper()
    password = data.get('password', '')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password, role, status FROM users WHERE badge_id = ?", (badge_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "Invalid Badge ID or Passcode."}), 401

    db_pass, role, status = user

    if db_pass != password:
        log_action(badge_id, "SECURITY_LOGIN_FAILED", "Incorrect password attempt", "Authentication Failure")
        return jsonify({"status": "error", "message": "Invalid Badge ID or Passcode."}), 401

    if status != 'approved':
        return jsonify({"status": "error", "message": "Account pending administrator approval."}), 403

    log_action(badge_id, "SECURITY_LOGIN_SUCCESS", f"Successful login as {role}", "System Access")
    return jsonify({"status": "success", "role": role})

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    badge_id = data.get('badge_id', '').strip().upper()
    reason = data.get('reason', 'Forgotten passcode')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE badge_id = ?", (badge_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Badge ID not found."}), 404

    request_id = 'REQ-' + uuid.uuid4().hex[:8].upper()
    cursor.execute("INSERT INTO password_resets (request_id, badge_id, reason, status) VALUES (?, ?, ?, ?)",
                   (request_id, badge_id, reason, 'pending'))
    conn.commit()
    conn.close()

    log_action(badge_id, "PASSWORD_RESET_REQUEST", f"Requested password reset", reason)
    return jsonify({"status": "success", "message": "Password reset request submitted to administrators."})

@app.route('/admin/pending_users', methods=['GET'])
def pending_users():
    admin_id = request.headers.get('X-User-ID')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE badge_id = ?", (admin_id,))
    row = cursor.fetchone()
    if not row or row[0] != 'Admin':
        conn.close()
        return jsonify({"message": "Unauthorized"}), 403

    cursor.execute("SELECT badge_id, role FROM users WHERE status = 'pending'")
    users = [{"badge_id": r[0], "role": r[1]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/admin/approve_user', methods=['POST'])
def approve_user():
    admin_id = request.headers.get('X-User-ID')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE badge_id = ?", (admin_id,))
    row = cursor.fetchone()
    if not row or row[0] != 'Admin':
        conn.close()
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    target_badge = data.get('target_badge_id')
    approved = data.get('approved', False)

    if approved:
        cursor.execute("UPDATE users SET status = 'approved' WHERE badge_id = ?", (target_badge,))
        msg = f"User {target_badge} approved."
    else:
        cursor.execute("DELETE FROM users WHERE badge_id = ?", (target_badge,))
        msg = f"User {target_badge} rejected and removed."

    conn.commit()
    conn.close()
    log_action(admin_id, "ADMIN_USER_APPROVAL", msg, "Administrative User Management")
    return jsonify({"status": "success", "message": msg})

@app.route('/admin/pending_resets', methods=['GET'])
def pending_resets():
    admin_id = request.headers.get('X-User-ID')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE badge_id = ?", (admin_id,))
    row = cursor.fetchone()
    if not row or row[0] != 'Admin':
        conn.close()
        return jsonify({"message": "Unauthorized"}), 403

    cursor.execute("SELECT request_id, badge_id, reason FROM password_resets WHERE status = 'pending'")
    resets = [{"request_id": r[0], "badge_id": r[1], "reason": r[2]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(resets)

@app.route('/admin/reset_password', methods=['POST'])
def admin_reset_password():
    admin_id = request.headers.get('X-User-ID')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE badge_id = ?", (admin_id,))
    row = cursor.fetchone()
    if not row or row[0] != 'Admin':
        conn.close()
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    request_id = data.get('request_id')
    badge_id = data.get('badge_id')
    new_password = data.get('new_password')
    approved = data.get('approved', False)

    if approved:
        cursor.execute("UPDATE users SET password = ? WHERE badge_id = ?", (new_password, badge_id))
        cursor.execute("UPDATE password_resets SET status = 'approved' WHERE request_id = ?", (request_id,))
        msg = f"Password updated for {badge_id}."
    else:
        cursor.execute("UPDATE password_resets SET status = 'rejected' WHERE request_id = ?", (request_id,))
        msg = f"Password reset rejected for {badge_id}."

    conn.commit()
    conn.close()
    log_action(admin_id, "ADMIN_PASSWORD_RESET", msg, "Administrative Passcode Management")
    return jsonify({"status": "success", "message": msg})

@app.route('/upload', methods=['POST'])
def upload_document():
    data = request.json
    user_id = request.headers.get('X-User-ID', 'UNKNOWN')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO documents (id, filename, category, mimeType, uploader, timestamp, originalHash, data, salt, iv, expires_at, signature, public_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['id'], data['filename'], data['category'], data['mimeType'], data['uploader'],
        data['timestamp'], data['originalHash'], data['data'], data['salt'], data['iv'],
        data['expires_at'], data['signature'], data['public_key']
    ))
    conn.commit()
    conn.close()

    log_action(user_id, "INGESTION_UPLOAD", f"Uploaded and signed document {data['filename']} ({data['id']})", f"Category: {data['category']}")
    return jsonify({"status": "success", "message": "Document successfully uploaded and indexed."})

@app.route('/documents', methods=['GET'])
def get_documents():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, category, mimeType, uploader, timestamp, expires_at FROM documents")
    rows = cursor.fetchall()
    conn.close()

    import time
    current_time = int(time.time() * 1000)

    docs = []
    for r in rows:
        expires_at = r[6]
        is_expired = expires_at > 0 and current_time > expires_at
        docs.append({
            "id": r[0], "filename": r[1], "category": r[2], "mimeType": r[3],
            "uploader": r[4], "timestamp": r[5], "expires_at": expires_at, "is_expired": is_expired
        })
    return jsonify(docs)

@app.route('/log_custody', methods=['POST'])
def log_custody():
    data = request.json
    log_action(data.get('user', 'UNKNOWN'), data.get('action', 'CUSTODY_VIEW'), data.get('details', ''), data.get('reason', 'Court Order'))
    return jsonify({"status": "success"})

@app.route('/audit', methods=['GET'])
def get_audit():
    user_id = request.headers.get('X-User-ID')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE badge_id = ?", (user_id,))
    row = cursor.fetchone()
    
    if not row or row[0] not in ['Supervisor', 'Admin']:
        conn.close()
        return jsonify({"message": "Forbidden"}), 403

    cursor.execute("SELECT id, user, action, details, reason, timestamp FROM audit_logs ORDER BY timestamp DESC")
    logs = [{"id": r[0], "user": r[1], "action": r[2], "details": r[3], "reason": r[4], "timestamp": r[5]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

if __name__ == '__main__':
    app.run(debug=True, port=8000)