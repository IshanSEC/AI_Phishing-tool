import os
import sys
# Allow running app.py directly as a script without module namespace errors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import math
import hashlib
import urllib.request
import urllib.error

from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from backend.database import Database
from backend.auth import hash_password, check_password, generate_token, token_required, admin_required
from backend.email_analyzer import EmailAnalyzer
from backend.file_analyzer import FileAnalyzer
from backend.report_generator import PDFReportGenerator

app = Flask(__name__)
# Enable CORS for frontend requests
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Flask configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB limit

# Instantiate core modules
db = Database()
email_analyzer = EmailAnalyzer()
file_analyzer = FileAnalyzer()
report_generator = PDFReportGenerator()

# Rate limiting helper (in-memory, IP-based)
rate_limit_records = {}

def rate_limit(limit=60, period=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            if ip not in rate_limit_records:
                rate_limit_records[ip] = []
            # Filter timestamps in active window
            rate_limit_records[ip] = [t for t in rate_limit_records[ip] if now - t < period]
            if len(rate_limit_records[ip]) >= limit:
                db.log_event("WARNING", f"Rate limit tripped by IP: {ip}")
                return jsonify({"message": "Too many requests. Please slow down."}), 429
            rate_limit_records[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Auto-provision Default Admin on startup
def provision_admin():
    try:
        admin = db.get_user_by_email("admin@threatshield.sec")
        if not admin:
            hashed = hash_password("AdminSecure1337!")
            db.register_user(
                name="Security Administrator",
                email="admin@threatshield.sec",
                password_hash=hashed,
                role="admin"
            )
            print(">>> Provisioned default admin account: admin@threatshield.sec / AdminSecure1337!")
    except Exception as e:
        print(f">>> Failed auto-provisioning admin ({e})")

# ----------------- AUTHENTICATION ROUTES -----------------

@app.route("/api/auth/register", methods=["POST"])
@rate_limit(limit=10, period=60)
def register():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not name or not email or not password:
        return jsonify({"message": "All fields are required"}), 400
        
    if len(password) < 8:
        return jsonify({"message": "Password must be at least 8 characters"}), 400
        
    try:
        hashed = hash_password(password)
        user = db.register_user(name, email, hashed, role="user")
        
        # Auto-login on register
        token = generate_token(user["id"], user["email"], user["role"])
        return jsonify({
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
        }), 201
    except ValueError as ve:
        return jsonify({"message": str(ve)}), 400
    except Exception as e:
        return jsonify({"message": "Internal registration error"}), 500

@app.route("/api/auth/login", methods=["POST"])
@rate_limit(limit=15, period=60)
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400
        
    user = db.get_user_by_email(email)
    if not user or not check_password(password, user["password_hash"]):
        db.log_event("WARNING", f"Failed login attempt for email: {email}")
        return jsonify({"message": "Invalid email or password"}), 401
        
    token = generate_token(user["id"], user["email"], user["role"])
    db.log_event("INFO", f"User logged in: {email}")
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200

@app.route("/api/auth/profile", methods=["GET", "PUT"])
@token_required
def profile():
    user = request.current_user
    if request.method == "GET":
        return jsonify({
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"]
        }), 200
        
    # Edit profile
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    password = data.get("password", "").strip()
    
    if not name:
        return jsonify({"message": "Name field cannot be empty"}), 400
        
    hashed = None
    if password:
        if len(password) < 8:
            return jsonify({"message": "Password must be at least 8 characters"}), 400
        hashed = hash_password(password)
        
    updated = db.update_user_profile(user["id"], name, hashed)
    return jsonify({
        "id": updated["id"],
        "name": updated["name"],
        "email": updated["email"],
        "role": updated["role"]
    }), 200

# ----------------- SCAN ENDPOINTS -----------------

@app.route("/api/analyze/email", methods=["POST"])
@token_required
@rate_limit(limit=30, period=60)
def analyze_email():
    user = request.current_user
    
    # Check EML file upload vs plain text paste
    if "eml_file" in request.files:
        file = request.files["eml_file"]
        if file.filename == "":
            return jsonify({"message": "Empty file uploaded"}), 400
            
        filename = secure_filename(file.filename)
        # Read EML bytes
        eml_bytes = file.read()
        report = email_analyzer.analyze("", filename=filename, eml_bytes=eml_bytes)
        scan_name = report["subject"] or filename
        input_preview = report["subject"]
    else:
        # Expecting json body containing email text
        data = request.get_json() or {}
        email_text = data.get("email_text", "").strip()
        if not email_text:
            return jsonify({"message": "Email text content is empty"}), 400
            
        report = email_analyzer.analyze(email_text)
        scan_name = report["subject"]
        input_preview = email_text[:200]
        
    # Save analysis results
    scan_id = db.save_scan(
        user_id=user["id"],
        scan_type="email",
        name=scan_name,
        input_content=input_preview,
        prediction=report["prediction"],
        confidence=report["confidence"],
        risk_score=report["risk_score"],
        details=report
    )
    
    report["id"] = scan_id
    return jsonify(report), 200

@app.route("/api/analyze/file", methods=["POST"])
@token_required
@rate_limit(limit=20, period=60)
def analyze_file():
    user = request.current_user
    
    if "file" not in request.files:
        return jsonify({"message": "No file payload detected"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "Empty file name"}), 400
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{int(time.time())}_{filename}")
    
    try:
        file.save(filepath)
        
        # Analyze using static file analyzer
        report = file_analyzer.analyze(filepath, filename=filename)
        
        # Save scan
        scan_id = db.save_scan(
            user_id=user["id"],
            scan_type="file",
            name=filename,
            input_content=f"Size: {report['metadata']['file_size']} bytes | SHA-256: {report['metadata']['sha256'][:16]}...",
            prediction=report["prediction"],
            confidence=100.0,  # File scanners are deterministic static rules
            risk_score=report["risk_score"],
            details=report
        )
        
        report["id"] = scan_id
        return jsonify(report), 200
    except Exception as e:
        db.log_event("ERROR", f"File analysis failed for {filename}: {e}")
        return jsonify({"message": f"Static analysis failed: {str(e)}"}), 500
    finally:
        # Cleanup temporary saved file
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

# ----------------- SCAN HISTORY & REPORTS -----------------

@app.route("/api/history", methods=["GET"])
@token_required
def history():
    user = request.current_user
    search = request.args.get("search", "")
    prediction = request.args.get("prediction", "")
    risk = request.args.get("risk", "")
    scan_type = request.args.get("type", "")
    
    records = db.get_history(
        user_id=user["id"],
        role=user["role"],
        search_query=search,
        prediction_filter=prediction,
        risk_filter=risk,
        type_filter=scan_type
    )
    return jsonify(records), 200

@app.route("/api/history/<scan_id>", methods=["DELETE"])
@token_required
def delete_history_item(scan_id):
    user = request.current_user
    scan = db.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"message": "Record not found"}), 404
        
    # Enforce scan owner check (except admins)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        return jsonify({"message": "Access denied"}), 403
        
    db.delete_scan(scan_id)
    return jsonify({"message": "Record deleted successfully"}), 200

@app.route("/api/reports/download/<scan_id>", methods=["GET"])
@token_required
def download_pdf_report(scan_id):
    user = request.current_user
    scan = db.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"message": "Threat log record not found"}), 404
        
    # Access checks
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        return jsonify({"message": "Access denied"}), 403
        
    try:
        pdf_path = report_generator.generate_report(scan)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"Threat_Analysis_Report_{scan_id[:8]}.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        db.log_event("ERROR", f"Failed compiling report PDF for scan {scan_id}: {e}")
        return jsonify({"message": f"Failed generating PDF: {str(e)}"}), 500

# ----------------- ADMIN DASHBOARD ROUTES -----------------

@app.route("/api/admin/users", methods=["GET"])
@token_required
@admin_required
def get_users():
    users = db.get_all_users()
    return jsonify(users), 200

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    if user_id == request.current_user["id"]:
        return jsonify({"message": "Self deletion forbidden"}), 400
        
    success = db.delete_user(user_id)
    if not success:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"message": "User and history deleted successfully"}), 200

@app.route("/api/admin/stats", methods=["GET"])
@token_required
@admin_required
def get_admin_dashboard():
    # Admin stats collects global details
    stats = db.get_dashboard_stats(user_id=None, role="admin")
    logs = db.get_system_logs(limit=30)
    
    # ML model diagnostics
    has_model = email_analyzer.model is not None
    model_details = {
        "loaded": has_model,
        "algorithm": str(email_analyzer.model.__class__.__name__) if has_model else "None (Rule-based Fallback)",
        "features_count": len(email_analyzer.vectorizer.get_feature_names_out()) if has_model and email_analyzer.vectorizer else 0
    }
    
    return jsonify({
        "summary": stats,
        "logs": logs,
        "model_diagnostics": model_details
    }), 200

@app.route("/api/dashboard/stats", methods=["GET"])
@token_required
def get_user_dashboard_stats():
    user = request.current_user
    stats = db.get_dashboard_stats(user_id=user["id"], role=user["role"])
    return jsonify(stats), 200

def check_hibp_pwned(password):
    """
    Securely checks if a password was leaked using Have I Been Pwned k-Anonymity API.
    Sends only the first 5 chars of the SHA-1 hash.
    Returns: (is_leaked: bool, count: int)
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'ThreatShield-AI Phishing Defense Tool - Security Auditor'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            lines = response.read().decode('utf-8').splitlines()
            for line in lines:
                parts = line.split(':')
                if len(parts) == 2:
                    api_suffix, count_str = parts
                    if api_suffix.upper() == suffix:
                        return True, int(count_str)
    except Exception as e:
        print(f"HIBP check failed: {e}")
        return False, 0
    return False, 0

def calculate_entropy(password):
    """
    Calculates the bits of entropy of a password and returns a score and classification.
    """
    if not password:
        return 0, "Empty", "red"
        
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 33
    
    if pool_size == 0:
        pool_size = 1 # Fallback
        
    entropy_bits = length * math.log2(pool_size)
    
    # Classify strength
    if entropy_bits < 40:
        strength = "Very Weak"
        color = "red"
    elif entropy_bits < 60:
        strength = "Weak"
        color = "orange"
    elif entropy_bits < 80:
        strength = "Medium"
        color = "yellow"
    else:
        strength = "Strong"
        color = "green"
        
    return round(entropy_bits, 1), strength, color

@app.route("/api/security/password-audit", methods=["POST"])
@token_required
@rate_limit(limit=30, period=60)
def password_audit():
    data = request.get_json() or {}
    password = data.get("password", "")
    
    if not password:
        return jsonify({"message": "Password cannot be empty"}), 400
        
    entropy, strength, color = calculate_entropy(password)
    is_leaked, leak_count = check_hibp_pwned(password)
    
    # Generate tips based on characteristics
    tips = []
    if len(password) < 12:
        tips.append("Increase length to at least 12-16 characters. Length is the single most important factor for entropy.")
    if not any(c.isupper() for c in password):
        tips.append("Include uppercase characters (A-Z) to expand character pool complexity.")
    if not any(c.islower() for c in password):
        tips.append("Include lowercase characters (a-z) for better character variation.")
    if not any(c.isdigit() for c in password):
        tips.append("Add numeric digits (0-9).")
    if not any(not c.isalnum() for c in password):
        tips.append("Use special symbols (e.g., !, @, #, $, %, etc.).")
    
    # Simple check for common dictionary patterns
    common_patterns = ["password", "12345", "admin", "login", "qwerty", "welcome"]
    for pattern in common_patterns:
        if pattern in password.lower():
            tips.append(f"Avoid using simple dictionary terms like '{pattern}'.")
            
    if not tips:
        tips.append("Excellent character diversity and length. Password holds robust entropy!")
        
    return jsonify({
        "entropy_bits": entropy,
        "strength": strength,
        "color": color,
        "is_leaked": is_leaked,
        "leak_count": leak_count,
        "recommendations": tips
    }), 200

# Startup actions
provision_admin()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
