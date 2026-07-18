import os
import sys
# Allow running auth.py directly as a script without module namespace errors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from backend.database import Database

db = Database()
JWT_SECRET = os.getenv("JWT_SECRET", "super_cyber_security_secret_key_1337")

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def generate_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
        "sub": user_id,
        "email": email,
        "role": role
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({"message": "Access token is missing"}), 401
            
        payload = decode_token(token)
        if "error" in payload:
            return jsonify({"message": payload["error"]}), 401
            
        user = db.get_user_by_id(payload["sub"])
        if not user:
            return jsonify({"message": "User not found or account deleted"}), 401
            
        # Attach current user to the request context
        request.current_user = user
        return f(*args, **kwargs)
        
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, "current_user"):
            return jsonify({"message": "Authentication required"}), 401
            
        if request.current_user.get("role") != "admin":
            return jsonify({"message": "Admin privileges required"}), 403
            
        return f(*args, **kwargs)
        
    return decorated
