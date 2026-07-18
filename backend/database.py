import os
import json
import sqlite3
import uuid
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        self.db_type = "sqlite"
        self.mongo_client = None
        self.mongo_db = None
        
        # Check MongoDB configuration
        mongo_uri = os.getenv("MONGODB_URI")
        if mongo_uri:
            try:
                from pymongo import MongoClient
                import pymongo.errors
                # Attempt to connect to MongoDB with a short timeout
                self.mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
                # Trigger an action to verify connection
                self.mongo_client.server_info()
                self.mongo_db = self.mongo_client.get_database("phishing_db")
                self.db_type = "mongodb"
                print(">>> Connected successfully to MongoDB database.")
            except Exception as e:
                print(f">>> Failed to connect to MongoDB ({e}). Falling back to SQLite.")
                self.db_type = "sqlite"
        else:
            print(">>> MONGODB_URI not found in env. Initializing SQLite local database.")
            
        if self.db_type == "sqlite":
            self.sqlite_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
            os.makedirs(self.sqlite_dir, exist_ok=True)
            self.sqlite_path = os.path.join(self.sqlite_dir, "phishing_tool.db")
            self._init_sqlite()

    def _get_sqlite_conn(self):
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self):
        conn = self._get_sqlite_conn()
        cursor = conn.cursor()
        
        # Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        # Scans Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                input_content TEXT,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        # System Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id TEXT PRIMARY KEY,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
        print(f">>> SQLite database initialized at {self.sqlite_path}")

    # Log writer helper
    def log_event(self, level, message):
        timestamp = datetime.utcnow().isoformat()
        log_id = str(uuid.uuid4())
        if self.db_type == "mongodb":
            self.mongo_db.logs.insert_one({
                "_id": log_id,
                "level": level,
                "message": message,
                "timestamp": timestamp
            })
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (id, level, message, timestamp) VALUES (?, ?, ?, ?)",
                (log_id, level, message, timestamp)
            )
            conn.commit()
            conn.close()

    # USER AUTH METHODS
    def register_user(self, name, email, password_hash, role="user"):
        user_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()
        
        if self.db_type == "mongodb":
            users_col = self.mongo_db.users
            if users_col.find_one({"email": email.lower()}):
                raise ValueError("User with this email already exists")
            
            users_col.insert_one({
                "_id": user_id,
                "name": name,
                "email": email.lower(),
                "password_hash": password_hash,
                "role": role,
                "created_at": created_at
            })
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, name, email.lower(), password_hash, role, created_at)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                raise ValueError("User with this email already exists")
            conn.close()
            
        self.log_event("INFO", f"Registered new user {email} with role {role}")
        return {
            "id": user_id,
            "name": name,
            "email": email,
            "role": role,
            "created_at": created_at
        }

    def get_user_by_email(self, email):
        if self.db_type == "mongodb":
            user = self.mongo_db.users.find_one({"email": email.lower()})
            if user:
                user["id"] = user["_id"]
                return user
            return None
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
            return None

    def get_user_by_id(self, user_id):
        if self.db_type == "mongodb":
            user = self.mongo_db.users.find_one({"_id": user_id})
            if user:
                user["id"] = user["_id"]
                return user
            return None
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
            return None

    def get_all_users(self):
        if self.db_type == "mongodb":
            users = list(self.mongo_db.users.find())
            for u in users:
                u["id"] = u["_id"]
            return users
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, email, role, created_at FROM users")
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def update_user_profile(self, user_id, name, password_hash=None):
        if self.db_type == "mongodb":
            update_data = {"name": name}
            if password_hash:
                update_data["password_hash"] = password_hash
            self.mongo_db.users.update_one({"_id": user_id}, {"$set": update_data})
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            if password_hash:
                cursor.execute("UPDATE users SET name = ?, password_hash = ? WHERE id = ?", (name, password_hash, user_id))
            else:
                cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
            conn.commit()
            conn.close()
        self.log_event("INFO", f"Updated user profile details for user ID: {user_id}")
        return self.get_user_by_id(user_id)

    def delete_user(self, user_id):
        user = self.get_user_by_id(user_id)
        if not user:
            return False
            
        if self.db_type == "mongodb":
            self.mongo_db.users.delete_one({"_id": user_id})
            # Also purge their scans
            self.mongo_db.scans.delete_many({"user_id": user_id})
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
        self.log_event("WARNING", f"Deleted user {user['email']} and all their scan history.")
        return True

    # SCAN HISTORY METHODS
    def save_scan(self, user_id, scan_type, name, input_content, prediction, confidence, risk_score, details):
        scan_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()
        
        details_str = json.dumps(details) if isinstance(details, dict) else details
        
        if self.db_type == "mongodb":
            details_dict = details if isinstance(details, dict) else json.loads(details)
            self.mongo_db.scans.insert_one({
                "_id": scan_id,
                "user_id": user_id,
                "type": scan_type,
                "name": name,
                "input_content": input_content,
                "prediction": prediction,
                "confidence": confidence,
                "risk_score": int(risk_score),
                "details": details_dict,
                "created_at": created_at
            })
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (id, user_id, type, name, input_content, prediction, confidence, risk_score, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, user_id, scan_type, name, input_content, prediction, float(confidence), int(risk_score), details_str, created_at))
            conn.commit()
            conn.close()
            
        self.log_event("INFO", f"Saved scan {scan_id} ({scan_type}) for user {user_id}. Prediction: {prediction}, Risk: {risk_score}")
        return scan_id

    def get_scan_by_id(self, scan_id):
        if self.db_type == "mongodb":
            scan = self.mongo_db.scans.find_one({"_id": scan_id})
            if scan:
                scan["id"] = scan["_id"]
                return scan
            return None
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                res = dict(row)
                res["details"] = json.loads(res["details"])
                return res
            return None

    def get_history(self, user_id, role, search_query=None, prediction_filter=None, risk_filter=None, type_filter=None, limit=100):
        if self.db_type == "mongodb":
            query = {}
            # Unless admin, limit history to self
            if role != "admin":
                query["user_id"] = user_id
                
            if search_query:
                # Text search on scan name or input content
                query["$or"] = [
                    {"name": {"$regex": search_query, "$options": "i"}},
                    {"input_content": {"$regex": search_query, "$options": "i"}}
                ]
                
            if prediction_filter:
                query["prediction"] = prediction_filter
                
            if risk_filter:
                if risk_filter == "High":
                    query["risk_score"] = {"$gte": 75}
                elif risk_filter == "Medium":
                    query["risk_score"] = {"$gte": 30, "$lt": 75}
                elif risk_filter == "Low":
                    query["risk_score"] = {"$lt": 30}
                    
            if type_filter:
                query["type"] = type_filter
                
            scans = list(self.mongo_db.scans.find(query).sort("created_at", -1).limit(limit))
            for s in scans:
                s["id"] = s["_id"]
            return scans
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            
            sql = "SELECT * FROM scans WHERE 1=1"
            params = []
            
            if role != "admin":
                sql += " AND user_id = ?"
                params.append(user_id)
                
            if search_query:
                sql += " AND (name LIKE ? OR input_content LIKE ?)"
                params.extend([f"%{search_query}%", f"%{search_query}%"])
                
            if prediction_filter:
                sql += " AND prediction = ?"
                params.append(prediction_filter)
                
            if risk_filter:
                if risk_filter == "High":
                    sql += " AND risk_score >= 75"
                elif risk_filter == "Medium":
                    sql += " AND risk_score >= 30 AND risk_score < 75"
                elif risk_filter == "Low":
                    sql += " AND risk_score < 30"
                    
            if type_filter:
                sql += " AND type = ?"
                params.append(type_filter)
                
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details"])
                results.append(item)
            return results

    def delete_scan(self, scan_id):
        if self.db_type == "mongodb":
            res = self.mongo_db.scans.delete_one({"_id": scan_id})
            deleted = res.deleted_count > 0
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        if deleted:
            self.log_event("WARNING", f"Deleted scan log with ID: {scan_id}")
        return deleted

    def get_dashboard_stats(self, user_id=None, role="user"):
        # We need: Scanned counts, Phishing vs Safe ratios, Avg risk scores, Activity lists
        if self.db_type == "mongodb":
            query = {}
            if role != "admin" and user_id:
                query["user_id"] = user_id
                
            total = self.mongo_db.scans.count_documents(query)
            phishing_query = {**query, "prediction": {"$in": ["Phishing", "Suspicious", "Malicious"]}}
            legitimate_query = {**query, "prediction": {"$in": ["Legitimate", "Safe"]}}
            
            phishing_count = self.mongo_db.scans.count_documents(phishing_query)
            legitimate_count = self.mongo_db.scans.count_documents(legitimate_query)
            
            # Email vs File breakdown
            emails_total = self.mongo_db.scans.count_documents({**query, "type": "email"})
            files_total = self.mongo_db.scans.count_documents({**query, "type": "file"})
            
            # Avg Risk Score
            pipeline = [
                {"$match": query},
                {"$group": {"_id": None, "avg_risk": {"$avg": "$risk_score"}}}
            ]
            avg_result = list(self.mongo_db.scans.aggregate(pipeline))
            avg_risk = round(avg_result[0]["avg_risk"], 1) if avg_result else 0
            
            # Recent scans
            recent = list(self.mongo_db.scans.find(query).sort("created_at", -1).limit(5))
            for r in recent:
                r["id"] = r["_id"]
                
            # Quick categories / word occurrences summary could be generated here too.
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            
            # Base counters
            if role == "admin" or not user_id:
                cursor.execute("SELECT count(*) FROM scans")
                total = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE prediction IN ('Phishing', 'Suspicious', 'Malicious')")
                phishing_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE prediction IN ('Legitimate', 'Safe')")
                legitimate_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE type = 'email'")
                emails_total = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE type = 'file'")
                files_total = cursor.fetchone()[0]
                
                cursor.execute("SELECT AVG(risk_score) FROM scans")
                avg_risk = cursor.fetchone()[0]
                avg_risk = round(avg_risk, 1) if avg_risk is not None else 0
                
                cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 5")
                recent = [dict(row) for row in cursor.fetchall()]
            else:
                cursor.execute("SELECT count(*) FROM scans WHERE user_id = ?", (user_id,))
                total = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE user_id = ? AND prediction IN ('Phishing', 'Suspicious', 'Malicious')", (user_id,))
                phishing_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE user_id = ? AND prediction IN ('Legitimate', 'Safe')", (user_id,))
                legitimate_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE user_id = ? AND type = 'email'", (user_id,))
                emails_total = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM scans WHERE user_id = ? AND type = 'file'", (user_id,))
                files_total = cursor.fetchone()[0]
                
                cursor.execute("SELECT AVG(risk_score) FROM scans WHERE user_id = ?", (user_id,))
                avg_risk = cursor.fetchone()[0]
                avg_risk = round(avg_risk, 1) if avg_risk is not None else 0
                
                cursor.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5", (user_id,))
                recent = [dict(row) for row in cursor.fetchall()]
                
            for r in recent:
                r["details"] = json.loads(r["details"])
            conn.close()
            
        return {
            "total_scans": total,
            "phishing_scans": phishing_count,
            "legitimate_scans": legitimate_count,
            "email_scans": emails_total,
            "file_scans": files_total,
            "average_risk_score": avg_risk,
            "recent_scans": recent
        }

    def get_system_logs(self, limit=100):
        if self.db_type == "mongodb":
            logs = list(self.mongo_db.logs.find().sort("timestamp", -1).limit(limit))
            for l in logs:
                l["id"] = l["_id"]
            return logs
        else:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT id, level, message, timestamp FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]
