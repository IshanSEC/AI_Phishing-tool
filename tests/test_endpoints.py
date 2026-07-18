import os
import sys
import unittest
import json
from datetime import datetime

# Inject workspace path into Python system paths to ensure import works
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import Database
from backend.auth import hash_password, check_password
from backend.email_analyzer import EmailAnalyzer
from backend.file_analyzer import FileAnalyzer
from backend.report_generator import PDFReportGenerator

class TestPhishingAppBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure database fallback to use local testing SQLite file
        os.environ["MONGODB_URI"] = "" # Enforce local SQLite fallback path
        cls.db = Database()
        cls.email_analyzer = EmailAnalyzer()
        cls.file_analyzer = FileAnalyzer()
        cls.report_generator = PDFReportGenerator()
        
        # Paths for temporary test files
        cls.test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scratch")
        os.makedirs(cls.test_dir, exist_ok=True)
        cls.safe_pdf_path = os.path.join(cls.test_dir, "test_safe.pdf")
        cls.malicious_pdf_path = os.path.join(cls.test_dir, "test_malicious.pdf")
        cls.mismatch_file_path = os.path.join(cls.test_dir, "invoice.pdf") # Will contain PE headers
        
        # Write mock files for analysis checks
        with open(cls.safe_pdf_path, 'wb') as f:
            f.write(b"%PDF-1.4\n%...\n%%EOF")
            
        with open(cls.malicious_pdf_path, 'wb') as f:
            f.write(b"%PDF-1.4\n/OpenAction <</S /JavaScript /JS (app.alert('malware');)>>\n%%EOF")
            
        with open(cls.mismatch_file_path, 'wb') as f:
            # PE MZ header
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00"*60)

    @classmethod
    def tearDownClass(cls):
        # Cleanup temporary files
        for p in [cls.safe_pdf_path, cls.malicious_pdf_path, cls.mismatch_file_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        if os.path.exists(cls.test_dir):
            try:
                os.rmdir(cls.test_dir)
            except Exception:
                pass

    def test_01_database_fallback(self):
        """Verify SQLite fallback starts and users/scans interfaces conform to schemas."""
        self.assertEqual(self.db.db_type, "sqlite")
        
        email = f"operator_{int(datetime.utcnow().timestamp())}@sec.com"
        pwd = "SecurityPassword123!"
        hashed = hash_password(pwd)
        
        # Register user
        user = self.db.register_user("Test Operator", email, hashed)
        self.assertEqual(user["email"], email)
        self.assertEqual(user["role"], "user")
        
        # Login validation
        fetched = self.db.get_user_by_email(email)
        self.assertIsNotNone(fetched)
        self.assertTrue(check_password(pwd, fetched["password_hash"]))
        
        # Get profile
        profile = self.db.get_user_by_id(user["id"])
        self.assertEqual(profile["name"], "Test Operator")

    def test_02_email_analysis(self):
        """Test Email spoofing, brand checks, and XAI feature card matching."""
        phish_text = "Urgent billing update Chase Credit Card suspension immediately update password at http://chase-security-verify.net"
        
        report = self.email_analyzer.analyze(phish_text)
        self.assertEqual(report["prediction"], "Phishing")
        self.assertGreaterEqual(report["risk_score"], 60)
        self.assertEqual(report["threat_level"], "Medium" if report["risk_score"] < 75 else "High")
        
        # Check XAI triggers
        cats = [ind["category"] for ind in report["xai_indicators"]]
        self.assertIn("Urgent Language", cats)
        self.assertIn("Credential Harvesting", cats)
        self.assertIn("Financial Solicitation", cats)

    def test_03_file_analysis_magic_mismatch(self):
        """Verify extension mismatch detection alerts (MZ header in .pdf filename)."""
        report = self.file_analyzer.analyze(self.mismatch_file_path)
        self.assertEqual(report["prediction"], "Suspicious" if report["risk_score"] < 75 else "Malicious")
        self.assertTrue(report["metadata"]["extension_mismatch"])
        self.assertIn("MZ header", report["metadata"]["mismatch_warning"])

    def test_04_file_analysis_active_pdf(self):
        """Verify PDF static triggers detect /JavaScript actions and trigger warnings."""
        report = self.file_analyzer.analyze(self.malicious_pdf_path)
        self.assertGreater(report["risk_score"], 20)
        
        triggers = [ind["indicator"] for ind in report["xai_indicators"]]
        self.assertIn("Embedded JavaScript execution block (/JavaScript)", triggers)
        self.assertIn("Automatic action execution on file open (/OpenAction)", triggers)

    def test_05_pdf_report_compilation(self):
        """Check ReportLab PDF writer parses scan details and writes binary output."""
        scan_id = "test-scan-12345"
        mock_scan = {
            "id": scan_id,
            "type": "email",
            "prediction": "Phishing",
            "confidence": 92.4,
            "risk_score": 85,
            "created_at": datetime.utcnow().isoformat(),
            "details": {
                "subject": "Fake Suspicious Subject",
                "sender_name": "Suspicious Paypal Customer Service",
                "sender_email": "billing@paypal-alert-security.xyz",
                "sender_domain": "paypal-alert-security.xyz",
                "suspicious_domain": True,
                "possible_spoofing": True,
                "spf_pass": False,
                "dkim_pass": False,
                "xai_indicators": [
                    {
                        "category": "Credential Harvesting",
                        "severity": "High",
                        "matches": ["password", "log in"],
                        "description": "Attempt to obtain operator crypt credentials."
                    }
                ]
            }
        }
        
        pdf_path = self.report_generator.generate_report(mock_scan)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 5000) # Ensure it has file size
        
        # Cleanup compiled pdf
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

    def test_06_email_pasted_headers_analysis(self):
        """Verify headers (From, Subject, Reply-To) are correctly parsed from pasted raw text."""
        raw_pasted = (
            "From: Microsoft Security <security@microsoft-support-login.com>\n"
            "To: user@example.com\n"
            "Subject: Urgent! Verify Your Microsoft Account\n"
            "Reply-To: hacker@phishing-defense.com\n"
            "\n"
            "Dear User,\n"
            "Your Microsoft account has been suspended because unusual activity was detected."
        )
        report = self.email_analyzer.analyze(raw_pasted)
        
        self.assertEqual(report["subject"], "Urgent! Verify Your Microsoft Account")
        self.assertEqual(report["sender_name"], "Microsoft Security")
        self.assertEqual(report["sender_email"], "security@microsoft-support-login.com")
        self.assertEqual(report["sender_domain"], "microsoft-support-login.com")
        self.assertEqual(report["reply_to"], "hacker@phishing-defense.com")
        self.assertTrue(report["possible_spoofing"])

if __name__ == "__main__":
    unittest.main()
