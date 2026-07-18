import os
import re
import joblib
import email
from email import policy
import numpy as np
from datetime import datetime
import dns.resolver
import socket


# Define regex patterns for Explainable AI (XAI) extraction
RE_URGENT = re.compile(r"\b(urgent|immediate|immediately|action required|suspended|suspension|expire|expiration|terminate|unauthorized|critical|restrict|security update|resolve now|attention required)\b", re.IGNORECASE)
RE_PASSWORD = re.compile(r"\b(password|credential|credentials|login page|verify password|update credential|reset password|secret key|security questions|passcode|verify account|log in)\b", re.IGNORECASE)
RE_BANKING = re.compile(r"\b(bank|banking|credit card|debit card|visa|mastercard|routing number|wire transfer|transaction|invoice|billing|payment|dollars|fund|funds|transfer limit|overdraft|account details|social security|ssn)\b", re.IGNORECASE)
RE_SUSPICIOUS_LINKS = re.compile(r"https?://[^\s<>#\"'\u007f-\uffff]+", re.IGNORECASE)

class EmailAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        
        # Paths for trained models
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = os.path.join(base_dir, "models", "phishing_model.joblib")
        self.vectorizer_path = os.path.join(base_dir, "models", "vectorizer.joblib")
        
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            try:
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                print(">>> ML Phishing model and Vectorizer loaded successfully.")
            except Exception as e:
                print(f">>> Failed to load ML model files ({e}). Using rule-based fallback.")
        else:
            print(">>> ML model files not found. Run model training. Fallback classifier enabled.")

    def parse_eml(self, eml_bytes):
        """Parses raw EML bytes into subject, body, headers, and metadata."""
        try:
            msg = email.message_from_bytes(eml_bytes, policy=policy.default)
            
            # Extract headers
            headers = {}
            for header in ['From', 'To', 'Subject', 'Date', 'Reply-To', 'Message-ID', 'Received', 'Return-Path']:
                headers[header] = msg.get(header, "")
                
            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    elif content_type == "text/html" and not body and "attachment" not in content_disposition:
                        # Fallback to HTML body if plain text is empty
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore')
                    
            subject = headers.get('Subject', '')
            return subject, body, headers
        except Exception as e:
            print(f">>> Error parsing EML: {e}")
            return "", "", {}

    def extract_sender_info(self, from_header):
        """Extracts display name, email address, and domain from From header."""
        if not from_header:
            return {"name": "Unknown", "email": "Unknown", "domain": "Unknown", "suspicious_domain": False}
            
        # Standard formats: "Name <email@domain.com>" or "email@domain.com"
        email_match = re.search(r'<([^>]+)>', from_header)
        if email_match:
            email_address = email_match.group(1).strip()
            display_name = from_header.split('<')[0].strip().replace('"', '')
        else:
            email_address = from_header.strip()
            display_name = "Unknown"
            
        domain = "Unknown"
        if "@" in email_address:
            domain = email_address.split("@")[1]
            
        # Check suspicious domain properties
        suspicious = False
        # Free email domains are fine but if spoofing as a service, they are suspicious
        free_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"]
        
        # Look for keywords inside the domain that indicate brand spoofing
        brand_keywords = ["paypal", "netflix", "bank", "amazon", "microsoft", "google", "apple", "support", "secure", "update", "verify"]
        domain_lower = domain.lower()
        
        if domain_lower not in free_providers:
            for kw in brand_keywords:
                if kw in domain_lower and domain_lower != f"{kw}.com" and not domain_lower.endswith(f".{kw}.com"):
                    suspicious = True
                    break
                    
        # Check domain endings like .xyz, .top, .work, .icu, etc. (often used for spam)
        uncommon_tlds = [".xyz", ".top", ".work", ".click", ".icu", ".loan", ".racing", ".bid", ".win"]
        for tld in uncommon_tlds:
            if domain_lower.endswith(tld):
                suspicious = True
                break
                
        return {
            "name": display_name or "Unknown",
            "email": email_address,
            "domain": domain,
            "suspicious_domain": suspicious
        }

    def detect_spoofing(self, headers, sender_info):
        """Detects possible domain spoofing (From vs Reply-To mismatch, missing DKIM/SPF headers)."""
        mismatched_reply_to = False
        reply_to_header = headers.get("Reply-To", "")
        
        if reply_to_header and sender_info["email"] != "Unknown":
            reply_match = re.search(r'<([^>]+)>', reply_to_header)
            reply_email = reply_match.group(1).strip() if reply_match else reply_to_header.strip()
            
            if "@" in reply_email and "@" in sender_info["email"]:
                reply_domain = reply_email.split("@")[1].lower()
                sender_domain = sender_info["domain"].lower()
                if reply_domain != sender_domain:
                    # Allow mismatches of free domains unless they are completely distinct types
                    mismatched_reply_to = True
                    
        # Simulate SPF/DKIM validation from Received/Authentication headers
        received = headers.get("Received", "")
        spf_pass = True
        dkim_pass = True
        
        # Static check in header strings (in a real mail transfer agent, these are parsed from MTA results)
        if received:
            received_lower = received.lower()
            if "spf=fail" in received_lower or "spf=softfail" in received_lower:
                spf_pass = False
            if "dkim=fail" in received_lower:
                dkim_pass = False
                
        return {
            "mismatched_reply_to": mismatched_reply_to,
            "reply_to": reply_to_header,
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "possible_spoofing": mismatched_reply_to or not spf_pass or not dkim_pass or sender_info["suspicious_domain"]
        }

    def extract_xai_indicators(self, text):
        """Extracts threat categories and matched words for Explainable AI (XAI)."""
        indicators = []
        
        # Urgent Language
        urgent_matches = RE_URGENT.findall(text)
        if urgent_matches:
            indicators.append({
                "category": "Urgent Language",
                "severity": "Medium",
                "matches": list(set(urgent_matches)),
                "description": "Urgency cues force victims to act rapidly without thinking, a primary psychological trigger."
            })
            
        # Password / Security Request
        pwd_matches = RE_PASSWORD.findall(text)
        if pwd_matches:
            indicators.append({
                "category": "Credential Harvesting",
                "severity": "High",
                "matches": list(set(pwd_matches)),
                "description": "Requests to verify passwords or login credentials are characteristic of phishing pages designed to steal accounts."
            })
            
        # Banking & Financial Keywords
        bank_matches = RE_BANKING.findall(text)
        if bank_matches:
            indicators.append({
                "category": "Financial Solicitation",
                "severity": "High",
                "matches": list(set(bank_matches)),
                "description": "References to billing, banking transfers, or credits are used to lure users into submitting card or account numbers."
            })
            
        # Suspicious URLs
        links = RE_SUSPICIOUS_LINKS.findall(text)
        suspicious_links = []
        for link in links:
            # Analyze links: check IP address URLs or too many subdomains or hyphens
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
                suspicious_links.append(link)
            elif link.count(".") > 4 or link.count("-") > 3:
                suspicious_links.append(link)
                
        if suspicious_links:
            indicators.append({
                "category": "Suspicious URLs",
                "severity": "High",
                "matches": list(set(suspicious_links))[:5], # limit to 5
                "description": "Links containing IP addresses, excessive subdomains, or spelling hyphens are used to masquerade as legitimate portals."
            })
            
        # Spelling/Grammar Heuristic
        caps_count = len(re.findall(r"\b[A-Z]{4,}\b", text))
        bangs_count = text.count("!")
        if caps_count > 5 or bangs_count > 3:
            indicators.append({
                "category": "Irregular Formatting / Style",
                "severity": "Low",
                "matches": [f"{caps_count} CAPS words", f"{bangs_count} exclamation marks"],
                "description": "Excessive exclamation marks and all-caps phrasing indicate non-professional formatting common in spam campaigns."
            })
            
        return indicators

    def classify_text_ml(self, text):
        """Classifies text as Phishing or Safe using the ML model (or rule-based fallback)."""
        if self.model and self.vectorizer:
            try:
                features = self.vectorizer.transform([text])
                prediction_idx = self.model.predict(features)[0]
                probabilities = self.model.predict_proba(features)[0]
                
                # Check mapping index - standard mapping is 0: Legitimate/Safe, 1: Phishing
                # We can verify classes mapping or use a safe prediction check
                confidence = float(np.max(probabilities) * 100)
                
                # If model classes are string labeled
                pred_label = str(prediction_idx)
                if "phishing" in pred_label.lower():
                    prediction = "Phishing"
                elif "safe" in pred_label.lower() or "legitimate" in pred_label.lower():
                    prediction = "Legitimate"
                else:
                    # Integer labels fallback: assuming 1 is phishing, 0 is safe
                    prediction = "Phishing" if prediction_idx == 1 else "Legitimate"
                    
                return prediction, confidence
            except Exception as e:
                print(f">>> ML Classification error ({e}). Using rule-based fallback.")
                
        # Rule-based fallback classifier
        # Calculate a threat score from keyword indicators
        text_lower = text.lower()
        score = 0
        score += len(RE_URGENT.findall(text_lower)) * 10
        score += len(RE_PASSWORD.findall(text_lower)) * 15
        score += len(RE_BANKING.findall(text_lower)) * 15
        
        # Check URLs
        links = RE_SUSPICIOUS_LINKS.findall(text_lower)
        score += len(links) * 12
        for link in links:
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
                score += 25
                
        if score >= 30:
            prediction = "Phishing"
            confidence = min(50.0 + float(score) / 2, 98.0)
        else:
            prediction = "Legitimate"
            confidence = min(80.0 + (30 - float(score)), 99.0)
            
        return prediction, confidence

    def dns_audit_domain(self, domain):
        """
        Queries SPF (TXT) and DMARC (TXT) records and A records (resolved IPs) via DNS resolver.
        Optimized with timeouts to prevent hanging the API request.
        """
        res = {
            "has_dns": False,
            "spf_record": None,
            "dmarc_record": None,
            "resolved_ips": []
        }
        
        if not domain or domain.lower() in ["unknown", "local", "localhost"] or "." not in domain:
            return res
            
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1.5
            resolver.lifetime = 1.5
            
            # 1. Resolve A records (IP addresses)
            try:
                answers = resolver.resolve(domain, 'A')
                res["resolved_ips"] = [rdata.address for rdata in answers]
                if res["resolved_ips"]:
                    res["has_dns"] = True
            except Exception:
                pass
                
            # 2. Check SPF records
            try:
                answers = resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt_content = "".join([t.decode('utf-8') if isinstance(t, bytes) else t for t in rdata.strings])
                    if "v=spf1" in txt_content.lower():
                        res["spf_record"] = txt_content
                        break
            except Exception:
                pass
                
            # 3. Check DMARC records
            try:
                answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                for rdata in answers:
                    txt_content = "".join([t.decode('utf-8') if isinstance(t, bytes) else t for t in rdata.strings])
                    if "v=dmarc1" in txt_content.lower():
                        res["dmarc_record"] = txt_content
                        break
            except Exception:
                pass
        except Exception as e:
            print(f">>> DNS resolution failed for domain {domain}: {e}")
            
        return res

    def scan_links_dns(self, text):
        """
        Extracts domains from links, resolves them via DNS, and returns a list of results.
        """
        links = RE_SUSPICIOUS_LINKS.findall(text)
        unique_links = list(set(links))[:5] # Check top 5 links to prevent latency issues
        
        results = []
        for link in unique_links:
            # Extract domain from link
            domain_match = re.search(r"https?://([^/\s?#]+)", link, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1).lower()
                # If domain is an IP address
                is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
                
                resolved_ips = []
                has_dns = False
                
                if is_ip:
                    resolved_ips = [domain]
                    has_dns = True
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 1.0
                        resolver.lifetime = 1.0
                        answers = resolver.resolve(domain, 'A')
                        resolved_ips = [rdata.address for rdata in answers]
                        has_dns = True
                    except Exception:
                        pass
                        
                results.append({
                    "url": link,
                    "domain": domain,
                    "resolved_ips": resolved_ips,
                    "has_dns": has_dns
                })
        return results

    def analyze(self, raw_text, filename=None, eml_bytes=None):
        """Main analysis entrypoint."""
        subject = ""
        body = raw_text
        headers = {}
        
        if eml_bytes:
            subject, body, headers = self.parse_eml(eml_bytes)
            name = filename or subject or "Uploaded EML File"
        else:
            name = filename or "Pasted Text Analysis"
            
            # Extract headers from pasted raw text (if present)
            lines = raw_text.splitlines()
            body_start_idx = 0
            has_headers = False
            
            for i, line in enumerate(lines[:15]):
                if not line.strip():
                    body_start_idx = i + 1
                    break
                
                # Check for standard header patterns (e.g. From: value)
                match = re.match(r"^([a-zA-Z\-]+):\s*(.*)", line)
                if match:
                    header_name = match.group(1).strip().title()
                    header_value = match.group(2).strip()
                    headers[header_name] = header_value
                    has_headers = True
                else:
                    if has_headers:
                        body_start_idx = i
                        break
            
            if has_headers:
                body = "\n".join(lines[body_start_idx:]).strip()
            else:
                body = raw_text
                
            # Regex fallbacks in case headers were not separated by clean newlines
            if not headers.get("Subject"):
                subj_match = re.search(r"^Subject:\s*(.*)", raw_text, re.MULTILINE | re.IGNORECASE)
                if subj_match:
                    headers["Subject"] = subj_match.group(1).strip()
                    
            if not headers.get("From"):
                from_match = re.search(r"^From:\s*(.*)", raw_text, re.MULTILINE | re.IGNORECASE)
                if from_match:
                    headers["From"] = from_match.group(1).strip()
                    
            if not headers.get("To"):
                to_match = re.search(r"^To:\s*(.*)", raw_text, re.MULTILINE | re.IGNORECASE)
                if to_match:
                    headers["To"] = to_match.group(1).strip()
                    
            if not headers.get("Reply-To"):
                reply_to_match = re.search(r"^Reply-To:\s*(.*)", raw_text, re.MULTILINE | re.IGNORECASE)
                if reply_to_match:
                    headers["Reply-To"] = reply_to_match.group(1).strip()

            subject = headers.get("Subject", "")
                
        # Fallback to body content if subject empty
        if not subject and body:
            subject = body[:50].strip() + "..."
            
        # 1. Classify text using model or fallback
        prediction, ml_confidence = self.classify_text_ml(body)
        
        # 2. Extract sender information & check spoofing
        from_header = headers.get("From", "")
        sender_info = self.extract_sender_info(from_header)
        spoofing_info = self.detect_spoofing(headers, sender_info)
        
        # Live DNS check for sender domain
        dns_records = self.dns_audit_domain(sender_info["domain"])
        
        # Active DNS check for links
        link_details = self.scan_links_dns(body)
        
        # 3. Extract XAI highlights
        xai_indicators = self.extract_xai_indicators(body)
        
        # 4. Calculate weighted threat score
        risk_score = 0
        if prediction == "Phishing":
            risk_score = int(ml_confidence * 0.6)  # Base ML impact
        else:
            risk_score = int((100 - ml_confidence) * 0.3)
            
        # Heuristics adjustment
        if sender_info["suspicious_domain"]:
            risk_score += 20
        if spoofing_info["possible_spoofing"]:
            risk_score += 20
        if any(ind["category"] == "Credential Harvesting" for ind in xai_indicators):
            risk_score += 25
        if any(ind["category"] == "Urgent Language" for ind in xai_indicators):
            risk_score += 15
        if any(ind["category"] == "Financial Solicitation" for ind in xai_indicators):
            risk_score += 15
        if any(ind["category"] == "Suspicious URLs" for ind in xai_indicators):
            risk_score += 20
            
        # Extra adjustments from Live DNS checks
        if sender_info["domain"] != "Unknown" and not dns_records["has_dns"]:
            risk_score += 25 # Non-resolving sender domain is highly suspicious
            
        unresolved_links = [l for l in link_details if not l["has_dns"]]
        if unresolved_links:
            risk_score += 15 # Links referencing dead/non-resolving domains
            
        # Ensure bounds 0-100
        risk_score = max(0, min(100, risk_score))
        
        # Re-align prediction if score is extremely high due to rule indicators
        if risk_score >= 70 and prediction == "Legitimate":
            prediction = "Phishing"
            ml_confidence = float(risk_score)
            
        # Determine Threat Level
        if risk_score >= 75:
            threat_level = "High"
        elif risk_score >= 30:
            threat_level = "Medium"
        else:
            threat_level = "Low"
            
        analysis_report = {
            "subject": subject,
            "sender_name": sender_info["name"],
            "sender_email": sender_info["email"],
            "sender_domain": sender_info["domain"],
            "suspicious_domain": sender_info["suspicious_domain"],
            "possible_spoofing": spoofing_info["possible_spoofing"],
            "mismatched_reply_to": spoofing_info["mismatched_reply_to"],
            "reply_to": spoofing_info["reply_to"],
            "spf_pass": spoofing_info["spf_pass"],
            "dkim_pass": spoofing_info["dkim_pass"],
            "xai_indicators": xai_indicators,
            "prediction": prediction,
            "confidence": round(ml_confidence, 2),
            "risk_score": risk_score,
            "threat_level": threat_level,
            "timestamp": datetime.utcnow().isoformat(),
            "dns_records": dns_records,
            "link_details": link_details
        }
        
        return analysis_report
