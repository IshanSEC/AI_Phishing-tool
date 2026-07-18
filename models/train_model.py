import os
import urllib.request
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Dataset configuration
DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset")
DATASET_PATH = os.path.join(DATASET_DIR, "Phishing_Email.csv")
DATASET_URL = "https://raw.githubusercontent.com/SINANFIROZ/Phishing-Email-Detector/master/Phishing_Email.csv"

# Models target directory
MODELS_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

def download_dataset():
    """Attempts to download the Kaggle-based Phishing Email dataset from a raw GitHub mirror."""
    if os.path.exists(DATASET_PATH):
        print(f">>> Dataset already exists locally at {DATASET_PATH}.")
        return True
        
    print(f">>> Attempting to download phishing dataset from: {DATASET_URL} ...")
    try:
        urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
        print(">>> Dataset downloaded successfully!")
        return True
    except Exception as e:
        print(f">>> Failed downloading dataset ({e}). Creating localized fallback dataset.")
        return False

def generate_fallback_dataset():
    """Generates a high-quality local synthetic dataset of 200+ samples to train models offline."""
    print(">>> Generating synthetic training dataset for offline resilience...")
    
    phishing_templates = [
        "Urgent: Your account has been suspended! Please click here to verify your identity immediately: http://login-paypal-verify.com/login",
        "Attention: Security update required. Your bank password has expired. Reset it now at http://chase-update-routing.net/reset",
        "Dear Customer, we detected unauthorized login attempts on your Netflix subscription. Update billing at http://billing-netflix.xyz",
        "Verify your credentials: We need you to confirm your email and passcode to access your company dashboard page: http://company-secure-log.com",
        "Immediate payment notice: Invoice #28394 is past due. Wire $4,500 immediately to account routing number 8293-847-192 or face penalties.",
        "Congratulations! You won a $1,000 Amazon gift card! Click here to claim your reward: http://giftcard-rewards-winner.xyz/claim",
        "Action Required: Suspicious transaction detected on your credit card. Verify details at http://security-bank-alert.com/login",
        "Your package delivery failed. Please download the attachment or verify your details at http://fedex-delivery-update.com",
        "Microsoft Account Alert: Unauthorized device accessed your email. Reset credential password now: http://outlook-safety-verification.com",
        "Important notification: Your IRS tax refund is ready. Access credit funds immediately: http://irs-refund-portal.net/login"
    ]
    
    safe_templates = [
        "Hey, are we still meeting for lunch today at 12:30 PM? Let me know, thanks!",
        "Hi Team, please find attached the project status logs and timeline spreadsheet for the upcoming sprint review.",
        "Hi John, the team meeting has been rescheduled to Thursday at 10 AM in Conference Room B.",
        "Dear employee, your annual performance appraisal details are now available on the company HR portal dashboard.",
        "Hello, I hope you are doing well. Just wanted to follow up on the status of the invoice for last month's consultation work.",
        "Good morning, here is the PDF outline for the upcoming security training webinar. Please review prior to Monday.",
        "Hi Sarah, could you please send over the design assets for the new landing page by end of day today?",
        "Dear customer, thank you for your order. Here is your transaction receipt. Your shipping number is 8293-9481.",
        "Reminder: The weekly status report is due tomorrow at noon. Please update your tasks on the project spreadsheet.",
        "Hello, the company holiday calendar has been updated. Feel free to review the vacation schedules on the intranet."
    ]
    
    # Synthesize multiple variations to create a robust offline set (200 records)
    records = []
    
    # Expand Phishing emails
    companies = ["Google", "PayPal", "Amazon", "Bank of America", "Chase", "Apple", "Netflix", "Wells Fargo", "Microsoft"]
    domains = ["verify-credentials.org", "security-alert-update.net", "chase-log.com", "billing-support.net", "service-portal.xyz"]
    
    for i in range(100):
        comp = np.random.choice(companies)
        dom = np.random.choice(domains)
        tpl = np.random.choice(phishing_templates)
        
        # Add random variations
        text = tpl.replace("Netflix", comp).replace("bank", comp).replace("paypal-verify.com", dom)
        # Add random salutation or noise
        noise = f" Ref ID: {np.random.randint(1000, 99999)}"
        records.append({"Email Text": text + noise, "Email Type": "Phishing Email"})
        
    # Expand Safe emails
    names = ["Alice", "Bob", "Charlie", "David", "Emma", "Sophia", "Oliver", "James", "Sarah"]
    projects = ["Alpha", "Beta", "Cyber-Shield", "Delta", "Core-Infrastructure", "Cloud-Migration"]
    
    for i in range(100):
        name = np.random.choice(names)
        proj = np.random.choice(projects)
        tpl = np.random.choice(safe_templates)
        
        text = tpl.replace("John", name).replace("Sarah", name).replace("sprint review", f"{proj} review")
        noise = f" Sent from my mobile device."
        records.append({"Email Text": text + noise, "Email Type": "Safe Email"})
        
    df = pd.DataFrame(records)
    df.to_csv(DATASET_PATH, index=False)
    print(f">>> Fallback dataset generated at {DATASET_PATH}.")

def train_and_evaluate():
    """Loads dataset, trains models, evaluates metrics, and stores the best one."""
    print(">>> Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    
    # Drop empty records
    df = df.dropna(subset=["Email Text", "Email Type"])
    
    # Map classes: Phishing Email -> 1, Safe Email -> 0
    df["Email Type"] = df["Email Type"].astype(str).str.strip().str.lower()
    
    # Direct list mapping to ensure 100% compatibility across pandas versions
    df["label"] = [1 if "phish" in val or "spam" in val or val == "1" else 0 for val in df["Email Type"]]
    df["label"] = df["label"].astype(int)
    
    # Text cleaning
    df["Email Text"] = df["Email Text"].astype(str).str.lower()
    
    print(f">>> Class distribution:\n{df['label'].value_counts()}")
    
    X = df["Email Text"]
    y = df["label"]
    
    # Feature extraction (TF-IDF vectorizer)
    print(">>> Extracting TF-IDF text features...")
    vectorizer = TfidfVectorizer(stop_words='english', max_features=3000, min_df=2)
    X_features = vectorizer.fit_transform(X)
    
    # Split training / testing
    X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.2, random_state=42, stratify=y)
    
    # Algorithms dict
    models = {
        "Naive Bayes (Multinomial)": MultinomialNB(),
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Support Vector Machine": CalibratedClassifierCV(LinearSVC(random_state=42, dual=False))
    }
    
    results = {}
    best_f1 = -1.0
    best_model_name = ""
    best_model = None
    
    print("\n" + "="*50)
    print("MODEL EVALUATION COMPARISON")
    print("="*50)
    
    for name, clf in models.items():
        print(f">>> Training {name}...")
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        
        # Calculate stats
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, zero_division=0)
        rec = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)
        
        results[name] = {"accuracy": acc, "f1": f1}
        print(f"    - Accuracy : {acc:.4f}")
        print(f"    - Precision: {prec:.4f}")
        print(f"    - Recall   : {rec:.4f}")
        print(f"    - F1 Score : {f1:.4f}")
        print("-" * 30)
        
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf
            
    print("="*50)
    print(f"CHOSEN CHAMPION MODEL: {best_model_name} (F1 Score: {best_f1:.4f})")
    print("="*50)
    
    # Train champion model on full dataset
    print(f">>> Fitting final {best_model_name} on complete dataset...")
    best_model.fit(X_features, y)
    
    # Save artifacts
    model_output_path = os.path.join(MODELS_DIR, "phishing_model.joblib")
    vectorizer_output_path = os.path.join(MODELS_DIR, "vectorizer.joblib")
    
    joblib.dump(best_model, model_output_path)
    joblib.dump(vectorizer, vectorizer_output_path)
    
    print(f">>> ML model saved to: {model_output_path}")
    print(f">>> Vectorizer saved to: {vectorizer_output_path}")
    print(">>> ML Pipeline Training Complete!")

def main():
    download_success = download_dataset()
    if not download_success:
        generate_fallback_dataset()
    train_and_evaluate()

if __name__ == "__main__":
    main()
