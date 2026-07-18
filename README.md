# AI-Based Phishing Detection & Malicious File Static Analysis Tool

A premium, modern threat detection portal designed to analyze suspicious emails and files for security threats. It utilizes machine learning models to detect phishing attempts, performs static analysis on uploaded files, generates PDF reports, and provides an administrative center for monitoring security events.

---

## 📸 Dashboard Preview

<p align="center">
  <img src="assets/dashboard.png" alt="ThreatShield-AI Dashboard" width="100%">
</p>

<p align="center">
  <b>ThreatShield-AI Security Operations Dashboard</b><br>
  Real-time phishing detection, malware analysis, threat monitoring, and security analytics.
</p>

---

## 🚀 Quick Start (Recommended)

The project includes an orchestrator script that automatically installs dependencies, configures the database, and launches both frontend and backend servers.

To start everything automatically, open your terminal in the project root directory and run:

```bash
python run.py
```

### What this script does:

1. **Verifies Python packages**: Installs missing libraries from `backend/requirements.txt`.
2. **Initializes the database**: Automatically provisions a local SQLite database (`backend/data/phishing_tool.db`) or connects to MongoDB if `MONGODB_URI` is present in a `.env` file.
3. **Provisions default administrator credentials** (if not already present).
4. **Starts the Flask Backend**: Runs the REST API at `http://localhost:5000`.
5. **Starts the React Frontend**: Detects Node.js, runs `npm install` inside the `frontend` folder if `node_modules` is missing, and starts the Vite development server at `http://localhost:3000`.

---

## 🔐 Default Admin Credentials

On first run, the system automatically provisions a security administrator account for you to access the dashboard and admin panel:

* **Email:** `admin@threatshield.sec`
* **Password:** `AdminSecure1337!`

---

## 🛠️ Manual Installation & Launch

If you prefer to start the components manually in separate terminals, follow these steps:

### 1. Backend Server Setup

Open a terminal in the `backend` directory:

```bash
# Navigate to backend
cd backend

# Install python requirements
pip install -r requirements.txt

# Start Flask server
python -m backend.app
```

The server will start at `http://localhost:5000`.

### 2. Frontend React Setup

Open a terminal in the `frontend` directory:

```bash
# Navigate to frontend
cd frontend

# Install Node modules
npm install

# Start Vite developer server
npm run dev
```

The client dashboard will launch at `http://localhost:3000`.

### 3. Training/Re-training the Machine Learning Model

The system uses a pre-trained TF-IDF and Classifier model to score phishing emails. If you want to train it yourself using the dataset:

```bash
python models/train_model.py
```

*Note: This script will download the full 52MB Kaggle dataset from a mirror. If you are offline, it will automatically generate a high-quality synthetic dataset of 200+ samples so you can train the model offline immediately.*

---

## 📁 Project Architecture & Structure

```filepath
AI-Phishing email detection tool/
│
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── auth.py
│   ├── email_analyzer.py
│   ├── file_analyzer.py
│   ├── report_generator.py
│   ├── requirements.txt
│   └── data/
│
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   ├── package.json
│   └── src/
│
├── models/
├── dataset/
├── run.py
└── README.md
```

---

## ⚡ Main Features

* **Real-time Phishing Analysis**
* **Static File Threat Analysis**
* **Interactive Dashboard**
* **Audit & Security Logging**
* **PDF Threat Report Export**
