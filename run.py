import os
import sys
import subprocess
import time
import signal
import shutil

# Beautiful ASCII Header
BANNER = """
======================================================================
     ___   _   _ _____ ___ ____ ____    _    _   _ ___ _______     __ 
    / _ \ / \ | |_   _|_ _/ ___|  _ \  / \  \ \ / /_ _|_   _\ \   / / 
   | | | / _ \| | | |  | | |  _| |_) |/ _ \  \ V / | |  | |  \ \ / /  
   | |_|/ ___ \ | | |  | | |_| |  _ <___  \  | |  | |  | |   \ V /   
    \___/_/   \_\_| |_| |___\____|_| \_\  /_/  |_| |___| |_|    \_/    
                                                                      
    AI-BASED PHISHING DETECTION & MALICIOUS FILE STATIC ANALYSIS TOOL
======================================================================
"""

def print_banner():
    print(BANNER)
    print(">>> Operational Status: INITIALIZING SYSTEM...")

def check_requirements():
    print(">>> Checking python dependencies...")
    try:
        import flask
        import pymongo
        import jwt
        import bcrypt
        import sklearn
        import pandas
        import numpy
        import joblib
        import reportlab
        import matplotlib
        import dotenv
        print(">>> All python libraries verified.")
    except ImportError as e:
        print(f">>> Missing python libraries ({e}). Auto-installing from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "backend/requirements.txt"])
            print(">>> Dependencies installed successfully.")
        except Exception as err:
            print(f">>> Failed auto-installing python packages: {err}. Please run 'pip install -r backend/requirements.txt' manually.")

def start_backend():
    print(">>> Starting Python/Flask REST API on http://localhost:5000 ...")
    
    # Start backend as a module to resolve absolute package namespace imports
    proc = subprocess.Popen(
        [sys.executable, "-m", "backend.app"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    return proc

def start_frontend():
    # Detect if npm is installed
    npm_path = shutil.which("npm")
    frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
    
    if not npm_path:
        print("\n" + "!"*70)
        print("ENVIRONMENT PATH ALERT: Node.js and NPM were not found.")
        print("The backend REST API is running successfully at http://localhost:5000.")
        print("To start the React frontend:")
        print("1. Install Node.js (https://nodejs.org/) on your system.")
        print("2. Open a command shell in the 'frontend' folder.")
        print("3. Execute: 'npm install' followed by 'npm run dev'.")
        print("!"*70 + "\n")
        return None
        
    print(">>> Node.js/NPM detected. Initializing React frontend client...")
    
    # Check if node_modules exists, if not, run npm install
    node_modules = os.path.join(frontend_dir, "node_modules")
    if not os.path.exists(node_modules):
        print(">>> node_modules folder not found. Running 'npm install' in frontend folder (this may take a minute)...")
        try:
            # Run npm install synchronously first
            subprocess.check_call(["npm", "install"], cwd=frontend_dir, shell=True)
            print(">>> Frontend package installation completed.")
        except Exception as e:
            print(f">>> npm install failed ({e}). Please try running it manually inside the 'frontend' folder.")
            return None
            
    print(">>> Starting React dev server on http://localhost:3000 ...")
    proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=frontend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=True
    )
    return proc

def main():
    print_banner()
    check_requirements()
    
    # Start Backend
    backend_proc = start_backend()
    time.sleep(2) # Give Flask a moment to start
    
    # Start Frontend
    frontend_proc = start_frontend()
    
    print("\n>>> Core Services Launched. Press Ctrl+C to terminate services safely.")
    print(">>> Listening for live events...\n")
    
    # Keep main thread alive and pipe logs
    try:
        while True:
            # Check if backend processes died
            if backend_proc.poll() is not None:
                print(">>> CRITICAL: Flask server terminated unexpectedly!")
                print(backend_proc.stdout.read())
                break
                
            # Non-blocking check for stdout line printing
            # In a basic single-threaded loop, we can just sleep
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n>>> Keyboard interrupt received. Shutting down servers gracefully...")
    finally:
        # Graceful shutdown of subprocesses
        if backend_proc:
            print(">>> Stopping Flask backend server...")
            if sys.platform == 'win32':
                # Windows taskkill
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(backend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                backend_proc.terminate()
                
        if frontend_proc:
            print(">>> Stopping Vite frontend client...")
            if sys.platform == 'win32':
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                frontend_proc.terminate()
                
        print(">>> Services terminated. Goodbye Operator.")

if __name__ == "__main__":
    main()
