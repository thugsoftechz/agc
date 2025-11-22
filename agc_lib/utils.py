import os
import sys
import json
import logging
import subprocess

SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"
REQUIRED_MODULES = ["cryptography", "pyperclip", "miniupnpc", "pyaudio", "cv2", "imutils", "numpy", "flask", "flask_socketio"]

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

def check_dependencies(auto_install=False):
    """Check if required dependencies are installed."""
    missing = []
    for module in REQUIRED_MODULES:
        try:
            import_name = module
            if module == "cv2": import_name = "cv2"
            elif module == "opencv-python": import_name = "cv2"
            __import__(import_name)
        except ImportError:
            missing.append(module)

    if missing:
        if auto_install:
            logging.info(f"Missing modules: {missing}. Attempting to install...")
            for module in missing:
                try:
                    install_name = module
                    if module == "cv2": install_name = "opencv-python"
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_name])
                    logging.info(f"Successfully installed {module}")
                except subprocess.CalledProcessError:
                    logging.error(f"Failed to install {module}.")
        else:
            logging.warning(f"Missing dependencies: {', '.join(missing)}. Use --install-deps.")

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"chat_history": True, "contacts": {}, "password": None}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    settings = load_settings()
    if settings.get("chat_history", True):
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(message + "\n")
