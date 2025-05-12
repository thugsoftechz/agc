#!/usr/bin/env python3
"""
agc - A secure, cross-platform CLI chat application.

Features:
  • Encrypted peer-to-peer messaging and file transfers.
  • Auto-installation of missing dependencies.
  • Persistent settings and chat history logging.
  • Simple command interface for sending files, clearing history, and exiting.
"""

import os
import sys
import json
import socket
import threading
import getpass
import time
import subprocess
from cryptography.fernet import Fernet

# ---------------------------
# Dependency Management
# ---------------------------
REQUIRED_MODULES = ["cryptography"]

def ensure_dependencies():
    """Ensure that all required modules are installed."""
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            print(f"[INFO] Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

ensure_dependencies()

# ---------------------------
# Encryption Utilities
# ---------------------------
def generate_session_key():
    """Generate a secure session key."""
    return Fernet.generate_key()

def load_fernet(session_key):
    """Initialize Fernet with the given session key."""
    return Fernet(session_key)

def encrypt_message(fernet, message: bytes) -> bytes:
    """Encrypt a byte-string message."""
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    """Decrypt the token back to plain text if possible."""
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

# ---------------------------
# Persistent Storage and Logging
# ---------------------------
SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"

def load_settings():
    """Load application settings from the JSON file or return default settings."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"chat_history": True, "contacts": {}}

def save_settings(settings):
    """Save the application settings to a JSON file."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    """Log chat messages if logging is enabled."""
    settings = load_settings()
    if settings.get("chat_history", True):
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(message + "\n")

# ---------------------------
# File Transfer Functions
# ---------------------------
def send_file(fernet, conn, filename):
    """Encrypt and send a file's contents over the connection."""
    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' not found.")
        return
    try:
        with open(filename, "rb") as f:
            content = f.read()
        payload = b"[FILE]" + filename.encode() + b"::" + content
        encrypted = encrypt_message(fernet, payload)
        conn.sendall(encrypted)
        print(f"[INFO] File '{filename}' sent.")
        log_chat(f"Sent file: {filename}")
    except Exception as e:
        print(f"[ERROR] Error sending file: {e}")

def handle_received_data(fernet, data):
    """Decrypt and distinguish between a plain text message and a file."""
    dec = decrypt_message(fernet, data)
    if dec.startswith(b"[FILE]"):
        try:
            content = dec[len(b"[FILE]"):]
            filename, file_content = content.split(b"::", 1)
            filename = filename.decode()
            received_filename = "received_" + filename
            with open(received_filename, "wb") as f:
                f.write(file_content)
            print(f"\n[INFO] Received file saved as: {received_filename}")
            log_chat(f"Received file: {filename}")
        except Exception:
            print("[ERROR] Received a file but could not parse the data.")
    else:
        try:
            message = dec.decode()
            print("\nPeer:", message)
            log_chat("Peer: " + message)
        except Exception:
            print("[ERROR] Unable to decode message.")

# ---------------------------
# Chat Communication Threads
# ---------------------------
def chat_listener(conn, fernet):
    """Listen for and process incoming messages."""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("[INFO] Connection closed by peer.")
                break
            handle_received_data(fernet, data)
        except Exception as e:
            print(f"[ERROR] Error receiving data: {e}")
            break

def chat_sender(conn, fernet):
    """Send messages and commands from the user to the peer."""
    instructions = (
        "Commands:\n"
        "  /file <path>   - Send a file\n"
        "  /delchat       - Delete chat history\n"
        "  /exit          - Exit the chat\n"
    )
    print(instructions)
    while True:
        msg = input("> ").strip()
        if not msg:
            continue
        if msg == "/exit":
            conn.close()
            print("[INFO] Chat session ended.")
            break
        elif msg == "/delchat":
            if os.path.exists(CHAT_HISTORY_FILE):
                os.remove(CHAT_HISTORY_FILE)
                print("[INFO] Chat history deleted.")
            else:
                print("[INFO] No chat history found.")
        elif msg.startswith("/file "):
            _, filename = msg.split(" ", 1)
            send_file(fernet, conn, filename.strip())
        else:
            try:
                encrypted = encrypt_message(fernet, msg.encode())
                conn.sendall(encrypted)
                log_chat("Me: " + msg)
            except Exception as e:
                print(f"[ERROR] Error sending message: {e}")
                break

# ---------------------------
# Connection Set-Up (Host and Client)
# ---------------------------
def run_host():
    """Run the application in HOST mode."""
    HOST, PORT = '', 5000
    print("[INFO] Hosting chat session...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, PORT))
            s.listen(1)
            print(f"[INFO] Listening on port {PORT}.")
        except Exception as e:
            print(f"[ERROR] Could not start server: {e}")
            return

        conn, addr = s.accept()
        print(f"[INFO] Connection accepted from {addr}.")
        # Password Authentication (for production, consider hashed passwords)
        settings = load_settings()
        stored_pass = settings.get("password")
        if not stored_pass:
            stored_pass = getpass.getpass("Set your session password: ")
            settings["password"] = stored_pass
            save_settings(settings)

        conn.sendall(b"[AUTH] Please send the session password.")
        peer_pass = conn.recv(1024).decode().strip()
        if peer_pass != stored_pass:
            conn.sendall(b"[AUTH_FAIL] Incorrect password. Connection refused.")
            print("[ERROR] Incorrect session password from peer. Disconnecting...")
            conn.close()
            return
        else:
            conn.sendall(b"[AUTH_OK]")
            print("[INFO] Password verified. Securing session...")

        # Secure the session using a newly generated session key.
        session_key = generate_session_key()
        time.sleep(0.5)  # Brief pause before sending key.
        conn.sendall(session_key)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established. Ready to chat.")

        threading.Thread(target=chat_listener, args=(conn, fernet), daemon=True).start()
        chat_sender(conn, fernet)

def run_client():
    """Run the application in Client mode."""
    host_ip = input("Enter host IP: ").strip()
    try:
        host_port = int(input("Enter host port (e.g., 5000): ").strip())
    except ValueError:
        print("[ERROR] Invalid port number.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host_ip, host_port))
        except Exception as e:
            print(f"[ERROR] Failed to connect: {e}")
            return

        auth_request = s.recv(1024)
        if auth_request.startswith(b"[AUTH]"):
            session_pass = getpass.getpass("Enter the session password provided by the host: ").strip()
            s.sendall(session_pass.encode())
            auth_resp = s.recv(1024)
            if auth_resp.startswith(b"[AUTH_FAIL]"):
                print("[ERROR] Authentication failed. Disconnecting...")
                return
            elif auth_resp.startswith(b"[AUTH_OK]"):
                print("[INFO] Authentication successful.")
        else:
            print("[ERROR] Unexpected authentication step. Exiting.")
            return

        session_key = s.recv(1024)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established. Ready to chat.")

        threading.Thread(target=chat_listener, args=(s, fernet), daemon=True).start()
        chat_sender(s, fernet)

def main():
    """Main entry point for the application."""
    print("=== agc: Secure CLI Chat Application ===")
    print("1. Host a chat session")
    print("2. Connect to a chat session")
    choice = input("Select mode (1 or 2): ").strip()
    if choice == "1":
        run_host()
    elif choice == "2":
        run_client()
    else:
        print("[ERROR] Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
