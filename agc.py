#!/usr/bin/env python3
"""
agc - A secure, cross-platform CLI chat application.

This application supports encrypted peer-to-peer chat and file transfer. 
On first run, it auto-installs required modules if missing.
"""

import subprocess
import sys
import os
import json
import socket
import threading
import getpass
import time

# ---------------------------
# Auto-install required modules
# ---------------------------
try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Module 'cryptography' not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.fernet import Fernet

# ---------------------------
# Utility / Encryption Module
# ---------------------------

def generate_session_key():
    """Generate an ephemeral session key."""
    return Fernet.generate_key()

def load_fernet(session_key):
    return Fernet(session_key)

def encrypt_message(fernet, message: bytes) -> bytes:
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

# ---------------------------
# Settings and Persistent Storage
# ---------------------------

SETTINGS_FILE = "chat_settings.json"

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    else:
        # Default settings: keep chat history on by default and an empty contacts dict
        return {"chat_history": True, "contacts": {}}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    settings = load_settings()
    if settings.get("chat_history", True):
        with open("chat_history.log", "a") as f:
            f.write(message + "\n")

# ---------------------------
# Chat Session: Shared Functions
# ---------------------------

def send_file(fernet, conn, filename):
    if not os.path.exists(filename):
        print(f"File '{filename}' not found.")
        return
    try:
        with open(filename, "rb") as f:
            content = f.read()
        # Use a marker to identify file transfer data
        prefix = b"[FILE]"
        encrypted = encrypt_message(fernet, prefix + filename.encode() + b"::" + content)
        conn.sendall(encrypted)
        print(f"File '{filename}' sent.")
        log_chat(f"Sent file: {filename}")
    except Exception as e:
        print("Error sending file:", e)

def handle_received_data(fernet, data):
    dec = decrypt_message(fernet, data)
    try:
        # Check if it’s a file marker
        if dec.startswith(b"[FILE]"):
            # Format: [FILE]filename::filecontent
            try:
                payload = dec[len(b"[FILE]"):]
                filename_part, file_content = payload.split(b"::", 1)
                filename = filename_part.decode()
                # Save file (prefixed with 'received_')
                with open("received_" + filename, "wb") as f:
                    f.write(file_content)
                print(f"\nReceived file saved as: received_{filename}")
                log_chat(f"Received file: {filename}")
            except Exception:
                print("Received a file but could not parse the data.")
        else:
            print("\nPeer:", dec.decode())
            log_chat("Peer: " + dec.decode())
    except Exception:
        print("Error processing received data.")

# ---------------------------
# Chat Listening Thread
# ---------------------------

def chat_listener(conn, fernet):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("Connection closed by peer.")
                break
            handle_received_data(fernet, data)
        except Exception as e:
            print("Error receiving data:", e)
            break

# ---------------------------
# Send Chat Messages
# ---------------------------

def chat_sender(conn, fernet):
    print("Type your messages below.\nCommands:\n   /file path/to/file      -> to send a file\n   /delchat                -> delete chat history\n   /exit                   -> exit chat")
    while True:
        msg = input("> ")
        if msg.strip() == "":
            continue
        if msg.startswith("/file"):
            parts = msg.split(" ", 1)
            if len(parts) == 2:
                filename = parts[1].strip()
                send_file(fernet, conn, filename)
            else:
                print("Usage: /file path/to/file")
        elif msg == "/exit":
            conn.close()
            print("Chat session ended.")
            break
        elif msg == "/delchat":
            if os.path.exists("chat_history.log"):
                os.remove("chat_history.log")
                print("Chat history deleted.")
            else:
                print("No chat history found.")
        else:
            encrypted = encrypt_message(fernet, msg.encode())
            try:
                conn.sendall(encrypted)
                log_chat("Me: " + msg)
            except Exception as e:
                print("Error sending message:", e)
                break

# ---------------------------
# Host (Server) Mode
# ---------------------------

def run_host():
    HOST = ''  # Listen on all interfaces
    PORT = 5000  # You can choose any port
    print("Starting in HOST mode (waiting for connections)...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Listening on port {PORT}. Share your IP and port with your peer to connect.")
        conn, addr = s.accept()
        print(f"Connection attempt from {addr}.")

        # Authentication: Use a preset password stored in settings.
        settings = load_settings()
        stored_pass = settings.get("password")
        if not stored_pass:
            stored_pass = getpass.getpass("Set your session password (share with your peer): ")
            settings["password"] = stored_pass  # In production, use secure hash storage!
            save_settings(settings)

        # Prompt peer for password verification.
        conn.sendall(b"[AUTH] Please send the session password.")
        peer_pass = conn.recv(1024).decode().strip()
        if peer_pass != stored_pass:
            conn.sendall(b"[AUTH_FAIL] Incorrect password. Connection refused.")
            print("Peer provided wrong password. Closing connection.")
            conn.close()
            return
        else:
            conn.sendall(b"[AUTH_OK]")
            print("Peer verified. Securing session...")

        # Generate session key and send it securely.
        session_key = generate_session_key()
        time.sleep(0.5)  # brief pause before transmission
        conn.sendall(session_key)
        fernet = load_fernet(session_key)
        print("Secure session established. Start chatting now.")

        # Start communication threads.
        listener = threading.Thread(target=chat_listener, args=(conn, fernet), daemon=True)
        listener.start()
        chat_sender(conn, fernet)

# ---------------------------
# Client (Connector) Mode
# ---------------------------

def run_client():
    host_ip = input("Enter host IP: ").strip()
    host_port = int(input("Enter host port (e.g., 5000): ").strip())
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host_ip, host_port))
        except Exception as e:
            print("Failed to connect:", e)
            return

        auth_request = s.recv(1024)
        if auth_request.startswith(b"[AUTH]"):
            session_pass = getpass.getpass("Enter the session password provided by the host: ").strip()
            s.sendall(session_pass.encode())
            auth_resp = s.recv(1024)
            if auth_resp.startswith(b"[AUTH_FAIL]"):
                print("Authentication failed. Closing connection.")
                s.close()
                return
            elif auth_resp.startswith(b"[AUTH_OK]"):
                print("Authentication successful.")
        else:
            print("Unexpected authentication step. Exiting.")
            s.close()
            return

        session_key = s.recv(1024)
        fernet = load_fernet(session_key)
        print("Secure session established. Start chatting now.")

        listener = threading.Thread(target=chat_listener, args=(s, fernet), daemon=True)
        listener.start()
        chat_sender(s, fernet)

# ---------------------------
# Main Application Entry Point
# ---------------------------

def main():
    print("=== agc: Secure CLI Chat Application ===")
    print("1. Host a chat session")
    print("2. Connect to a chat session")
    choice = input("Select mode (1 or 2): ").strip()
    if choice == "1":
        run_host()
    elif choice == "2":
        run_client()
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
