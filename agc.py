#!/usr/bin/env python3
"""
agc - Secure CLI Chat Application

A simple and secure command-line chat tool with built-in encryption,
file transfer, and clipboard integration for easily sharing connection details.
This version tries to help with NAT traversal by attempting to set up port forwarding via UPnP.
If UPnP is available and enabled, it will automatically map your port for external connections.
"""

import os
import sys
import json
import socket
import threading
import getpass
import time
import subprocess
import urllib.request
from cryptography.fernet import Fernet

# ---------------------------
# Dependency Management
# ---------------------------
# We now need pyperclip for clipboard operations and miniupnpc for UPnP NAT traversal.
REQUIRED_MODULES = ["cryptography", "pyperclip", "miniupnpc"]

def ensure_dependencies():
    """Check and install any missing dependencies."""
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            print(f"[INFO] Module '{module}' not found. Installing now...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
            
ensure_dependencies()

# ---------------------------
# Utility: Public IP Lookup and NAT Traversal via UPnP
# ---------------------------
def get_public_ip(timeout=5):
    """Attempt to determine the host's public IP address using api.ipify.org."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as response:
            ip = response.read().decode("utf8")
            return ip
    except Exception as e:
        print(f"[WARN] Failed to retrieve public IP: {e}")
        return None

def setup_nat(port, description="AGC Chat Application"):
    """
    Attempt to map the given TCP port using UPnP.
    Returns (external_ip, mapping_success) if UPnP is successful; otherwise (None, False).
    """
    try:
        import miniupnpc
        upnpc = miniupnpc.UPnP()
        upnpc.discoverdelay = 200
        ndevices = upnpc.discover()
        if ndevices > 0:
            upnpc.selectigd()
            external_ip = upnpc.externalipaddress()
            # Try to add port mapping: external port maps to the same internal port.
            mapping = upnpc.addportmapping(port, 'TCP', upnpc.lanaddr, port, description, '')
            if mapping:
                print(f"[INFO] Port {port} successfully mapped via UPnP. External IP: {external_ip}")
                return external_ip, True
            else:
                print("[WARN] UPnP found a gateway but failed to add port mapping.")
                return external_ip, False
        else:
            print("[WARN] No UPnP-enabled router found.")
            return None, False
    except Exception as e:
        print(f"[WARN] NAT traversal using UPnP failed: {e}")
        return None, False

# ---------------------------
# Encryption Utilities
# ---------------------------
def generate_session_key():
    """Generate an encryption key for the session."""
    return Fernet.generate_key()

def load_fernet(session_key):
    """Initialize the Fernet object with the session key."""
    return Fernet(session_key)

def encrypt_message(fernet, message: bytes) -> bytes:
    """Encrypt a message (in bytes)."""
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    """Decrypt the token. Returns error message if decryption fails."""
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

# ---------------------------
# Persistent Storage & Logging
# ---------------------------
SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"

def load_settings():
    """Load settings from a JSON file; use defaults if missing."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"chat_history": True, "contacts": {}}

def save_settings(settings):
    """Save settings to a JSON file."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    """Append a message to the chat log if enabled."""
    settings = load_settings()
    if settings.get("chat_history", True):
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(message + "\n")

# ---------------------------
# File Transfer Functions
# ---------------------------
def send_file(fernet, conn, filename):
    """Send a file securely to the client."""
    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' not found.")
        return
    try:
        with open(filename, "rb") as f:
            content = f.read()
        # Tag the payload as a file, then encrypt.
        payload = b"[FILE]" + filename.encode() + b"::" + content
        encrypted = encrypt_message(fernet, payload)
        conn.sendall(encrypted)
        print(f"[INFO] File '{filename}' sent successfully.")
        log_chat(f"Sent file: {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to send file: {e}")

def handle_received_data(fernet, data):
    """Handles decrypted data as text or a file."""
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
            print("[ERROR] File received, but could not parse its content.")
    else:
        try:
            message = dec.decode()
            print("\nPeer:", message)
            log_chat("Peer: " + message)
        except Exception:
            print("[ERROR] Unable to decode incoming message.")

# ---------------------------
# Chat Communication Threads
# ---------------------------
def chat_listener(conn, fernet):
    """Listen continuously for incoming messages."""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("[INFO] Connection closed by peer.")
                break
            handle_received_data(fernet, data)
        except Exception as e:
            print(f"[ERROR] Problem receiving data: {e}")
            break

def chat_sender(conn, fernet):
    """Send messages (or execute commands) to your chat partner."""
    help_msg = (
        "\n[COMMANDS]\n"
        "  /file <path>   : Send a file\n"
        "  /delchat       : Delete chat history\n"
        "  /exit          : Exit the chat\n"
    )
    print(help_msg)
    while True:
        msg = input("> ").strip()
        if not msg:
            continue
        if msg == "/exit":
            conn.close()
            print("Goodbye! Chat session ended.")
            break
        elif msg == "/delchat":
            if os.path.exists(CHAT_HISTORY_FILE):
                os.remove(CHAT_HISTORY_FILE)
                print("[INFO] Chat history removed.")
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
                print(f"[ERROR] Failed to send message: {e}")
                break

# ---------------------------
# Connection Setup (Host & Client)
# ---------------------------
def run_host():
    """Start the chat app as Host with user-friendly prompts and NAT assistance."""
    HOST, PORT = '', 5000
    print("\n[HOST MODE] Starting your chat session...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((HOST, PORT))
            server_socket.listen(1)
            print(f"[INFO] Listening on port {PORT}.")
        except Exception as e:
            print(f"[ERROR] Unable to start server: {e}")
            return

        settings = load_settings()
        stored_pass = settings.get("password")
        if not stored_pass:
            stored_pass = getpass.getpass("Please set a session password: ")
            settings["password"] = stored_pass
            save_settings(settings)

        # Try UPnP NAT traversal.
        nat_ip, mapping_success = setup_nat(PORT)
        if mapping_success and nat_ip:
            host_ip = nat_ip
            print(f"[INFO] Using NAT-mapped external IP: {host_ip}")
        else:
            # Fallback: Try to get public IP; if not available, use local.
            host_ip = get_public_ip()
            if not host_ip:
                host_ip = socket.gethostbyname(socket.gethostname())
                print(f"[WARN] Could not retrieve public IP. Using local IP: {host_ip}")
            else:
                print(f"[INFO] Public IP retrieved successfully: {host_ip}")

        connection_info = (
            "\n–––––– [HOST CONNECTION INFO] ––––––\n"
            f"IP Address       : {host_ip}\n"
            f"Port             : {PORT}\n"
            f"Session Password : {stored_pass}\n"
            "––––––––––––––––––––––––––––––––––––––––\n"
            "Tip: If behind NAT, ensure your router forwards port 5000.\n"
        )
        try:
            import pyperclip
            pyperclip.copy(connection_info)
            print("[INFO] Connection details have been copied to the clipboard.")
        except Exception as e:
            print(f"[WARN] Clipboard copy failed: {e}")
        print(connection_info)
        print("[INFO] Waiting for a client connection...\n")

        conn, addr = server_socket.accept()
        print(f"[INFO] Connected with {addr}.")

        # Authentication procedure.
        conn.sendall(b"[AUTH] Please send your session password.")
        peer_pass = conn.recv(1024).decode().strip()
        if peer_pass != stored_pass:
            conn.sendall(b"[AUTH_FAIL] Incorrect password. Connection refused.")
            print("[ERROR] Client entered an incorrect password. Disconnecting...")
            conn.close()
            return
        else:
            conn.sendall(b"[AUTH_OK]")
            print("[INFO] Client successfully authenticated!")

        # Establish secure session.
        session_key = generate_session_key()
        time.sleep(0.5)
        conn.sendall(session_key)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established. Let the chat begin!")

        threading.Thread(target=chat_listener, args=(conn, fernet), daemon=True).start()
        chat_sender(conn, fernet)

def run_client():
    """Start the chat app as Client with friendly user prompts."""
    print("\n[CLIENT MODE] Please enter the host's connection details.")
    host_ip = input("Host IP Address: ").strip()
    try:
        host_port = int(input("Host Port (e.g., 5000): ").strip())
    except ValueError:
        print("[ERROR] Port must be a number!")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host_ip, host_port))
        except Exception as e:
            print(f"[ERROR] Could not connect to the host: {e}")
            return

        # Handle authentication.
        auth_request = client_socket.recv(1024)
        if auth_request.startswith(b"[AUTH]"):
            session_pass = getpass.getpass("Enter the session password: ").strip()
            client_socket.sendall(session_pass.encode())
            auth_resp = client_socket.recv(1024)
            if auth_resp.startswith(b"[AUTH_FAIL]"):
                print("[ERROR] Authentication failed. Check your password and try again.")
                return
            elif auth_resp.startswith(b"[AUTH_OK]"):
                print("[INFO] You have been successfully authenticated!")
        else:
            print("[ERROR] Unexpected response during authentication.")
            return

        # Retrieve secure session key.
        session_key = client_socket.recv(1024)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established with the host. You may now chat.")

        threading.Thread(target=chat_listener, args=(client_socket, fernet), daemon=True).start()
        chat_sender(client_socket, fernet)

def print_banner():
    """Display a friendly welcome banner."""
    banner = (
        "\n=====================================================\n"
        "      Welcome to AGC - Secure CLI Chat Application\n"
        "=====================================================\n"
    )
    print(banner)

def main():
    """Main entry point: choose Host or Client mode."""
    print_banner()
    print("Select an option:")
    print("  1. Host a chat session")
    print("  2. Connect to a chat session (Client Mode)")
    choice = input("\nEnter 1 or 2: ").strip()
    if choice == "1":
        run_host()
    elif choice == "2":
        run_client()
    else:
        print("[ERROR] Invalid choice. Please run the application again and select 1 or 2.")

if __name__ == "__main__":
    main()