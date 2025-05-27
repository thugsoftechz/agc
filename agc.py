#!/usr/bin/env python3
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

# Ensure required dependencies are installed
REQUIRED_MODULES = ["cryptography", "pyperclip", "miniupnpc"]

def ensure_dependencies():
    """Ensure required dependencies are installed."""
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            print(f"[INFO] Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

ensure_dependencies()

# Import tkinter for GUI functionality
try:
    import tkinter as tk
    from tkinter import scrolledtext, filedialog, messagebox
except ImportError:
    print("[ERROR] tkinter is not installed. GUI functionality will not be available.")
    # For GUI mode, the program will exit if tkinter is missing.

def update_agc():
    """
    Update the AGC application from the GitHub repository: 
    https://github.com/thugsoftechz/agc.
    """
    print("[INFO] Attempting to update AGC from https://github.com/thugsoftechz/agc ...")
    if os.path.exists(".git"):
        try:
            result = subprocess.run(["git", "pull"], check=True, text=True, capture_output=True)
            print(result.stdout)
            print("[INFO] Update completed successfully.")
        except subprocess.CalledProcessError as e:
            print("[ERROR] Git pull failed. Details:")
            print(e.stderr)
    else:
        print(("[ERROR] No Git repository found. Please ensure that AGC was cloned from "
               "https://github.com/thugsoftechz/agc or update manually."))

def get_public_ip(timeout=5):
    """Retrieve the host's public IP using api.ipify.org."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as response:
            ip = response.read().decode("utf8")
            return ip
    except Exception as e:
        print(f"[WARN] Failed to retrieve public IP: {e}")
        return None

def setup_nat(port, description="AGC Secure Session"):
    """
    Attempt to map the given TCP port using UPnP.
    Returns (external_ip, mapping_success) if successful; otherwise (None, False).
    """
    try:
        import miniupnpc
        upnpc = miniupnpc.UPnP()
        upnpc.discoverdelay = 200
        ndevices = upnpc.discover()
        if ndevices > 0:
            upnpc.selectigd()
            external_ip = upnpc.externalipaddress()
            mapping = upnpc.addportmapping(port, 'TCP', upnpc.lanaddr, port, description, None)
            if mapping:
                print(f"[INFO] Port {port} successfully mapped via UPnP. External IP: {external_ip}")
                return external_ip, True
            else:
                print("[WARN] UPnP gateway found but port mapping failed.")
                return external_ip, False
        else:
            print("[WARN] No UPnP-enabled router found.")
            return None, False
    except Exception as e:
        print(f"[WARN] NAT traversal using UPnP failed: {e}")
        return None, False

def generate_session_key():
    """Generate an encryption key for the session."""
    return Fernet.generate_key()

def load_fernet(session_key):
    """Return a Fernet object for the given session key."""
    return Fernet(session_key)

def encrypt_message(fernet, message: bytes) -> bytes:
    """Encrypt a message (in bytes)."""
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    """Attempt to decrypt the token; return an error indicator on failure."""
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

# ----- Framing Helper Functions -----
def recvall(conn, n):
    """Receive exactly n bytes from the socket (or None on socket close)."""
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_encrypted(conn, token: bytes):
    """
    Send an encrypted token with a 4-byte header indicating its length.
    """
    token_length = len(token)
    conn.sendall(token_length.to_bytes(4, byteorder='big'))
    conn.sendall(token)

def recv_encrypted(conn):
    """
    Receive an encrypted token preceded by a 4-byte length header.
    """
    header = recvall(conn, 4)
    if not header:
        return None
    token_length = int.from_bytes(header, byteorder='big')
    token = recvall(conn, token_length)
    return token

SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"

def load_settings():
    """Load settings from a JSON file; return defaults if not found."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"chat_history": True, "contacts": {}}

def save_settings(settings):
    """Save settings to a JSON file."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    """Append a message to the chat log if chat history is enabled."""
    settings = load_settings()
    if settings.get("chat_history", True):
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(message + "\n")

def send_file(fernet, conn, filename):
    """Send a file securely over the connection using framing."""
    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' not found.")
        return
    try:
        with open(filename, "rb") as f:
            content = f.read()
        payload = b"[FILE]" + filename.encode() + b"::" + content
        encrypted = encrypt_message(fernet, payload)
        send_encrypted(conn, encrypted)
        print(f"[INFO] File '{filename}' sent successfully.")
        log_chat(f"Sent file: {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to send file: {e}")

def handle_received_data(fernet, token):
    """Handle a complete encrypted token as a file or plain message."""
    dec = decrypt_message(fernet, token)
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
            print("[ERROR] Failed to parse received file data.")
    else:
        try:
            message = dec.decode()
            print("\nPeer:", message)
            log_chat("Peer: " + message)
        except Exception:
            print("[ERROR] Unable to decode incoming message.")

def chat_listener(conn, fernet):
    """Continuously listen for incoming messages in console mode using framing."""
    while True:
        try:
            token = recv_encrypted(conn)
            if token is None:
                print("[INFO] Connection closed by peer.")
                break
            handle_received_data(fernet, token)
        except Exception as e:
            print(f"[ERROR] Problem receiving data: {e}")
            break

def chat_sender(conn, fernet):
    """Read input from the console and send messages or files using framing."""
    help_msg = (
        "\n[COMMANDS]\n"
        "  /file <path>   : Send a file\n"
        "  /delchat       : Delete chat history\n"
        "  /exit          : Exit chat\n"
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
                send_encrypted(conn, encrypted)
                log_chat("Me: " + msg)
            except Exception as e:
                print(f"[ERROR] Failed to send message: {e}")
                break

# -------------------------
# GUI Components for AGC Chat
# -------------------------
class ChatGUI:
    def __init__(self, conn, fernet):
        self.conn = conn
        self.fernet = fernet
        self.root = tk.Tk()
        self.root.title("AGC Chat Session")
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='disabled', width=50, height=20)
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10)
        self.entry = tk.Entry(self.root, width=40)
        self.entry.grid(row=1, column=0, padx=10, pady=5)
        self.entry.bind("<Return>", self.send_message)
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=5, pady=5)
        self.file_button = tk.Button(self.root, text="Send File", command=self.send_file)
        self.file_button.grid(row=1, column=2, padx=5, pady=5)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def append_message(self, msg):
        """Safely append messages to the text area from any thread."""
        def inner():
            self.text_area.config(state='normal')
            self.text_area.insert(tk.END, msg + "\n")
            self.text_area.see(tk.END)
            self.text_area.config(state='disabled')
        self.root.after(0, inner)

    def send_message(self, event=None):
        """Send the message typed in the GUI."""
        msg = self.entry.get().strip()
        if msg:
            try:
                encrypted = encrypt_message(self.fernet, msg.encode())
                send_encrypted(self.conn, encrypted)
                self.append_message("Me: " + msg)
                self.entry.delete(0, tk.END)
            except Exception as e:
                self.append_message("[ERROR] Failed to send message: " + str(e))

    def send_file(self):
        """Open a file dialog to choose and send a file."""
        filename = filedialog.askopenfilename()
        if filename:
            try:
                with open(filename, "rb") as f:
                    content = f.read()
                payload = b"[FILE]" + os.path.basename(filename).encode() + b"::" + content
                encrypted = encrypt_message(self.fernet, payload)
                send_encrypted(self.conn, encrypted)
                self.append_message("[INFO] File '" + os.path.basename(filename) + "' sent successfully.")
            except Exception as e:
                self.append_message("[ERROR] Failed to send file: " + str(e))

    def on_close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.root.destroy()

    def start(self):
        self.root.mainloop()

def gui_chat_listener(conn, fernet, gui):
    """Continuously listen for incoming messages in GUI mode using framing."""
    while True:
        try:
            token = recv_encrypted(conn)
            if token is None:
                gui.append_message("[INFO] Connection closed by peer.")
                break
            dec = decrypt_message(fernet, token)
            if dec.startswith(b"[FILE]"):
                try:
                    content = dec[len(b"[FILE]"):]
                    filename, file_content = content.split(b"::", 1)
                    filename = filename.decode()
                    received_filename = "received_" + filename
                    with open(received_filename, "wb") as f:
                        f.write(file_content)
                    gui.append_message("[INFO] Received file saved as: " + received_filename)
                except Exception:
                    gui.append_message("[ERROR] Failed to parse received file data.")
            else:
                try:
                    message = dec.decode()
                    gui.append_message("Peer: " + message)
                except Exception:
                    gui.append_message("[ERROR] Unable to decode incoming message.")
        except Exception as e:
            gui.append_message("[ERROR] Problem receiving data: " + str(e))
            break

# -------------------------
# Modes: Console and GUI with LAN/WAN Connectivity Display
# -------------------------
def run_host():
    """Run as Host in console mode, showing both LAN and WAN connectivity details."""
    HOST = ''
    DEFAULT_PORT = 5000
    PORT = DEFAULT_PORT

    print("\n[HOST MODE] Starting chat session...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    while True:
        try:
            server_socket.bind((HOST, PORT))
            break
        except Exception as e:
            print(f"[ERROR] Unable to bind port {PORT}: {e}")
            new_port = input("Enter a different port number: ").strip()
            try:
                PORT = int(new_port)
            except ValueError:
                print("[ERROR] Invalid port number. Please try again.")

    server_socket.listen(1)
    print(f"[INFO] Listening on port {PORT}.")

    # Retrieve LAN IP
    lan_ip = socket.gethostbyname(socket.gethostname())

    # Attempt UPnP for a NAT-mapped external IP; fallback to public service
    nat_ip, mapping_success = setup_nat(PORT)
    if mapping_success and nat_ip:
        wan_ip = nat_ip
        print(f"[INFO] Using NAT-mapped external IP: {wan_ip}")
    else:
        wan_ip = get_public_ip()
        if not wan_ip:
            wan_ip = "Unavailable"
            print(f"[WARN] Could not retrieve public IP. Using local IP: {lan_ip}")
        else:
            print(f"[INFO] Public IP retrieved: {wan_ip}")

    settings = load_settings()
    stored_pass = settings.get("password")
    if not stored_pass:
        stored_pass = getpass.getpass("Set a session password: ")
        settings["password"] = stored_pass
        save_settings(settings)

    connection_info = (
        f"\n[HOST INFO]\n"
        f"LAN IP Address: {lan_ip}\n"
        f"WAN IP Address: {wan_ip}\n"
        f"Port: {PORT}\n"
        f"Session Password: {stored_pass}\n"
        "Note: Use the LAN IP if connecting within the local network; use the WAN IP if connecting over the Internet.\n"
    )
    try:
        import pyperclip
        pyperclip.copy(connection_info)
        print("[INFO] Connection details copied to clipboard.")
    except Exception as e:
        print(f"[WARN] Clipboard copy failed: {e}")
    print(connection_info)
    print("[INFO] Waiting for a client connection...\n")

    conn, addr = server_socket.accept()
    print(f"[INFO] Connected to {addr}.")

    conn.sendall(b"[AUTH] Please send your session password.")
    peer_pass = conn.recv(1024).decode().strip()
    if peer_pass != stored_pass:
        conn.sendall(b"[AUTH_FAIL] Incorrect password. Connection refused.")
        print("[ERROR] Incorrect password entered by client. Disconnecting...")
        conn.close()
        return
    else:
        conn.sendall(b"[AUTH_OK]")
        print("[INFO] Client authenticated successfully.")

    session_key = generate_session_key()
    time.sleep(0.5)
    conn.sendall(session_key)
    fernet = load_fernet(session_key)
    print("[INFO] Secure session established. Let the chat begin!")

    threading.Thread(target=chat_listener, args=(conn, fernet), daemon=True).start()
    chat_sender(conn, fernet)

def run_client():
    """Run as Client in console mode: enter host details and start chatting."""
    print("\n[CLIENT MODE] Enter host connection details.")
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
            print(f"[ERROR] Could not connect to host: {e}")
            return

        auth_request = client_socket.recv(1024)
        if auth_request.startswith(b"[AUTH]"):
            session_pass = getpass.getpass("Enter session password: ").strip()
            client_socket.sendall(session_pass.encode())
            auth_resp = client_socket.recv(1024)
            if auth_resp.startswith(b"[AUTH_FAIL]"):
                print("[ERROR] Authentication failed. Check password and try again.")
                return
            elif auth_resp.startswith(b"[AUTH_OK]"):
                print("[INFO] Authentication successful!")
        else:
            print("[ERROR] Unexpected authentication response.")
            return

        session_key = client_socket.recv(1024)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established with host. You may now chat.")

        threading.Thread(target=chat_listener, args=(client_socket, fernet), daemon=True).start()
        chat_sender(client_socket, fernet)

def run_host_gui():
    """Run as Host in GUI mode, showing LAN and WAN connectivity information."""
    HOST = ''
    DEFAULT_PORT = 5000
    PORT = DEFAULT_PORT

    print("\n[HOST MODE - GUI] Starting chat session...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    while True:
        try:
            server_socket.bind((HOST, PORT))
            break
        except Exception as e:
            print(f"[ERROR] Unable to bind port {PORT}: {e}")
            new_port = input("Enter a different port number: ").strip()
            try:
                PORT = int(new_port)
            except ValueError:
                print("[ERROR] Invalid port number. Please try again.")

    server_socket.listen(1)
    print(f"[INFO] Listening on port {PORT}.")

    lan_ip = socket.gethostbyname(socket.gethostname())

    nat_ip, mapping_success = setup_nat(PORT)
    if mapping_success and nat_ip:
        wan_ip = nat_ip
        print(f"[INFO] Using NAT-mapped external IP: {wan_ip}")
    else:
        wan_ip = get_public_ip()
        if not wan_ip:
            wan_ip = "Unavailable"
            print(f"[WARN] Could not retrieve public IP. Using local IP: {lan_ip}")
        else:
            print(f"[INFO] Public IP retrieved: {wan_ip}")

    settings = load_settings()
    stored_pass = settings.get("password")
    if not stored_pass:
        stored_pass = getpass.getpass("Set a session password: ")
        settings["password"] = stored_pass
        save_settings(settings)

    connection_info = (
        f"\n[HOST INFO]\n"
        f"LAN IP Address: {lan_ip}\n"
        f"WAN IP Address: {wan_ip}\n"
        f"Port: {PORT}\n"
        f"Session Password: {stored_pass}\n"
        "Note: Use the LAN IP if connecting within the local network; use the WAN IP if connecting over the Internet.\n"
    )
    try:
        import pyperclip
        pyperclip.copy(connection_info)
        print("[INFO] Connection details copied to clipboard.")
    except Exception as e:
        print(f"[WARN] Clipboard copy failed: {e}")
    print(connection_info)
    print("[INFO] Waiting for a client connection...\n")

    conn, addr = server_socket.accept()
    print(f"[INFO] Connected to {addr}.")

    conn.sendall(b"[AUTH] Please send your session password.")
    peer_pass = conn.recv(1024).decode().strip()
    if peer_pass != stored_pass:
        conn.sendall(b"[AUTH_FAIL] Incorrect password. Connection refused.")
        print("[ERROR] Incorrect password entered by client. Disconnecting...")
        conn.close()
        return
    else:
        conn.sendall(b"[AUTH_OK]")
        print("[INFO] Client authenticated successfully.")

    session_key = generate_session_key()
    time.sleep(0.5)
    conn.sendall(session_key)
    fernet = load_fernet(session_key)
    print("[INFO] Secure session established. Let the chat begin!")

    chat_gui = ChatGUI(conn, fernet)
    listener_thread = threading.Thread(target=gui_chat_listener, args=(conn, fernet, chat_gui), daemon=True)
    listener_thread.start()
    chat_gui.start()

def run_client_gui():
    """Run as Client in GUI mode: prompt for host details and display the chat window."""
    print("\n[CLIENT MODE - GUI] Enter host connection details.")
    host_ip = input("Host IP Address: ").strip()
    try:
        host_port = int(input("Host Port (e.g., 5000): ").strip())
    except ValueError:
        print("[ERROR] Port must be a number!")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host_ip, host_port))
    except Exception as e:
        print(f"[ERROR] Could not connect to host: {e}")
        return

    auth_request = client_socket.recv(1024)
    if auth_request.startswith(b"[AUTH]"):
        session_pass = getpass.getpass("Enter session password: ").strip()
        client_socket.sendall(session_pass.encode())
        auth_resp = client_socket.recv(1024)
        if auth_resp.startswith(b"[AUTH_FAIL]"):
            print("[ERROR] Authentication failed. Check password and try again.")
            return
        elif auth_resp.startswith(b"[AUTH_OK]"):
            print("[INFO] Authentication successful!")
    else:
        print("[ERROR] Unexpected authentication response.")
        return

    session_key = client_socket.recv(1024)
    fernet = load_fernet(session_key)
    print("[INFO] Secure session established with host.")

    chat_gui = ChatGUI(client_socket, fernet)
    listener_thread = threading.Thread(target=gui_chat_listener, args=(client_socket, fernet, chat_gui), daemon=True)
    listener_thread.start()
    chat_gui.start()

def print_banner():
    """Display a simple welcome banner."""
    print("\nWelcome to AGC\n")

def main():
    # If the script is run with the "update" argument, execute the update routine.
    if len(sys.argv) > 1 and sys.argv[1].lower() == "update":
        update_agc()
        sys.exit(0)

    print_banner()
    print("Select an option:")
    print("  1. Host a chat session (Console Mode)")
    print("  2. Connect to a chat session (Console Mode)")
    print("  3. Host a chat session (GUI Mode)")
    print("  4. Connect to a chat session (GUI Mode)")
    choice = input("\nEnter 1, 2, 3, or 4: ").strip()
    if choice == "1":
        run_host()
    elif choice == "2":
        run_client()
    elif choice == "3":
        run_host_gui()
    elif choice == "4":
        run_client_gui()
    else:
        print("[ERROR] Invalid choice. Please restart and select 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()