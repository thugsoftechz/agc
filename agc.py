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
import struct
from cryptography.fernet import Fernet

# Ensure required dependencies are installed
REQUIRED_MODULES = ["cryptography", "pyperclip", "miniupnpc", "pyaudio", "opencv-python"]

def ensure_dependencies():
    """Ensure required dependencies are installed."""
    for module in REQUIRED_MODULES:
        try:
            if module == "opencv-python":
                import cv2
            else:
                __import__(module)
        except ImportError:
            print(f"[INFO] Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

ensure_dependencies()

# Import optional libraries
try:
    import cv2
except ImportError:
    cv2 = None

try:
    import pyaudio
except ImportError:
    pyaudio = None

try:
    import tkinter as tk
    from tkinter import scrolledtext, filedialog, messagebox
except ImportError:
    print("[ERROR] tkinter is not installed. GUI functionality will not be available.")

# ------------------------- Update Functionality -------------------------
def update_agc():
    """
    Update the AGC application from the GitHub repository.
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
        print("[ERROR] No Git repository found. Please ensure that AGC was cloned from https://github.com/thugsoftechz/agc or update manually.")

# ------------------------- Core Functions -------------------------
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
    Map the given TCP port using UPnP.
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
                print(f"[INFO] Port {port} mapped via UPnP. External IP: {external_ip}")
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

class SecureConnection:
    """Helper class for secure, framed communication."""
    def __init__(self, socket, fernet):
        self.socket = socket
        self.fernet = fernet

    def send(self, data: bytes):
        """Encrypts and sends data with a length header."""
        try:
            encrypted = self.fernet.encrypt(data)
            length = len(encrypted)
            self.socket.sendall(length.to_bytes(4, byteorder='big'))
            self.socket.sendall(encrypted)
            return True
        except Exception as e:
            print(f"[ERROR] Secure send failed: {e}")
            return False

    def recv(self):
        """Receives a length header, then the body, and decrypts it."""
        try:
            header = self._recvall(4)
            if not header:
                return None
            length = int.from_bytes(header, byteorder='big')
            encrypted = self._recvall(length)
            if not encrypted:
                return None
            return self.fernet.decrypt(encrypted)
        except Exception as e:
            print(f"[ERROR] Secure recv failed: {e}")
            return None

    def _recvall(self, n):
        data = b""
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

# ----- Legacy Framing Helper Functions (for backward compatibility in Chat) -----
def recvall(conn, n):
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_encrypted(conn, token: bytes):
    token_length = len(token)
    conn.sendall(token_length.to_bytes(4, byteorder='big'))
    conn.sendall(token)

def recv_encrypted(conn):
    header = recvall(conn, 4)
    if not header:
        return None
    token_length = int.from_bytes(header, byteorder="big")
    token = recvall(conn, token_length)
    return token

def encrypt_message(fernet, message: bytes) -> bytes:
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"chat_history": True, "contacts": {}}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def log_chat(message: str):
    settings = load_settings()
    if settings.get("chat_history", True):
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(message + "\n")

def send_file(fernet, conn, filename):
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

# ------------------------- GUI Components -------------------------
class ChatGUI:
    def __init__(self, conn, fernet):
        self.conn = conn
        self.fernet = fernet
        self.root = tk.Tk()
        self.root.title("AGC Chat Session")
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state="disabled", width=50, height=20)
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
        def inner():
            self.text_area.config(state="normal")
            self.text_area.insert(tk.END, msg + "\n")
            self.text_area.see(tk.END)
            self.text_area.config(state="disabled")
        self.root.after(0, inner)

    def send_message(self, event=None):
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

# ------------------------- Common Media Call Functions -------------------------
def establish_secure_media_connection(role, port, password_prompt=True):
    """
    Establishes a secure connection for media (voice/video).
    Role: 'host' or 'client'
    Returns: (SecureConnection object, socket object) or (None, None)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if role == 'host':
        while True:
            try:
                sock.bind(('', port))
                break
            except Exception as e:
                print(f"[ERROR] Unable to bind port {port}: {e}")
                port_str = input("Enter a different port number: ").strip()
                try:
                    port = int(port_str)
                except ValueError:
                    print("Invalid port.")
        sock.listen(1)
        print(f"[INFO] Listening for media connection on port {port}...")
        conn, addr = sock.accept()
        print(f"[INFO] Media connection from {addr}")

        # Handshake
        if password_prompt:
            stored_pass = load_settings().get("password")
            if not stored_pass:
                stored_pass = getpass.getpass("Set a session password for verification: ")

            conn.sendall(b"[AUTH] Password?")
            peer_pass = conn.recv(1024).decode().strip()
            if peer_pass != stored_pass:
                conn.sendall(b"[AUTH_FAIL]")
                print("[ERROR] Auth failed.")
                conn.close()
                sock.close()
                return None, None
            conn.sendall(b"[AUTH_OK]")

        session_key = generate_session_key()
        conn.sendall(session_key)
        fernet = load_fernet(session_key)
        return SecureConnection(conn, fernet), conn

    elif role == 'client':
        host_ip = input("Enter Host IP: ").strip()
        try:
            host_port = int(input(f"Enter Host Port (default {port}): ").strip() or port)
        except ValueError:
            print("Invalid port.")
            return None, None

        try:
            sock.connect((host_ip, host_port))
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return None, None

        if password_prompt:
            auth_req = sock.recv(1024)
            if auth_req.startswith(b"[AUTH]"):
                pwd = getpass.getpass("Enter session password: ").strip()
                sock.sendall(pwd.encode())
                auth_resp = sock.recv(1024)
                if not auth_resp.startswith(b"[AUTH_OK]"):
                    print("[ERROR] Auth failed.")
                    sock.close()
                    return None, None

        session_key = sock.recv(1024)
        fernet = load_fernet(session_key)
        return SecureConnection(sock, fernet), sock

# ------------------------- Voice Call Feature -------------------------
def run_voice_call(role):
    if pyaudio is None:
        print("[ERROR] PyAudio not installed. Cannot run voice call.")
        return

    print(f"\n[VOICE CALL - {role.upper()}]")
    secure_conn, raw_socket = establish_secure_media_connection(role, 6000)
    if not secure_conn:
        return

    print("[INFO] Secure Voice Call Established.")
    p = pyaudio.PyAudio()
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 16000

    running = True

    def send_audio():
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
        try:
            while running:
                data = stream.read(CHUNK, exception_on_overflow=False)
                if not secure_conn.send(data):
                    break
        except Exception as e:
            print(f"[Voice] Send error: {e}")
        finally:
            stream.stop_stream()
            stream.close()

    def receive_audio():
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)
        try:
            while running:
                data = secure_conn.recv()
                if not data:
                    break
                stream.write(data)
        except Exception as e:
            print(f"[Voice] Recv error: {e}")
        finally:
            stream.stop_stream()
            stream.close()

    t_send = threading.Thread(target=send_audio, daemon=True)
    t_recv = threading.Thread(target=receive_audio, daemon=True)
    t_send.start()
    t_recv.start()

    input("Press Enter to end the voice call...\n")
    running = False
    raw_socket.close()
    p.terminate()
    print("Voice call ended.")

# ------------------------- Video Call Feature -------------------------
def run_video_call(role):
    if cv2 is None:
        print("[ERROR] OpenCV not installed. Cannot run video call.")
        return

    print(f"\n[VIDEO CALL - {role.upper()}]")
    secure_conn, raw_socket = establish_secure_media_connection(role, 7000)
    if not secure_conn:
        return

    print("[INFO] Secure Video Call Established. Press 'q' in the video window to exit.")
    cap = cv2.VideoCapture(0)
    running = True

    def send_video():
        try:
            while running and cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                # Resize to reduce bandwidth
                frame = cv2.resize(frame, (640, 480))
                # Encode as JPEG
                _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                data = buffer.tobytes()
                if not secure_conn.send(data):
                    break
                time.sleep(0.05) # Limit FPS approx 20
        except Exception as e:
            print(f"[Video] Send error: {e}")

    def receive_video():
        import numpy as np
        try:
            while running:
                data = secure_conn.recv()
                if not data:
                    break
                # Decode JPEG
                nparr = np.frombuffer(data, np.uint8)
                frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if frame is not None:
                    cv2.imshow(f"Video Call ({role})", frame)
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        # Signal exit logic here if needed, but better to use main thread input
                        pass
        except Exception as e:
            print(f"[Video] Recv error: {e}")
        finally:
            cv2.destroyAllWindows()

    t_send = threading.Thread(target=send_video, daemon=True)
    t_recv = threading.Thread(target=receive_video, daemon=True)
    t_send.start()
    t_recv.start()

    input("Press Enter to end the video call...\n")
    running = False
    cap.release()
    raw_socket.close()
    print("Video call ended.")

# ------------------------- Main Application Modes -------------------------
def run_host():
    """Run as Host (Console Mode)."""
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
        f"\n[HOST INFO]\nLAN IP: {lan_ip}\nWAN IP: {wan_ip}\nPort: {PORT}\nSession Password: {stored_pass}\n"
        "Use LAN IP for local; use WAN IP for remote access.\n"
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
    """Run as Client (Console Mode) using manual host details."""
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
        settings = load_settings()
        settings["last_connection"] = {"host_ip": host_ip, "host_port": host_port}
        save_settings(settings)
        session_key = client_socket.recv(1024)
        fernet = load_fernet(session_key)
        print("[INFO] Secure session established with host. You may now chat!")
        threading.Thread(target=chat_listener, args=(client_socket, fernet), daemon=True).start()
        chat_sender(client_socket, fernet)

def run_client_last():
    """
    Run as Client (Console Mode) reconnecting with the last saved host details.
    """
    settings = load_settings()
    last = settings.get("last_connection")
    if not last:
        print("[ERROR] No last connection details found. Please enter details manually.")
        return
    host_ip = last.get("host_ip")
    host_port = last.get("host_port")
    print(f"\n[CONNECTING TO LAST SESSION] Host IP: {host_ip} Port: {host_port}")
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
        print("[INFO] Secure session established with host. You may now chat!")
        threading.Thread(target=chat_listener, args=(client_socket, fernet), daemon=True).start()
        chat_sender(client_socket, fernet)

def run_host_gui():
    """Run as Host (GUI Mode)."""
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
        f"\n[HOST INFO]\nLAN IP: {lan_ip}\nWAN IP: {wan_ip}\nPort: {PORT}\nSession Password: {stored_pass}\n"
        "Use LAN IP if local; use WAN IP if remote.\n"
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
    threading.Thread(target=gui_chat_listener, args=(conn, fernet, chat_gui), daemon=True).start()
    chat_gui.start()

def run_client_gui():
    """Run as Client (GUI Mode)."""
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
    threading.Thread(target=gui_chat_listener, args=(client_socket, fernet, chat_gui), daemon=True).start()
    chat_gui.start()

def print_banner():
    """Display a simple welcome banner."""
    print("\nWelcome to AGC\n")

# ------------------------- Main Entry Point -------------------------
def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "update":
        update_agc()
        sys.exit(0)
    print_banner()
    print("Select an option:")
    print("  1. Host a chat session (Console Mode)")
    print("  2. Connect to a chat session (Console Mode)")
    print("  3. Host a chat session (GUI Mode)")
    print("  4. Connect to a chat session (GUI Mode)")
    print("  5. Connect to last session (Console Mode)")
    print("  6. Start voice call (Host)")
    print("  7. Join voice call (Client)")
    print("  8. Start video call (Host)")
    print("  9. Join video call (Client)")
    choice = input("\nEnter choice (1-9): ").strip()
    if choice == "1":
        run_host()
    elif choice == "2":
        run_client()
    elif choice == "3":
        run_host_gui()
    elif choice == "4":
        run_client_gui()
    elif choice == "5":
        run_client_last()
    elif choice == "6":
        run_voice_call('host')
    elif choice == "7":
        run_voice_call('client')
    elif choice == "8":
        run_video_call('host')
    elif choice == "9":
        run_video_call('client')
    else:
        print("[ERROR] Invalid choice. Please restart and select a valid option.")

if __name__ == "__main__":
    main()
