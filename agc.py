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
import argparse
import struct
import base64
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

# Optional imports handled gracefully
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
except ImportError:
    Fernet = None
    rsa = None

try:
    import tkinter as tk
    from tkinter import scrolledtext, filedialog, messagebox
except ImportError:
    tk = None

# Constants
REQUIRED_MODULES = ["cryptography", "pyperclip", "miniupnpc", "pyaudio", "cv2", "imutils", "numpy", "flask", "flask_socketio"]
SETTINGS_FILE = "chat_settings.json"
CHAT_HISTORY_FILE = "chat_history.log"
VERSION = "0.5.0"

# ------------------------- Dependency Management -------------------------
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
                    logging.error(f"Failed to install {module}. Some features may not work.")
        else:
            logging.warning(f"Missing dependencies: {', '.join(missing)}. Use --install-deps or run pip install -r requirements.txt")

# ------------------------- Update Functionality -------------------------
def update_agc():
    """Update the AGC application from the GitHub repository."""
    logging.info("Attempting to update AGC from https://github.com/thugsoftechz/agc ...")
    if os.path.exists(".git"):
        try:
            result = subprocess.run(["git", "pull"], check=True, text=True, capture_output=True)
            logging.info(result.stdout.strip())
            logging.info("Update completed successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Git pull failed: {e.stderr}")
    else:
        logging.error("No Git repository found. Please ensure that AGC was cloned from git or update manually.")

# ------------------------- Network Utilities -------------------------
def get_public_ip(timeout=5):
    """Retrieve the host's public IP using api.ipify.org."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as response:
            return response.read().decode("utf8")
    except Exception as e:
        logging.warning(f"Failed to retrieve public IP: {e}")
        return None

def setup_nat(port, description="AGC Secure Session"):
    """Map the given TCP port using UPnP."""
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
                logging.info(f"Port {port} mapped via UPnP. External IP: {external_ip}")
                return external_ip, True
            else:
                logging.warning("UPnP gateway found but port mapping failed.")
                return external_ip, False
        else:
            logging.warning("No UPnP-enabled router found.")
            return None, False
    except ImportError:
        logging.warning("miniupnpc module not found. UPnP disabled.")
        return None, False
    except Exception as e:
        logging.warning(f"NAT traversal using UPnP failed: {e}")
        return None, False

# ------------------------- Encryption -------------------------
def generate_session_key():
    if Fernet:
        return Fernet.generate_key()
    return None

def load_fernet(session_key):
    if Fernet:
        return Fernet(session_key)
    return None

def encrypt_message(fernet, message: bytes) -> bytes:
    return fernet.encrypt(message)

def decrypt_message(fernet, token: bytes) -> bytes:
    try:
        return fernet.decrypt(token)
    except Exception:
        return b"[ERROR: Unable to decrypt message]"

def get_fingerprint(key_bytes):
    """Generate a short, human-readable fingerprint of a public key."""
    if not hashes: return "UNKNOWN"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_bytes)
    return digest.finalize().hex()[:16].upper()

def perform_secure_handshake_server(conn):
    if not rsa or not Fernet:
        logging.error("Cryptography module not installed.")
        return None

    logging.info("Generating RSA keys...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint = get_fingerprint(pem)
    print(f"\n[SECURITY] Your Session Fingerprint: {fingerprint}")
    print("Verify this matches the client's fingerprint to ensure no MITM attack.\n")

    conn.sendall(len(pem).to_bytes(4, 'big'))
    conn.sendall(pem)

    length_data = recvall(conn, 4)
    if not length_data: return None
    length = int.from_bytes(length_data, 'big')
    encrypted_session_key = recvall(conn, length)

    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return session_key
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None

def perform_secure_handshake_client(conn):
    if not rsa or not Fernet:
        logging.error("Cryptography module not installed.")
        return None

    length_data = recvall(conn, 4)
    if not length_data: return None
    length = int.from_bytes(length_data, 'big')
    pem = recvall(conn, length)

    fingerprint = get_fingerprint(pem)
    print(f"\n[SECURITY] Host Fingerprint: {fingerprint}")
    print("Verify this matches the host's fingerprint to ensure no MITM attack.\n")

    public_key = serialization.load_pem_public_key(pem)
    session_key = Fernet.generate_key()

    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    conn.sendall(len(encrypted_session_key).to_bytes(4, 'big'))
    conn.sendall(encrypted_session_key)
    return session_key

# ------------------------- Communication -------------------------
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
    return recvall(conn, token_length)

# ------------------------- Settings & Logging -------------------------
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

# ------------------------- Chat Logic -------------------------
def send_file(fernet, conn, filename):
    if not os.path.exists(filename):
        logging.error(f"File '{filename}' not found.")
        return
    try:
        with open(filename, "rb") as f:
            content = f.read()
        payload = b"[FILE]" + os.path.basename(filename).encode() + b"::" + content
        encrypted = encrypt_message(fernet, payload)
        send_encrypted(conn, encrypted)
        logging.info(f"File '{filename}' sent successfully.")
        log_chat(f"Sent file: {filename}")
    except Exception as e:
        logging.error(f"Failed to send file: {e}")

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
            logging.error("Failed to parse received file data.")
    else:
        try:
            message = dec.decode()
            print("\nPeer:", message)
            log_chat("Peer: " + message)
        except Exception:
            logging.error("Unable to decode incoming message.")

def chat_listener(conn, fernet):
    while True:
        try:
            token = recv_encrypted(conn)
            if token is None:
                logging.info("Connection closed by peer.")
                break
            handle_received_data(fernet, token)
        except Exception as e:
            logging.error(f"Problem receiving data: {e}")
            break

def chat_sender(conn, fernet):
    print("\n[COMMANDS] /file <path> | /delchat | /exit\n")
    while True:
        try:
            msg = input("> ").strip()
            if not msg: continue
            if msg == "/exit":
                conn.close()
                logging.info("Chat session ended.")
                break
            elif msg == "/delchat":
                if os.path.exists(CHAT_HISTORY_FILE):
                    os.remove(CHAT_HISTORY_FILE)
                    logging.info("Chat history removed.")
            elif msg.startswith("/file "):
                _, filename = msg.split(" ", 1)
                send_file(fernet, conn, filename.strip())
            else:
                encrypted = encrypt_message(fernet, msg.encode())
                send_encrypted(conn, encrypted)
                log_chat("Me: " + msg)
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            logging.error(f"Failed to send message: {e}")
            break

# ------------------------- GUI Logic -------------------------
class ChatGUI:
    def __init__(self, conn, fernet):
        if not tk: raise ImportError("Tkinter not available")
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
                self.append_message(f"[ERROR] {e}")

    def send_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            try:
                with open(filename, "rb") as f:
                    content = f.read()
                payload = b"[FILE]" + os.path.basename(filename).encode() + b"::" + content
                encrypted = encrypt_message(self.fernet, payload)
                send_encrypted(self.conn, encrypted)
                self.append_message(f"[INFO] File '{os.path.basename(filename)}' sent.")
            except Exception as e:
                self.append_message(f"[ERROR] {e}")

    def on_close(self):
        try: self.conn.close()
        except: pass
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
                    gui.append_message(f"[INFO] Received file saved: {received_filename}")
                except:
                    gui.append_message("[ERROR] Failed to parse file.")
            else:
                try:
                    gui.append_message("Peer: " + dec.decode())
                except:
                    gui.append_message("[ERROR] Decode error.")
        except Exception as e:
            gui.append_message(f"[ERROR] {e}")
            break

# ------------------------- Audio/Video Features -------------------------
def run_voice_call(mode):
    try:
        import pyaudio
    except ImportError:
        logging.error("PyAudio not installed.")
        return

    HOST = '' if mode == 'host' else input("Enter Host IP: ").strip()
    PORT = 6000
    if mode == 'client':
        try: PORT = int(input("Enter Host Port (6000): ").strip() or 6000)
        except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if mode == 'host':
        sock.bind((HOST, PORT))
        sock.listen(1)
        logging.info(f"Voice Host listening on {PORT}...")
        conn, addr = sock.accept()
        logging.info(f"Connected to {addr}")
        session_key = perform_secure_handshake_server(conn)
    else:
        try:
            sock.connect((HOST, PORT))
            logging.info("Connected to host.")
            session_key = perform_secure_handshake_client(sock)
            conn = sock
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return

    if not session_key:
        logging.error("Handshake failed.")
        return
    fernet = Fernet(session_key)

    p = pyaudio.PyAudio()
    CHUNK, FORMAT, CHANNELS, RATE = 1024, pyaudio.paInt16, 1, 16000

    def send_audio():
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
        try:
            while True:
                data = stream.read(CHUNK, exception_on_overflow=False)
                encrypted = fernet.encrypt(data)
                conn.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
        except: pass
        finally: stream.stop_stream(); stream.close()

    def receive_audio():
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)
        try:
            while True:
                header = recvall(conn, 4)
                if not header: break
                length = int.from_bytes(header, 'big')
                data = recvall(conn, length)
                if not data: break
                stream.write(fernet.decrypt(data))
        except: pass
        finally: stream.stop_stream(); stream.close()

    t1 = threading.Thread(target=send_audio, daemon=True)
    t2 = threading.Thread(target=receive_audio, daemon=True)
    t1.start(); t2.start()
    input("Press Enter to end call...\n")
    conn.close()
    sock.close()
    p.terminate()

def run_video_call(mode):
    try:
        import cv2
        import imutils
        import numpy as np
    except ImportError:
        logging.error("OpenCV/Imutils not installed.")
        return

    HOST = '' if mode == 'host' else input("Enter Host IP: ").strip()
    PORT = 7000
    if mode == 'client':
        try: PORT = int(input("Enter Host Port (7000): ").strip() or 7000)
        except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if mode == 'host':
        sock.bind((HOST, PORT))
        sock.listen(1)
        logging.info(f"Video Host listening on {PORT}...")
        conn, addr = sock.accept()
        session_key = perform_secure_handshake_server(conn)
    else:
        try:
            sock.connect((HOST, PORT))
            session_key = perform_secure_handshake_client(sock)
            conn = sock
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return

    if not session_key: return
    fernet = Fernet(session_key)
    cap = cv2.VideoCapture(0)

    def send_video():
        while cap.isOpened():
            try:
                ret, frame = cap.read()
                if not ret: break
                frame = imutils.resize(frame, width=320)
                _, buffer = cv2.imencode('.jpg', frame)
                encrypted = fernet.encrypt(buffer.tobytes())
                conn.sendall(struct.pack("Q", len(encrypted)) + encrypted)
                cv2.imshow('My Video', frame)
                if cv2.waitKey(1) == 13: break
            except: break
        conn.close()

    def receive_video():
        data = b""
        payload_size = struct.calcsize("Q")
        while True:
            try:
                while len(data) < payload_size:
                    packet = conn.recv(4096)
                    if not packet: return
                    data += packet
                packed_msg_size = data[:payload_size]
                data = data[payload_size:]
                msg_size = struct.unpack("Q", packed_msg_size)[0]
                while len(data) < msg_size:
                    data += conn.recv(4096)
                encrypted_data = data[:msg_size]
                data = data[msg_size:]
                frame_bytes = fernet.decrypt(encrypted_data)
                frame = cv2.imdecode(np.frombuffer(frame_bytes, np.uint8), cv2.IMREAD_COLOR)
                if frame is not None: cv2.imshow('Peer Video', frame)
                if cv2.waitKey(1) == 13: break
            except: break

    t1 = threading.Thread(target=send_video, daemon=True)
    t2 = threading.Thread(target=receive_video, daemon=True)
    t1.start(); t2.start()
    print("Press Enter in video window to exit.")
    input()
    conn.close()
    sock.close()
    cap.release()
    cv2.destroyAllWindows()

# ------------------------- Web App -------------------------
def run_web_app():
    logging.info("Starting Web Interface on http://0.0.0.0:5000")
    try:
        from app import socketio, app
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except ImportError:
        logging.error("Flask/SocketIO not found.")

# ------------------------- Main & Discovery -------------------------
def discovery_listener(stop_event):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    c.bind(("", 5005))
    while not stop_event.is_set():
        try:
            c.settimeout(1.0)
            data, addr = c.recvfrom(1024)
            if data.startswith(b"[AGC_HOST]"):
                print(f"[FOUND] {addr[0]} - {data.decode()}")
        except: pass

def discovery_announcer(port, stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while not stop_event.is_set():
        try:
            s.sendto(f"[AGC_HOST]:{port}".encode(), ('<broadcast>', 5005))
            time.sleep(2)
        except: pass

def run_chat_host(gui=False):
    PORT = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(('', PORT))
    except: PORT = int(input("Port 5000 busy. Enter new port: "))
    s.bind(('', PORT))
    s.listen(1)

    stop_disc = threading.Event()
    threading.Thread(target=discovery_announcer, args=(PORT, stop_disc), daemon=True).start()

    ip = get_public_ip()
    print(f"\n[HOST] Listening on Port {PORT}. WAN IP: {ip or 'Unknown'}")

    settings = load_settings()
    pw = settings.get("password") or getpass.getpass("Set Session Password: ")
    settings["password"] = pw; save_settings(settings)

    print("Waiting for client...")
    conn, addr = s.accept()
    stop_disc.set()
    print(f"Connected to {addr}")

    conn.sendall(b"[AUTH]")
    if conn.recv(1024).decode().strip() != pw:
        conn.sendall(b"[FAIL]")
        conn.close()
        return
    conn.sendall(b"[OK]")

    key = perform_secure_handshake_server(conn)
    if not key: return
    fernet = load_fernet(key)

    if gui:
        c = ChatGUI(conn, fernet)
        threading.Thread(target=gui_chat_listener, args=(conn, fernet, c), daemon=True).start()
        c.start()
    else:
        threading.Thread(target=chat_listener, args=(conn, fernet), daemon=True).start()
        chat_sender(conn, fernet)

def run_chat_client(gui=False):
    print("1. Enter IP  2. Scan LAN")
    if input("> ") == "2":
        stop = threading.Event()
        threading.Thread(target=discovery_listener, args=(stop,), daemon=True).start()
        input("Scanning... Press Enter to stop.\n"); stop.set()

    ip = input("Host IP: ").strip()
    port = int(input("Port (5000): ").strip() or 5000)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: s.connect((ip, port))
    except Exception as e: print(f"Error: {e}"); return

    if s.recv(1024) == b"[AUTH]":
        s.sendall(getpass.getpass("Password: ").encode())
        if s.recv(1024) != b"[OK]": print("Auth Failed"); return

    key = perform_secure_handshake_client(s)
    if not key: return
    fernet = load_fernet(key)

    settings = load_settings()
    settings["last_connection"] = {"host_ip": ip, "host_port": port}
    save_settings(settings)

    if gui:
        c = ChatGUI(s, fernet)
        threading.Thread(target=gui_chat_listener, args=(s, fernet, c), daemon=True).start()
        c.start()
    else:
        threading.Thread(target=chat_listener, args=(s, fernet), daemon=True).start()
        chat_sender(s, fernet)

def main():
    parser = argparse.ArgumentParser(description="AGC: Advanced Secure Chat Tool")
    parser.add_argument("--host", action="store_true", help="Host Chat (CLI)")
    parser.add_argument("--join", action="store_true", help="Join Chat (CLI)")
    parser.add_argument("--gui-host", action="store_true", help="Host Chat (GUI)")
    parser.add_argument("--gui-join", action="store_true", help="Join Chat (GUI)")
    parser.add_argument("--web", action="store_true", help="Web Interface")
    parser.add_argument("--voice-host", action="store_true", help="Host Voice")
    parser.add_argument("--voice-join", action="store_true", help="Join Voice")
    parser.add_argument("--video-host", action="store_true", help="Host Video")
    parser.add_argument("--video-join", action="store_true", help="Join Video")
    parser.add_argument("--update", action="store_true", help="Update AGC")
    parser.add_argument("--install-deps", action="store_true", help="Install Dependencies")
    args = parser.parse_args()

    check_dependencies(auto_install=args.install_deps)

    if args.update: update_agc()
    elif args.host: run_chat_host()
    elif args.join: run_chat_client()
    elif args.gui_host: run_chat_host(gui=True)
    elif args.gui_join: run_chat_client(gui=True)
    elif args.web: run_web_app()
    elif args.voice_host: run_voice_call('host')
    elif args.voice_join: run_voice_call('client')
    elif args.video_host: run_video_call('host')
    elif args.video_join: run_video_call('client')
    else:
        print(f"AGC v{VERSION}\nUse --help for options or select:")
        print("1. Host (CLI)  2. Join (CLI)\n3. Host (GUI)  4. Join (GUI)\n5. Web App\n6. Voice (Host) 7. Voice (Client)\n8. Video (Host) 9. Video (Client)")
        c = input("Choice: ")
        if c == '1': run_chat_host()
        elif c == '2': run_chat_client()
        elif c == '3': run_chat_host(gui=True)
        elif c == '4': run_chat_client(gui=True)
        elif c == '5': run_web_app()
        elif c == '6': run_voice_call('host')
        elif c == '7': run_voice_call('client')
        elif c == '8': run_video_call('host')
        elif c == '9': run_video_call('client')

if __name__ == "__main__":
    main()
