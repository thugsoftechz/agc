#!/usr/bin/env python3
import argparse
import socket
import threading
import getpass
import sys
from agc_lib import (
    SecurityManager, NetworkManager, Discovery,
    CLI, GUI, VoiceCall, VideoCall,
    setup_logging, check_dependencies, load_settings, save_settings
)

def run_host(args):
    net = NetworkManager()
    sec = SecurityManager()
    port = 5000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(('', port))
    except: port = int(input("Port 5000 busy. Enter new port: ")) or 5000; s.bind(('', port))
    s.listen(1)

    stop_event = threading.Event()
    threading.Thread(target=Discovery.announce, args=(port, stop_event), daemon=True).start()

    print(f"[HOST] Listening on Port {port}. Public IP: {net.get_public_ip() or 'Unknown'}")
    print("Waiting for client...")
    conn, addr = s.accept()
    stop_event.set()
    print(f"Connected to {addr}")

    # Auth
    settings = load_settings()
    pw = settings.get("password")
    if not pw:
        pw = getpass.getpass("Set Session Password: ")
        settings["password"] = pw
        save_settings(settings)

    conn.sendall(b"[AUTH]")
    if conn.recv(1024).decode().strip() != pw:
        conn.sendall(b"[FAIL]")
        conn.close()
        return
    conn.sendall(b"[OK]")

    # Handshake
    pub_pem = sec.generate_rsa_keys()
    print(f"Fingerprint: {sec.get_fingerprint(pub_pem)}")
    NetworkManager.send_frame(conn, pub_pem)

    enc_key = NetworkManager.recv_frame(conn)
    if sec.decrypt_session_key(enc_key):
        print("Secure Session Established.")
        if args.gui_host: GUI(conn, sec).start()
        else: CLI(conn, sec).start()
    else:
        print("Handshake Failed.")

def run_client(args):
    net = NetworkManager()
    sec = SecurityManager()

    print("1. Manual IP  2. Scan LAN")
    if input("> ") == "2":
        stop = threading.Event()
        threading.Thread(target=Discovery.listen, args=(stop,), daemon=True).start()
        input("Press Enter to stop scan.\n"); stop.set()

    ip = input("Host IP: ").strip()
    port = int(input("Port (5000): ").strip() or 5000)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: s.connect((ip, port))
    except Exception as e: print(f"Connection failed: {e}"); return

    if s.recv(1024) == b"[AUTH]":
        s.sendall(getpass.getpass("Password: ").encode())
        if s.recv(1024) != b"[OK]": print("Auth Failed"); return

    # Handshake
    pem = NetworkManager.recv_frame(s)
    print(f"Host Fingerprint: {sec.get_fingerprint(pem)}")

    sess_key = sec.create_session_key()
    sec.set_session_key(sess_key)
    enc_sess_key = sec.encrypt_session_key(pem, sess_key)
    NetworkManager.send_frame(s, enc_sess_key)

    print("Secure Session Established.")
    if args.gui_join: GUI(s, sec).start()
    else: CLI(s, sec).start()

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="AGC: Advanced Secure Chat")
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--join", action="store_true")
    parser.add_argument("--gui-host", action="store_true")
    parser.add_argument("--gui-join", action="store_true")
    parser.add_argument("--voice-host", action="store_true")
    parser.add_argument("--voice-join", action="store_true")
    parser.add_argument("--web", action="store_true")
    parser.add_argument("--install-deps", action="store_true")
    args = parser.parse_args()

    check_dependencies(args.install_deps)

    if args.host: run_host(args)
    elif args.join: run_client(args)
    elif args.gui_host: run_host(args)
    elif args.gui_join: run_client(args)
    elif args.voice_host:
        # Simplified voice host entry
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 6000)); s.listen(1)
        c, a = s.accept()
        sec = SecurityManager()
        # Quick handshake for voice
        pub = sec.generate_rsa_keys()
        NetworkManager.send_frame(c, pub)
        key = NetworkManager.recv_frame(c)
        sec.decrypt_session_key(key)
        VoiceCall(sec).start(c)
    elif args.voice_join:
        # Simplified voice client entry
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((input("Host IP: "), 6000))
        sec = SecurityManager()
        pem = NetworkManager.recv_frame(s)
        k = sec.create_session_key(); sec.set_session_key(k)
        NetworkManager.send_frame(s, sec.encrypt_session_key(pem, k))
        VoiceCall(sec).start(s)
    elif args.web:
        from app import socketio, app
        socketio.run(app, host='0.0.0.0', port=5000)
    else:
        print("Use --help for options.")

if __name__ == "__main__":
    main()
