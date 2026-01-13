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

def establish_secure_session(conn, sec, is_host):
    """
    Performs the RSA handshake to establish a shared session key.

    Args:
        conn: The socket connection.
        sec: The SecurityManager instance.
        is_host: Boolean, True if acting as host (generates RSA keys).

    Returns:
        True if successful, False otherwise.
    """
    try:
        if is_host:
            # Host generates RSA keys and sends public key
            pub_pem = sec.generate_rsa_keys()
            print(f"Fingerprint: {sec.get_fingerprint(pub_pem)}")
            NetworkManager.send_frame(conn, pub_pem)

            # Host receives encrypted session key
            enc_key = NetworkManager.recv_frame(conn)
            if sec.decrypt_session_key(enc_key):
                return True
            else:
                print("Failed to decrypt session key.")
                return False
        else:
            # Client receives public key
            pem = NetworkManager.recv_frame(conn)
            print(f"Host Fingerprint: {sec.get_fingerprint(pem)}")

            # Client generates session key and encrypts it with host's public key
            sess_key = sec.create_session_key()
            sec.set_session_key(sess_key)
            enc_sess_key = sec.encrypt_session_key(pem, sess_key)
            NetworkManager.send_frame(conn, enc_sess_key)
            return True
    except Exception as e:
        print(f"Handshake error: {e}")
        return False

def run_host(args):
    net = NetworkManager()
    sec = SecurityManager()
    port = args.port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', port))
    except OSError:
        print(f"Port {port} is busy.")
        try:
            port = int(input("Enter new port: "))
            s.bind(('', port))
        except:
            print("Invalid port or binding failed.")
            return
    s.listen(1)

    stop_event = threading.Event()
    threading.Thread(target=Discovery.announce, args=(port, stop_event), daemon=True).start()

    print(f"[HOST] Listening on Port {port}. Public IP: {net.get_public_ip() or 'Unknown'}")
    print("Waiting for client...")
    conn, addr = s.accept()
    stop_event.set()
    print(f"Connected to {addr}")

    # Handshake
    if not establish_secure_session(conn, sec, True):
        print("Handshake Failed.")
        conn.close()
        return

    # Secure Auth
    print("Authenticating...")
    settings = load_settings()
    pw = settings.get("password")
    if not pw:
        pw = getpass.getpass("Set Session Password: ")
        settings["password"] = pw
        save_settings(settings)

    try:
        NetworkManager.send_frame(conn, sec.encrypt(b"[AUTH]"))
        enc_resp = NetworkManager.recv_frame(conn)
        if not enc_resp: raise Exception("Connection closed")

        resp = sec.decrypt(enc_resp).decode().strip()
        if resp != pw:
            print("Auth Failed: Incorrect Password")
            NetworkManager.send_frame(conn, sec.encrypt(b"[FAIL]"))
            conn.close()
            return
        NetworkManager.send_frame(conn, sec.encrypt(b"[OK]"))
    except Exception as e:
        print(f"Auth Error: {e}")
        conn.close()
        return

    print("Secure Session Established.")
    if args.gui_host: GUI(conn, sec).start()
    else: CLI(conn, sec).start()

def run_client(args):
    net = NetworkManager()
    sec = SecurityManager()

    print("1. Manual IP  2. Scan LAN")
    if input("> ") == "2":
        stop = threading.Event()
        threading.Thread(target=Discovery.listen, args=(stop,), daemon=True).start()
        input("Press Enter to stop scan.\n"); stop.set()

    ip = input("Host IP: ").strip()
    port_input = input(f"Port ({args.port}): ").strip()
    port = int(port_input) if port_input else args.port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: s.connect((ip, port))
    except Exception as e: print(f"Connection failed: {e}"); return

    # Handshake
    if not establish_secure_session(s, sec, False):
        print("Handshake Failed.")
        s.close()
        return

    # Secure Auth
    print("Authenticating...")
    try:
        challenge = NetworkManager.recv_frame(s)
        if sec.decrypt(challenge) == b"[AUTH]":
            pw = getpass.getpass("Password: ")
            NetworkManager.send_frame(s, sec.encrypt(pw.encode()))

            result = NetworkManager.recv_frame(s)
            if sec.decrypt(result) != b"[OK]":
                print("Auth Failed: Host rejected password.")
                return
        else:
            print("Protocol Error: Expected AUTH")
            return
    except Exception as e:
        print(f"Auth Error: {e}")
        return

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
    parser.add_argument("--port", type=int, default=5000, help="Port to use for connection (default: 5000)")
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
        if establish_secure_session(c, sec, True):
            VoiceCall(sec).start(c)
        else:
            print("Voice Handshake Failed")
    elif args.voice_join:
        # Simplified voice client entry
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((input("Host IP: "), 6000))
        sec = SecurityManager()
        if establish_secure_session(s, sec, False):
            VoiceCall(sec).start(s)
        else:
            print("Voice Handshake Failed")
    elif args.web:
        from app import socketio, app
        socketio.run(app, host='0.0.0.0', port=args.port)
    else:
        print("Use --help for options.")

if __name__ == "__main__":
    main()
