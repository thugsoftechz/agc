import os
import logging
try:
    import tkinter as tk
    from tkinter import scrolledtext, filedialog
except ImportError:
    tk = None

from .networking import NetworkManager
from .utils import log_chat

class CLI:
    def __init__(self, conn, sec_manager):
        self.conn = conn
        self.sec = sec_manager

    def start(self):
        import threading
        threading.Thread(target=self._listener, daemon=True).start()
        self._sender()

    def _listener(self):
        while True:
            try:
                token = NetworkManager.recv_frame(self.conn)
                if not token:
                    print("[INFO] Connection closed.")
                    break
                dec = self.sec.decrypt(token)
                if dec.startswith(b"[FILE]"):
                    self._handle_file(dec)
                else:
                    print(f"\nPeer: {dec.decode()}")
                    log_chat(f"Peer: {dec.decode()}")
            except Exception as e:
                logging.error(f"Receive error: {e}")
                break

    def _handle_file(self, data):
        try:
            content = data[len(b"[FILE]"):]
            fname, fcontent = content.split(b"::", 1)
            fname = fname.decode()
            with open("recv_" + fname, "wb") as f: f.write(fcontent)
            print(f"\n[INFO] File received: recv_{fname}")
        except:
            print("[ERROR] File parse failed.")

    def _sender(self):
        print("\nCommands: /file <path> | /exit")
        while True:
            try:
                msg = input("> ").strip()
                if not msg: continue
                if msg == "/exit": break
                if msg.startswith("/file "):
                    self._send_file(msg.split(" ", 1)[1])
                else:
                    self.conn.sendall(len(self.sec.encrypt(msg.encode())).to_bytes(4, 'big') + self.sec.encrypt(msg.encode()))
                    log_chat(f"Me: {msg}")
            except: break
        self.conn.close()

    def _send_file(self, path):
        if not os.path.exists(path):
             print("File not found")
             return
        with open(path, "rb") as f:
            payload = b"[FILE]" + os.path.basename(path).encode() + b"::" + f.read()
        data = self.sec.encrypt(payload)
        self.conn.sendall(len(data).to_bytes(4, 'big') + data)
        print(f"Sent {path}")

class GUI:
    def __init__(self, conn, sec_manager):
        if not tk: raise ImportError("Tkinter missing")
        self.conn = conn
        self.sec = sec_manager
        self.root = tk.Tk()
        self.root.title("AGC Secure Chat")
        self._setup_ui()

    def _setup_ui(self):
        self.txt = scrolledtext.ScrolledText(self.root, state='disabled')
        self.txt.pack(padx=10, pady=10)
        self.entry = tk.Entry(self.root)
        self.entry.pack(padx=10, pady=5, fill=tk.X)
        self.entry.bind("<Return>", self._send)
        btn_frm = tk.Frame(self.root)
        btn_frm.pack()
        tk.Button(btn_frm, text="Send", command=self._send).pack(side=tk.LEFT)
        tk.Button(btn_frm, text="File", command=self._file).pack(side=tk.LEFT)

    def _log(self, msg):
        self.txt.config(state='normal')
        self.txt.insert(tk.END, msg + "\n")
        self.txt.see(tk.END)
        self.txt.config(state='disabled')

    def _send(self, event=None):
        msg = self.entry.get().strip()
        if not msg: return
        try:
            enc = self.sec.encrypt(msg.encode())
            NetworkManager.send_frame(self.conn, enc)
            self._log(f"Me: {msg}")
            self.entry.delete(0, tk.END)
        except Exception as e: self._log(f"Error: {e}")

    def _file(self):
        path = filedialog.askopenfilename()
        if path:
            try:
                with open(path, "rb") as f:
                    payload = b"[FILE]" + os.path.basename(path).encode() + b"::" + f.read()
                enc = self.sec.encrypt(payload)
                NetworkManager.send_frame(self.conn, enc)
                self._log(f"Sent file: {os.path.basename(path)}")
            except Exception as e: self._log(f"Error: {e}")

    def _listener(self):
        while True:
            try:
                token = NetworkManager.recv_frame(self.conn)
                if not token: break
                dec = self.sec.decrypt(token)
                if dec.startswith(b"[FILE]"):
                    fname = dec[6:].split(b"::", 1)[0].decode()
                    # Simple save, real app should probably ask user or save to downloads
                    with open("recv_" + fname, "wb") as f:
                         f.write(dec[6:].split(b"::", 1)[1])
                    self._log(f"Received file: recv_{fname}")
                else:
                    self._log(f"Peer: {dec.decode()}")
            except: break
        self._log("Disconnected.")

    def start(self):
        import threading
        threading.Thread(target=self._listener, daemon=True).start()
        self.root.mainloop()
