import socket
import urllib.request
import logging
import time
import threading

try:
    import miniupnpc
except ImportError:
    miniupnpc = None

class NetworkManager:
    def __init__(self):
        self.lan_ip = self.get_lan_ip()
        self.wan_ip = None

    def get_lan_ip(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"

    def get_public_ip(self, timeout=5):
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as response:
                self.wan_ip = response.read().decode("utf8")
                return self.wan_ip
        except Exception:
            return None

    def setup_upnp(self, port, description="AGC Session"):
        if not miniupnpc:
            logging.warning("MiniUPnPc not installed.")
            return None, False
        try:
            upnpc = miniupnpc.UPnP()
            upnpc.discoverdelay = 200
            if upnpc.discover() > 0:
                upnpc.selectigd()
                ext_ip = upnpc.externalipaddress()
                if upnpc.addportmapping(port, 'TCP', upnpc.lanaddr, port, description, ''):
                    logging.info(f"UPnP: Port {port} mapped to {ext_ip}")
                    return ext_ip, True
        except Exception as e:
            logging.warning(f"UPnP failed: {e}")
        return None, False

    @staticmethod
    def recvall(conn, n):
        chunks = []
        current_len = 0
        while current_len < n:
            packet = conn.recv(n - current_len)
            if not packet: return None
            chunks.append(packet)
            current_len += len(packet)
        return b"".join(chunks)

    @staticmethod
    def send_frame(conn, data):
        conn.sendall(len(data).to_bytes(4, 'big'))
        conn.sendall(data)

    @staticmethod
    def recv_frame(conn):
        header = NetworkManager.recvall(conn, 4)
        if not header: return None
        length = int.from_bytes(header, 'big')
        return NetworkManager.recvall(conn, length)

class Discovery:
    @staticmethod
    def listen(stop_event):
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

    @staticmethod
    def announce(port, stop_event):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while not stop_event.is_set():
            try:
                s.sendto(f"[AGC_HOST]:{port}".encode(), ('<broadcast>', 5005))
                time.sleep(2)
            except: pass
