import threading
import socket
import struct
import logging
try:
    import pyaudio
except ImportError:
    pyaudio = None
try:
    import cv2
    import imutils
    import numpy as np
except ImportError:
    cv2 = None

from .networking import NetworkManager

class VoiceCall:
    def __init__(self, sec_manager):
        self.sec = sec_manager
        self.running = False

    def start(self, conn):
        if not pyaudio:
            logging.error("PyAudio not installed.")
            return
        self.running = True
        p = pyaudio.PyAudio()
        CHUNK, FORMAT, CHANNELS, RATE = 1024, pyaudio.paInt16, 1, 16000

        def send():
            stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
            try:
                while self.running:
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    encrypted = self.sec.encrypt(data)
                    NetworkManager.send_frame(conn, encrypted)
            except: pass
            finally: stream.close()

        def recv():
            stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)
            try:
                while self.running:
                    data = NetworkManager.recv_frame(conn)
                    if not data: break
                    stream.write(self.sec.decrypt(data))
            except: pass
            finally: stream.close()

        t1 = threading.Thread(target=send, daemon=True)
        t2 = threading.Thread(target=recv, daemon=True)
        t1.start(); t2.start()
        input("Press Enter to end call...\n")
        self.running = False
        conn.close()
        p.terminate()

class VideoCall:
    def __init__(self, sec_manager):
        self.sec = sec_manager
        self.running = False

    def start(self, conn):
        if not cv2:
            logging.error("OpenCV not installed.")
            return
        self.running = True
        cap = cv2.VideoCapture(0)

        def send():
            while self.running and cap.isOpened():
                try:
                    ret, frame = cap.read()
                    if not ret: break
                    frame = imutils.resize(frame, width=320)
                    _, buffer = cv2.imencode('.jpg', frame)
                    encrypted = self.sec.encrypt(buffer.tobytes())
                    NetworkManager.send_frame(conn, encrypted)
                    cv2.imshow('My Video', frame)
                    if cv2.waitKey(1) == 13: break
                except: break
            self.running = False
            conn.close()

        def recv():
            while self.running:
                try:
                    data = NetworkManager.recv_frame(conn)
                    if not data: break
                    frame_bytes = self.sec.decrypt(data)
                    frame = cv2.imdecode(np.frombuffer(frame_bytes, np.uint8), cv2.IMREAD_COLOR)
                    if frame is not None: cv2.imshow('Peer Video', frame)
                    if cv2.waitKey(1) == 13: break
                except: break
            self.running = False

        t1 = threading.Thread(target=send, daemon=True)
        t2 = threading.Thread(target=recv, daemon=True)
        t1.start(); t2.start()
        print("Press Enter in video window to exit.")
        input()
        self.running = False
        cap.release()
        cv2.destroyAllWindows()
