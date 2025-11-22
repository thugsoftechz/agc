import sys
import socket
from cryptography.fernet import Fernet

# Mock dependencies if they fail
try:
    import cv2
except ImportError:
    print("cv2 not found, mocking it")
    import types
    cv2 = types.ModuleType("cv2")
    sys.modules["cv2"] = cv2

try:
    import pyaudio
except ImportError:
    print("pyaudio not found, mocking it")
    import types
    pyaudio = types.ModuleType("pyaudio")
    sys.modules["pyaudio"] = pyaudio

# Now try to import agc
try:
    import agc
    print("Successfully imported agc")
except Exception as e:
    print(f"Failed to import agc: {e}")
    sys.exit(1)

# Test SecureConnection
try:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    # Mock socket
    class MockSocket:
        def sendall(self, data):
            pass
        def recv(self, n):
            return b""

    sock = MockSocket()
    conn = agc.SecureConnection(sock, fernet)
    print("Successfully instantiated SecureConnection")
except Exception as e:
    print(f"Failed to instantiate SecureConnection: {e}")
    sys.exit(1)
