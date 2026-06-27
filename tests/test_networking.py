import pytest
from agc_lib.networking import NetworkManager

class MockConnection:
    def __init__(self):
        self.sent_data = b""
        self.recv_data = b""
        self.closed = False

    def sendall(self, data):
        self.sent_data += data

    def recv(self, size):
        if not self.recv_data:
            return b""
        data = self.recv_data[:size]
        self.recv_data = self.recv_data[size:]
        return data

    def close(self):
        self.closed = True

def test_send_frame():
    conn = MockConnection()
    data_to_send = b"hello test frame"
    NetworkManager.send_frame(conn, data_to_send)

    expected_header = len(data_to_send).to_bytes(4, 'big')
    assert conn.sent_data == expected_header + data_to_send

def test_recv_frame():
    conn = MockConnection()
    data_to_receive = b"incoming test data"
    header = len(data_to_receive).to_bytes(4, 'big')

    conn.recv_data = header + data_to_receive

    received = NetworkManager.recv_frame(conn)

    assert received == data_to_receive

def test_recv_frame_empty():
    conn = MockConnection()
    # Connection closes before reading header
    conn.recv_data = b""
    received = NetworkManager.recv_frame(conn)
    assert received is None
