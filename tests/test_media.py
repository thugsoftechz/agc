import pytest
from unittest.mock import MagicMock
from agc_lib.media import VideoCall
import struct
import builtins
import cv2

def test_video_call_recv(monkeypatch):
    sec_manager = MagicMock()
    sec_manager.decrypt = lambda x: b"decrypted_" + x

    call = VideoCall(sec_manager)
    call.running = True

    conn = MagicMock()

    # Create fake packets
    msg1 = b"hello_world1"
    msg2 = b"hello_world2"

    payload1 = struct.pack("Q", len(msg1)) + msg1
    payload2 = struct.pack("Q", len(msg2)) + msg2

    stream_data = payload1 + payload2

    # Mock conn.recv to return chunks of the stream
    chunk_size = 5
    pos = 0
    def mock_recv(size):
        nonlocal pos
        if pos >= len(stream_data):
            call.running = False # stop the loop
            return b""
        res = stream_data[pos:pos+size]
        pos += len(res)
        return res

    conn.recv.side_effect = mock_recv

    import numpy as np
    monkeypatch.setattr("cv2.imdecode", MagicMock(return_value=np.zeros((10,10,3), dtype=np.uint8)))
    monkeypatch.setattr("cv2.imshow", MagicMock())
    monkeypatch.setattr("cv2.waitKey", MagicMock(return_value=-1))
    monkeypatch.setattr("cv2.VideoCapture", MagicMock())
    monkeypatch.setattr("builtins.input", MagicMock())

    import threading
    def mock_thread(target, daemon):
        if target.__name__ == 'recv':
            target()
        return MagicMock()
    monkeypatch.setattr("threading.Thread", mock_thread)

    call.start(conn)
