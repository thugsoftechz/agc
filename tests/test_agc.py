import pytest
import os
import json
from unittest.mock import patch
from agc_lib.utils import load_settings, save_settings
from agc_lib.security import SecurityManager

def test_security_manager_keygen():
    sec = SecurityManager()
    pub_pem = sec.generate_rsa_keys()
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert pub_pem.endswith(b"-----END PUBLIC KEY-----\n")

def test_settings_load_save(tmp_path):
    test_settings_file = tmp_path / "test_settings.json"

    with patch('agc_lib.utils.SETTINGS_FILE', str(test_settings_file)):
        # Setup test file
        test_settings = {"chat_history": False, "contacts": {"test": "1.2.3.4"}, "password": "test"}
        save_settings(test_settings)

        # Load
        loaded = load_settings()
        assert loaded["chat_history"] is False
        assert loaded["password"] == "test"

@patch("agc_lib.ui.tk")
def test_gui_thread_safety(mock_tk):
    from agc_lib.ui import GUI
    from unittest.mock import MagicMock

    mock_conn = MagicMock()
    mock_sec = MagicMock()

    # We will simulate receiving exactly two frames, then return None to break the loop
    # Frame 1: a text message
    # Frame 2: a file
    mock_sec.decrypt.side_effect = [b"test message", b"[FILE]test.txt::file_content"]

    with patch("agc_lib.ui.NetworkManager.recv_frame") as mock_recv, patch("builtins.open"):
        mock_recv.side_effect = [b"encrypted1", b"encrypted2", None]

        gui = GUI(mock_conn, mock_sec)
        # Call _listener synchronously to test its behavior without threads
        gui._listener()

        # Verify that root.after was called 3 times: once for text, once for file, once for Disconnected
        assert gui.root.after.call_count == 3

        # Verify the exact arguments passed to after
        gui.root.after.assert_any_call(0, gui._log, "Peer: test message")
        gui.root.after.assert_any_call(0, gui._log, "Received file: recv_test.txt")
        gui.root.after.assert_any_call(0, gui._log, "Disconnected.")

@patch("builtins.input")
def test_cli_sender(mock_input, tmp_path):
    from agc_lib.ui import CLI
    from unittest.mock import MagicMock

    mock_conn = MagicMock()
    mock_sec = MagicMock()
    mock_sec.encrypt.side_effect = lambda x: b"ENC_" + x

    # Create a temporary file to simulate sending
    test_file = tmp_path / "test.txt"
    test_file.write_text("file content")

    # Simulate user entering a message, a file send command, and then exiting
    mock_input.side_effect = ["hello", f"/file {test_file}", "/exit"]

    with patch("agc_lib.ui.NetworkManager.send_frame") as mock_send:
        cli = CLI(mock_conn, mock_sec)

        # We also need to patch os.path.exists and open just in case, but using tmp_path is better
        # Actually log_chat writes to a file, let's patch it so it doesn't pollute
        with patch("agc_lib.ui.log_chat"):
            cli._sender()

            # _sender loop breaks on /exit. It should have sent two frames
            assert mock_send.call_count == 2

            # First frame is the message "hello"
            # It gets encoded, encrypted -> b"ENC_hello"
            mock_send.assert_any_call(mock_conn, b"ENC_hello")

            # Second frame is the file
            # Payload format: b"[FILE]test.txt::file content"
            # And then encrypted
            file_payload = b"[FILE]test.txt::b'file content'"
            # Wait, our encryption side effect is just prepending b"ENC_" to bytes
            expected_file_payload = b"ENC_" + b"[FILE]test.txt::file content"
            mock_send.assert_any_call(mock_conn, expected_file_payload)
