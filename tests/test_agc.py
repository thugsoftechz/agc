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
