import pytest
from agc_lib.security import SecurityManager

def test_security_manager_encryption():
    sec1 = SecurityManager()
    sec2 = SecurityManager()

    # Generate RSA keys for sec1 (acting as host)
    pub_pem = sec1.generate_rsa_keys()
    assert pub_pem is not None

    # Generate session key for sec2 (acting as client)
    session_key = sec2.create_session_key()
    sec2.set_session_key(session_key)

    # Encrypt session key with sec1's public key
    enc_session_key = sec2.encrypt_session_key(pub_pem, session_key)

    # sec1 decrypts the session key
    assert sec1.decrypt_session_key(enc_session_key) is True

    # Test symmetric encryption
    message = b"Secret Message"
    encrypted_message = sec2.encrypt(message)
    decrypted_message = sec1.decrypt(encrypted_message)

    assert decrypted_message == message

def test_security_manager_fingerprint():
    sec = SecurityManager()
    pub_pem = sec.generate_rsa_keys()

    fingerprint = sec.get_fingerprint(pub_pem)
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 16
