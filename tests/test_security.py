import pytest
from agc_lib.security import SecurityManager
from cryptography.hazmat.primitives import serialization

def test_generate_rsa_keys():
    sec = SecurityManager()
    pem = sec.generate_rsa_keys()

    assert sec.rsa_private is not None
    assert sec.rsa_public is not None
    assert isinstance(pem, bytes)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

def test_get_fingerprint():
    sec = SecurityManager()
    pem = sec.generate_rsa_keys()

    fp1 = sec.get_fingerprint(pem)
    fp2 = sec.get_fingerprint(pem)

    assert isinstance(fp1, str)
    assert len(fp1) == 16
    assert fp1 == fp2

def test_session_key_encryption_decryption():
    sec1 = SecurityManager()
    pem1 = sec1.generate_rsa_keys()

    sec2 = SecurityManager()
    session_key = sec2.create_session_key()

    enc_key = sec2.encrypt_session_key(pem1, session_key)

    assert isinstance(enc_key, bytes)
    assert enc_key != session_key

    # Decrypt
    assert sec1.decrypt_session_key(enc_key) == True

    # Check that they can now communicate
    sec2.set_session_key(session_key)

    msg = b"Hello, World!"
    enc_msg = sec2.encrypt(msg)

    assert enc_msg != msg
    assert sec1.decrypt(enc_msg) == msg

def test_encrypt_decrypt_no_session():
    sec = SecurityManager()

    with pytest.raises(ValueError):
        sec.encrypt(b"test")

    with pytest.raises(ValueError):
        sec.decrypt(b"test")
