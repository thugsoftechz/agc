import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class SecurityManager:
    def __init__(self):
        self.fernet = None
        self.rsa_private = None
        self.rsa_public = None

    def generate_rsa_keys(self):
        logging.info("Generating RSA keys...")
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_public = self.rsa_private.public_key()
        return self.rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_fingerprint(self, pem_bytes):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pem_bytes)
        return digest.finalize().hex()[:16].upper()

    def decrypt_session_key(self, encrypted_key):
        try:
            session_key = self.rsa_private.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.fernet = Fernet(session_key)
            return True
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            return False

    def create_session_key(self):
        return Fernet.generate_key()

    def encrypt_session_key(self, public_pem, session_key):
        public_key = serialization.load_pem_public_key(public_pem)
        return public_key.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def set_session_key(self, key):
        self.fernet = Fernet(key)

    def encrypt(self, message: bytes) -> bytes:
        if self.fernet:
            return self.fernet.encrypt(message)
        raise ValueError("Session not established")

    def decrypt(self, token: bytes) -> bytes:
        if self.fernet:
            return self.fernet.decrypt(token)
        raise ValueError("Session not established")
