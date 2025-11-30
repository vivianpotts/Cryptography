import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------- PASSWORD HASHING -------- #

def hash_password(password: str, salt: bytes = None):
    """
    PBKDF2-HMAC-SHA256 hashing for user passwords.
    Returns (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=200000,
        length=32,
        salt=salt,
    )

    key = kdf.derive(password.encode())
    return key, salt


def derive_key(password: str, salt: bytes):
    """
    Deterministically derive a PBKDF2 key using the stored salt.
    Used when decrypting the private key at login.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=200000,
        length=32,
        salt=salt,
    )
    return kdf.derive(password.encode())


def verify_password(stored_hash: bytes, provided_password: str, salt: bytes):
    """
    Verifies password by attempting PBKDF2 derivation and comparing.
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=200000,
            length=32,
            salt=salt,
        )
        kdf.verify(provided_password.encode(), stored_hash)
        return True
    except Exception:
        return False


# -------- AES-GCM AUTHENTICATED ENCRYPTION -------- #

def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_aes_gcm(key: bytes, enc_dict: dict):
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)


# -------- JSON HELPERS -------- #

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
