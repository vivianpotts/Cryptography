import os
import json
import base64
from crypto_utils import (
    hash_password,
    verify_password,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    derive_key,
    load_json,
    save_json,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

DATA_FILE = "data/users.json"


# ------- LOAD / SAVE USERS ------- #

def load_users():
    return load_json(DATA_FILE)


def save_users(data):
    save_json(DATA_FILE, data)


# ------- USER REGISTRATION ------- #

def register_user(username, password):
    users = load_users()

    if username in users:
        return False, "User already exists."

    # Hash password → produces (derived_key, salt)
    pwd_hash, salt = hash_password(password)

    # Generate RSA keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize public key (stored plaintext)
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Encrypt private key using AES-GCM with pwd_hash
    private_key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    enc_priv = encrypt_aes_gcm(pwd_hash, private_key_bytes)

    # Store user entry
    users[username] = {
        "salt": base64.b64encode(salt).decode(),
        "pwd_hash": base64.b64encode(pwd_hash).decode(),
        "public_key": public_bytes,
        "encrypted_private_key": enc_priv,
        "certificate": None
    }

    save_users(users)
    return True, "User registered successfully."


# ------- USER LOGIN ------- #

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User not found."

    salt = base64.b64decode(users[username]["salt"])
    stored_hash = base64.b64decode(users[username]["pwd_hash"])

    if verify_password(stored_hash, password, salt):
        return True, "Login successful."

    return False, "Incorrect password."


# ------- LOAD USER PRIVATE KEY ------- #

def load_user_private_key(username, password):
    """
    Correct version:
    Uses *derive_key()* to recreate the PBKDF2 key using the stored salt.
    This matches the encryption key used during registration.
    """
    users = load_users()

    salt = base64.b64decode(users[username]["salt"])
    pwd_hash = derive_key(password, salt)

    enc = users[username]["encrypted_private_key"]
    key_pem = decrypt_aes_gcm(pwd_hash, enc)

    return serialization.load_pem_private_key(key_pem, password=None)


# ------- CREATE CSR ------- #

def generate_csr(username, password):
    users = load_users()
    private_key = load_user_private_key(username, password)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]))
        .sign(private_key, hashes.SHA256())
    )

    csr_path = f"data/{username}.csr.pem"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr_path
