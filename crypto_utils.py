'''Module for cryptographic utilities including password hashing and AES-GCM encryption/decryption'''

import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Importing necessary libraries for cryptographic operations, JSON handling, and file management.

# PASSWORD HASHING

# Function to hash a password using PBKDF2-HMAC-SHA256.


def hash_password(password: str, salt: bytes = None):
    """
    PBKDF2-HMAC-SHA256 hashing for user passwords.
    Returns (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt if none is provided.

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA256 as the hashing algorithm.
        iterations=200000,  # Number of iterations for the key derivation.
        length=32,  # Length of the derived key in bytes.
        salt=salt,  # Salt used for key derivation.
    )

    key = kdf.derive(password.encode())  # Derive the key from the password.
    return key, salt

# Function to deterministically derive a key using PBKDF2 and a given salt.
# This is typically used for decrypting data where the salt is already known.


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

# Function to verify a password by comparing the stored hash with the derived hash.
# Returns True if the password matches, False otherwise.


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
        kdf.verify(provided_password.encode(), stored_hash)  # Verify the provided password.
        return True
    except Exception:
        return False

# AES-GCM AUTHENTICATED ENCRYPTION

# Function to encrypt plaintext using AES-GCM.
# Returns a dictionary containing the nonce and the ciphertext, both base64-encoded.


def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    '''Encrypt plaintext using AES-GCM.'''
    aesgcm = AESGCM(key)  # Initialize AES-GCM with the provided key.
    nonce = os.urandom(12)  # Generate a random 12-byte nonce.
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # Encrypt the plaintext.

    return {
        "nonce": base64.b64encode(nonce).decode(),  # Encode the nonce in base64.
        "ciphertext": base64.b64encode(ciphertext).decode()  # Encode the ciphertext in base64.
    }

# Function to decrypt ciphertext using AES-GCM.
# Takes a dictionary containing the base64-encoded nonce and ciphertext.


def decrypt_aes_gcm(key: bytes, enc_dict: dict):
    '''Decrypt ciphertext using AES-GCM.'''
    aesgcm = AESGCM(key)  # Initialize AES-GCM with the provided key.
    nonce = base64.b64decode(enc_dict["nonce"])  # Decode the nonce from base64.
    ciphertext = base64.b64decode(enc_dict["ciphertext"])  # Decode the ciphertext from base64.
    return aesgcm.decrypt(nonce, ciphertext, None)  # Decrypt and return the plaintext.

# JSON HELPERS

# Function to load JSON data from a file.
# Returns an empty dictionary if the file does not exist.


def load_json(path):
    '''Load data from a JSON file'''
    if not os.path.exists(path):  # Check if the file exists.
        return {}
    with open(path, "r") as f:
        return json.load(f)  # Load and return the JSON data.

# Function to save data as JSON to a file.
# Pretty-prints the JSON with an indentation of 4 spaces.


def save_json(path, data):
    '''Save data to a JSON file'''
    with open(path, "w") as f:
        json.dump(data, f, indent=4)  # Save the data as JSON with pretty formatting.
