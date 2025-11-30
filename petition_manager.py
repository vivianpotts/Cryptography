import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from user_management import load_users, load_user_private_key
from pki_utils import verify_user_certificate
from crypto_utils import load_json, save_json
from cryptography import x509


PETITIONS_FILE = "data/petitions.json"
SIGNATURES_DIR = "data/signatures"


def load_petitions():
    return load_json(PETITIONS_FILE)


def save_petitions(data):
    save_json(PETITIONS_FILE, data)


# -------- CREATE PETITION -------- #

def create_petition(title, text):
    petitions = load_petitions()

    if title in petitions:
        return False, "Petition already exists."

    petitions[title] = {
        "text": text,
        "signatures": []
    }

    save_petitions(petitions)
    return True, "Petition created."


# -------- SIGN PETITION -------- #

def sign_petition(username, password, title):
    petitions = load_petitions()
    if title not in petitions:
        return False, "Petition not found."

    # certificate validation
    valid, msg = verify_user_certificate(username)
    if not valid:
        return False, "Certificate invalid."

    # load key
    private_key = load_user_private_key(username, password)

    message = petitions[title]["text"].encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # save signature
    sig_path = f"{SIGNATURES_DIR}/{username}_{title}.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    petitions[title]["signatures"].append(username)
    save_petitions(petitions)

    return True, "Signature applied."


# -------- VERIFY PETITION SIGNATURE FOR A USER -------- #

def verify_signature(username, title):
    users = load_users()
    petitions = load_petitions()

    if title not in petitions:
        return False, "Petition not found."

    if username not in petitions[title]["signatures"]:
        return False, "User has not signed petition."

    # load signature
    sig_path = f"{SIGNATURES_DIR}/{username}_{title}.sig"
    with open(sig_path, "rb") as f:
        signature = f.read()

    message = petitions[title]["text"].encode()

    # load public key from cert
    cert_pem = users[username]["certificate"]
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pubkey = cert.public_key()

    try:
        pubkey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True, "Signature is valid."
    except Exception:
        return False, "Signature invalid."
