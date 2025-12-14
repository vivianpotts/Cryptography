'''Module for managing petitions and digital signatures'''

import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from user_management import load_users, load_user_private_key
from pki_utils import verify_user_certificate
from crypto_utils import load_json, save_json
from cryptography import x509

# Constants for file paths
PETITIONS_FILE = "data/petitions.json"
SIGNATURES_DIR = "data/signatures"


def load_petitions():
    '''Load petitions from the JSON file'''
    return load_json(PETITIONS_FILE)


def save_petitions(data):
    '''Save petitions to the JSON file'''
    save_json(PETITIONS_FILE, data)


def create_petition(title, text):
    '''Create a new petition with the given title and text'''
    petitions = load_petitions()

    # Check if the petition title already exists
    if title in petitions:
        return False, "Petition already exists."

    # Add the new petition to the dictionary
    petitions[title] = {
        "text": text,
        "signatures": []
    }

    # Save the updated petitions to the file
    save_petitions(petitions)
    return True, "Petition created."


def sign_petition(username, password, title):
    '''Sign a petition with the user's private key'''
    petitions = load_petitions()
    
    # Check if the petition exists
    if title not in petitions:
        return False, "Petition not found."

    # Validate the user's certificate
    valid, msg = verify_user_certificate(username)
    if not valid:
        return False, "Certificate invalid."

    # Load the user's private key using their credentials
    private_key = load_user_private_key(username, password)

    # Prepare the petition text for signing
    message = petitions[title]["text"].encode()

    # Generate the digital signature using the private key
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Save the signature to a file
    sig_path = f"{SIGNATURES_DIR}/{username}_{title}.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    # Add the username to the list of signatures for the petition
    petitions[title]["signatures"].append(username)
    save_petitions(petitions)

    return True, "Signature applied."


def verify_signature(username, title):
    '''Verify a user's signature on a petition'''
    users = load_users()
    petitions = load_petitions()

    # Check if the petition exists
    if title not in petitions:
        return False, "Petition not found."

    # Check if the user has signed the petition
    if username not in petitions[title]["signatures"]:
        return False, "User has not signed petition."

    # Load the user's signature from the file
    sig_path = f"{SIGNATURES_DIR}/{username}_{title}.sig"
    with open(sig_path, "rb") as f:
        signature = f.read()

    # Prepare the petition text for verification
    message = petitions[title]["text"].encode()

    # Load the user's public key from their certificate
    cert_pem = users[username]["certificate"]
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pubkey = cert.public_key()

    try:
        # Verify the signature using the public key
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
