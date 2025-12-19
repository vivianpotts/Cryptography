'''Utility functions for Public Key Infrastructure (PKI) operations'''

import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta
from user_management import load_users, save_users

CA_KEY = "ca/ac1.key.pem"  # Path to the private key of the CA
CA_CERT = "ca/ac1.cert.pem"  # Path to the certificate of the CA
CA_PASSWORD = "password"  # Password for the CA's private key (set to None if not password-protected)


# LOAD CA MATERIAL

def load_ca():
    '''Load the CA's private key from the specified file'''

    # The private key is used to sign certificates
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=CA_PASSWORD)
    # Load the CA's certificate from the specified file
    # The certificate contains the CA's public key and identity information
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    # Return both the private key and certificate
    return ca_key, ca_cert


# SIGN CSR TO ISSUE CERTIFICATE

def sign_user_csr(username, csr_path):
    '''Sign a user's CSR to issue a certificate'''
    # Load the CA's private key and certificate
    ca_key, ca_cert = load_ca()

    # Load the Certificate Signing Request (CSR) from the specified path
    # The CSR contains the user's public key and identity information
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    
    # Build and sign a new certificate using the CSR and the CA's private key
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)  # Set the subject name from the CSR
        .issuer_name(ca_cert.subject)  # Set the issuer name from the CA's certificate
        .public_key(csr.public_key()) 
        .serial_number(x509.random_serial_number())  # Generate a random serial number
        .not_valid_before(datetime.utcnow())  # Set the certificate's start validity period
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Set the certificate's end validity period (1 year)
        .sign(ca_key, hashes.SHA256())  # Sign the certificate with the CA's private key using SHA256
    )

    # Save the signed certificate to a file
    cert_path = f"data/{username}.cert.pem"
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    with open(cert_path, "wb") as f:
        f.write(pem_bytes)  # Write the certificate in PEM format
        f.flush()  # Ensure all data is written to disk
        os.fsync(f.fileno())  # Synchronize the file's in-core state with storage device

    # store cert in users.json
    users = load_users()  # Load existing user data
    users[username]["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()  # Store the certificate as a string
    save_users(users)  # Save updated user data

    # Return the path to the saved certificate
    return cert_path


# VERIFY CERTIFICATE

def verify_user_certificate(username):
    '''Verify a user's certificate using the CA's public key'''
    # Load the users data from the users.json file
    users = load_users()
    # Retrieve the user's certificate
    user_cert_pem = users[username]["certificate"]

    # Check if the user has a certificate
    if user_cert_pem is None:
        return False, "User has no certificate."

    # Load the user's certificate from the stored PEM data
    user_cert = x509.load_pem_x509_certificate(user_cert_pem.encode())
    _, ca_cert = load_ca()  # Load the CA's certificate

    # verify signature of the user's certificate using the CA's public key
    try:
        ca_cert.public_key().verify(
            user_cert.signature,  # The signature to verify
            user_cert.tbs_certificate_bytes,  # The data that was signed
            padding.PKCS1v15(),  # The padding scheme used for the signature
            user_cert.signature_hash_algorithm,  # The hash algorithm used for the signature
        )
        return True, "Certificate valid."  # Return success if verification passes
    except Exception:  # Catch specific exception for invalid signature
        return False, "Certificate signature invalid."  # Return failure if verification fails
