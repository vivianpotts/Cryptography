import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta
from user_management import load_users, save_users

CA_KEY = "ca/ac1.key.pem"
CA_CERT = "ca/ac1.cert.pem"


#LOAD CA MATERIAL

def load_ca():
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


#SIGN CSR TO ISSUE CERTIFICATE

def sign_user_csr(username, csr_path):
    ca_key, ca_cert = load_ca()

    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = f"data/{username}.cert.pem"
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    with open(cert_path, "wb") as f:
        f.write(pem_bytes)
        f.flush()
        os.fsync(f.fileno())


    # store cert in users.json
    users = load_users()
    users[username]["certificate"] = cert.public_bytes(serialization.Encoding.PEM).decode()
    save_users(users)

    return cert_path


#VERIFY CERTIFICATE

def verify_user_certificate(username):
    users = load_users()
    user_cert_pem = users[username]["certificate"]

    if user_cert_pem is None:
        return False, "User has no certificate."

    user_cert = x509.load_pem_x509_certificate(user_cert_pem.encode())
    _, ca_cert = load_ca()

    # verify signature
    try:
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,
        )
        return True, "Certificate valid."
    except Exception:
        return False, "Certificate signature invalid."
