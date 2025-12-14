# Cryptography

## Vivian Potts (100578802) & Sophia Wu (100578325)

## Code sharing option

[Indicate whether you’ll share the code via the Google folder or through a GitHub repository. In the last case, specify here the url of the repository and make sure you grant access to the GitHub user linked to email aigonzal@inf.uc3m.es. ]
High-level description of the app
This app is a command-line application demonstrating how cryptographic mechanisms such as hashing, authenticated key storage, PKI, certificate signing, and digital signatures can be integrated into a simple workflow. This simulates a scenario where users must authenticate themselves and produce verifiable cryptographic signatures.
Technical description
User -> System:
- Register/Login
- Create CSR
- Request certificate
- Create petition
- Sign petition
System -> User:
- Confirms authentication
- Issues certificates
- Confirms signature validity
Stored Data:
users.json: password hashes, salts, encrypted private keys, public kets, certificates
petitions.json: petition titles and text
signatures/: signature files for each petition
All private keys are encrypted using AES-GCM, and passwords are stored only as salted hashes.
Modules
main.py: Controls the menu and flow of the application. Routes the user's choices to teh correct module.
user_management.py: Handles user registration, login, RSA key generation, private key encryption/decryption, and CSR Creation.
pki_utils.py: Implements thte CA. Sings user CSRs to produce certificates and verifies certificates.
petition_manager.py: Creates petitions, signs petitions user the user's private key, and verifies petition signatures using the certificate's public key. 
crypto_utils.py: Provides low-level cryptographic helpers such as password hashing, AES-GCM encryption, and JSON load/save functions.

## Main functionalities

This application implements a secure petition-signing system that allows users to:
- Register with a password
- Generate RSA key pairs
- Produce a CSR 
- Obtain an X.509 certificate signed by a local CA
- Create petitions
- Digitally sign petitions
- Verify signatures
The primary purpose is to authenticate users and validate petition signatures using digital signatures and certificates. This prevents fraudulent signatures and ensure the integrity of signed petitions.

User Types
- Regular users: register, obtain keys/certificates, create petitions, sign petitions
- Certificate Authority - includes a mini PKI, so the CA is an internal role handled by scripts in /ca

Main Data Flows
User -> System:
- Registration
- CSR generation
- Signing petitions
System -> User:
- Confirmation of authentication
- Issued certificates
- Signature verification results

## Byte-like/text-like data encoding/decoding

The application frequently converts between bytes and text formats because cryptographic material (keys, certs, signatures) is inherently byte-based.

How Encoding/Decoding Is Handled
- Base64 encoding/decoding — used to store binary data (salts, password hashes, AES enctypted blobs) inside JSON
- PEM encoding — used to serialize RSA keys and X.509 certificates
- UTF-8 text encoding — used for petition content and JSON structures

Where Transformations Occur
- During password hashing (salt + PBKDF2 outputs)
- When storing encrypted private keys (AES-GCM output converted to Base64)
- When loading PEM certificates
- When creating signature files (raw bytes written to file)

## User authentication

User authentication consists of:

1. Registration
- User provides username + password
- System generates a random salt
- Uses PBKDF2 (SHA-256) to derive a password hash
Saves:
    - salt
    - pwd_hash
    - RSA public key
    - AES-GCM encrypted private key
    - certificate (initially None)
- Stored in JSON for easy retrieval

2. Login
- User enters credentials
- Application recomputes PBKDF2 hash
- Compares against stored hash
- Grants access upon match

## Data encryption and authentication

What Is Encrypted:
- Private keys are encrypted before being stored.
- Nothing else in the app requires symmetric encryption except protecting the user’s private RSA key.

Algorithm
- AES-GCM
- Key is derived from user's password hash
- Produces (nonce, ciphertext, tag) stored in JSON

Why AES-GCM?
- Provides confidentiality + integrity
- Widely adopted and secure
- Easy to store and recover due to AEAD construction

## Symmetric key management

Keys Used
- AES-GCM keys for encrypting private keys
- PBKDF2 password-derived keys for authentication and key wrapping

How Keys Are Created
- Salt generated via os.urandom()
- PBKDF2-HMAC-SHA256 derives:
    - stored password hash
    - AES key for encrypting private RSA key

Who Creates and Uses Keys
- Keys are created locally on the user's machine during registration
- Only the user can unlock their private key (by entering the password)

Storage
- AES-GCM encrypted blobs stored in users.json
- Raw AES keys are never stored

## Asymmetric key management

Every registered user automatically receives an RSA key pair.

When & How Keys Are Generated
- During registration
Using:

rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

Usage
- Private key: sign petitions
- Public key: included in CSR → certificate → used to verify signatures

## Loading and serializing asymmetric keys/public key certificates

Loading Keys
- Private keys decrypted from AES-GCM
- Public keys loaded from stored PEM strings
- Certificates loaded via x509.load_pem_x509_certificate()

Serialization
- Stored in PEM format
- Certificates in readable Base64-encoded PEM blocks
- Signatures stored as raw binary (.sig files)

This allows portability and compatibility with common crypto tools (OpenSSL, browsers, etc.).

## Digital signatures

What Is Signed
- The petition text
- Signed by the user’s RSA private key

Process
- Load petition text
- Decrypt private key
- Sign using:
RSA + PSS padding + SHA-256
- Save signature to /data/signatures/username_petition.sig

Verification
- System loads signer’s certificate
- Extracts public key
- Verifies signature using same PSS+SHA256 scheme
- Only valid if:
    - Certificate was issued by the CA
    - Certificate signature is authentic
    - Digital signature matches petition text

This ensures integrity, authorship, and non-repudiation.

## Asymmetric encryption / hybrid encryption 

This app does not use asymmetric encryption for confidentiality, only for authentication (digital signatures).
The only encrypted data is the user’s private key encrypted symmetrically.

## Public key certificates and mini-PKI

Certificate Type
- X.509 certificates
- Issued by a local Certificate Authority included in /ca

Mini-PKI Workflow
- User generates CSR
- CSR is sent to CA script
- CA signs certificate using:
    - Its private key (ac1.key.pem)
    - Its certificate (ac1.cert.pem)
- Certificate stored in users.json and in /data

CA Files
- Stored in /ca:
    - ac1.key.pem — CA private key (protected in real systems)
    - ac1.cert.pem — CA certificate
    - serial, index.txt, openssl.cnf — maintain CA state

Users trust the CA implicitly, forming a single-tier trust hierarchy.

## Other aspects

App runs in terminal menu interface
JSON-based storage for transparency

## Conclusions

Through this project, we learned how real cryptographic systems operate end-to-end — from password hashing to PKI issuance and digital signatures. The biggest challenges were:
- Ensuring correct private key encryption/decryption
- Proper certificate signing and verification
- Debugging serialization/byte-encoding issues
- Getting the mini-PKI to work consistently

We enjoyed seeing the entire workflow function correctly: users register, generate keys, get certified, sign a petition, and verify signatures — mirroring real-world digital identity systems. Building this app deepened our understanding of:
- Public Key Infrastructure (PKI)
- Digital signatures
- RSA key management

Overall, the project significantly improved our practical understanding of cryptography and secure system design.