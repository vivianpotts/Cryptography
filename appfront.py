from flask import Flask, request, jsonify  # Import Flask for creating the web app and handling requests
from flask_cors import CORS  # Import CORS to allow cross-origin requests (e.g., from a frontend app)
from cryptography.hazmat.primitives.asymmetric import padding  # Import padding for cryptographic operations
from cryptography.hazmat.primitives import hashes, serialization  # Import hashing and serialization utilities
from cryptography import x509  # Import x509 for loading certificates
import base64  # Import base64 for encoding/decoding binary data
import os  # Import os for checking file existence

# Initialize the Flask application
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing (CORS) to allow communication with frontend apps

# In-memory user database (for demonstration purposes, not suitable for production)
users = {}

# Paths to the private key and public certificate
PRIVATE_KEY_PATH = "app.key"
PUBLIC_CERT_PATH = "app.crt"

# Check if the private key and public certificate exist
if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_CERT_PATH):
    raise FileNotFoundError(
        f"Missing required files: '{PRIVATE_KEY_PATH}' or '{PUBLIC_CERT_PATH}'. "
        "Please generate them using OpenSSL."
    )

# Load the private key for signing operations
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),  # Read the private key from the file
        password=None,  # No password is used to encrypt the private key
    )

# Load the public key from the certificate
with open(PUBLIC_CERT_PATH, "rb") as cert_file:
    certificate = x509.load_pem_x509_certificate(cert_file.read())  # Load the certificate
    public_key = certificate.public_key()  # Extract the public key from the certificate


# Route to register a new user
@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user by storing their username and password in the in-memory database.
    """
    data = request.get_json()  # Parse the JSON payload from the request
    username = data["username"]  # Extract the username
    password = data["password"]  # Extract the password

    # Check if the username already exists in the database
    if username in users:
        return jsonify({"message": "❌ User already exists"})  # Return an error message if the user exists

    # Add the new user to the database
    users[username] = password
    return jsonify({"message": f"✅ User '{username}' registered successfully!"})  # Return a success message


# Route to log in a user
@app.route("/login", methods=["POST"])
def login():
    """
    Log in a user by verifying their username and password.
    """
    data = request.get_json()  # Parse the JSON payload from the request
    username = data["username"]  # Extract the username
    password = data["password"]  # Extract the password

    # Check if the username exists and the password matches
    if username in users and users[username] == password:
        return jsonify({"message": f"✅ Welcome back, {username}!"})  # Return a success message

    # Return an error message if the credentials are invalid
    return jsonify({"message": "❌ Invalid username or password"})


# Route to sign data using the private key
@app.route("/sign", methods=["POST"])
def sign_data():
    """
    Sign a message using the private key and return the signature.
    """
    data = request.get_json()  # Parse the JSON payload from the request
    message = data["message"].encode()  # Extract and encode the message as bytes

    # Sign the message using the private key and PSS padding
    signature = private_key.sign(
        message,  # The message to sign
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function using SHA-256
            salt_length=padding.PSS.MAX_LENGTH,  # Maximum salt length for PSS
        ),
        hashes.SHA256(),  # Hashing algorithm (SHA-256)
    )

    # Return the signature as a base64-encoded string
    return jsonify({"signature": base64.b64encode(signature).decode()})


# Route to verify a signature using the public key
@app.route("/verify", methods=["POST"])
def verify_signature():
    """
    Verify a signature using the public key and return whether it is valid.
    """
    data = request.get_json()  # Parse the JSON payload from the request
    message = data["message"].encode()  # Extract and encode the message as bytes
    signature = base64.b64decode(data["signature"])  # Decode the base64-encoded signature

    try:
        # Verify the signature using the public key and PSS padding
        public_key.verify(
            signature,  # The signature to verify
            message,  # The original message
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function using SHA-256
                salt_length=padding.PSS.MAX_LENGTH,  # Maximum salt length for PSS
            ),
            hashes.SHA256(),  # Hashing algorithm (SHA-256)
        )
        # Return a success message if the signature is valid
        return jsonify({"message": "✅ Signature is valid"})
    except Exception as e:
        # Return an error message if the signature is invalid
        return jsonify({"message": "❌ Signature is invalid", "error": str(e)})


# Run the Flask application
if __name__ == "__main__":
    app.run(debug=True)  # Enable debug mode for development
