from flask import Flask, request, jsonify
from flask_cors import CORS  # allow the HTML to talk to Flask

app = Flask(__name__)
CORS(app)

# In-memory user database
users = {}

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    if username in users:
        return jsonify({"message": "❌ User already exists"})
    users[username] = password
    return jsonify({"message": f"✅ User '{username}' registered successfully!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    if username in users and users[username] == password:
        return jsonify({"message": f"✅ Welcome back, {username}!"})
    return jsonify({"message": "❌ Invalid username or password"})

if __name__ == "__main__":
    app.run(debug=True)
