from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib

app = Flask(__name__)
CORS(app)  # 👈 THIS FIXES YOUR ERROR

stored_username = "admin"
stored_password_hash = hashlib.sha256("admin@123".encode()).hexdigest()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    hashed_input = hashlib.sha256(password.encode()).hexdigest()

    if username == stored_username and hashed_input == stored_password_hash:
        return jsonify({"message": "Login successful ✅"})
    else:
        return jsonify({"message": "Invalid credentials ❌"}), 401

if __name__ == "__main__":
    app.run(debug=True)