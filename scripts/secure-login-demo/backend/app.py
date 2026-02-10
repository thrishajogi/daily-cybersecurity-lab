from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import time

app = Flask(__name__)
CORS(app)

stored_username = "admin"
stored_password_hash = hashlib.sha256("admin@123".encode()).hexdigest()

MAX_ATTEMPTS = 3
LOCK_TIME = 30  # seconds

failed_attempts = 0
lock_until = 0

@app.route("/login", methods=["POST"])
def login():
    global failed_attempts, lock_until

    if time.time() < lock_until:
        return jsonify({"message": "Account locked. Try later 🔒"}), 403

    data = request.json
    username = data.get("username")
    password = data.get("password")

    hashed_input = hashlib.sha256(password.encode()).hexdigest()

    if username == stored_username and hashed_input == stored_password_hash:
        failed_attempts = 0
        return jsonify({"message": "Login successful ✅"})
    else:
        failed_attempts += 1

        if failed_attempts >= MAX_ATTEMPTS:
            lock_until = time.time() + LOCK_TIME
            failed_attempts = 0
            return jsonify({"message": "Too many attempts. Account locked 🔒"}), 403

        return jsonify({"message": "Invalid credentials ❌"}), 401

if __name__ == "__main__":
    app.run(debug=True)