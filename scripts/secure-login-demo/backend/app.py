from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import hmac
import base64
import json
import time

app = Flask(__name__)
CORS(app)

# ==============================
# Configuration
# ==============================
SECRET_KEY = b"super_secret_key_change_this"
MAX_ATTEMPTS = 3
LOCK_TIME = 30

# Simulated database
stored_username = "admin"
stored_password_hash = hashlib.sha256("admin@123".encode()).hexdigest()

# State tracking
failed_attempts = {}
alerts = []

# ==============================
# Utility Functions
# ==============================

def log_event(event):
    with open("security_log.json", "a") as f:
        f.write(json.dumps(event) + "\n")


def generate_token(username):
    payload = {
        "user": username,
        "timestamp": time.time()
    }

    payload_str = json.dumps(payload)

    signature = hmac.new(
        SECRET_KEY,
        payload_str.encode(),
        hashlib.sha256
    ).hexdigest()

    token_data = f"{payload_str}.{signature}"

    return base64.b64encode(token_data.encode()).decode()


def verify_token(token):
    try:
        decoded = base64.b64decode(token).decode()
        payload_str, received_signature = decoded.rsplit(".", 1)

        expected_signature = hmac.new(
            SECRET_KEY,
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(received_signature, expected_signature):
            return True, json.loads(payload_str)
        else:
            return False, None
    except Exception:
        return False, None


# ==============================
# Routes
# ==============================

@app.route("/login", methods=["POST"])
def login():
    global failed_attempts

    ip = request.remote_addr
    data = request.json
    username = data.get("username")
    password = data.get("password")

    current_time = time.time()

    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 0, "lock_until": 0}

    # IP Lock Check
    if current_time < failed_attempts[ip]["lock_until"]:
        return jsonify({"message": "IP temporarily blocked 🔒"}), 403

    hashed_input = hashlib.sha256(password.encode()).hexdigest()

    if username == stored_username and hashed_input == stored_password_hash:

        failed_attempts[ip]["count"] = 0

        token = generate_token(username)

        log_event({
            "type": "successful_login",
            "ip": ip,
            "timestamp": current_time
        })

        return jsonify({
            "message": "Login successful ✅",
            "token": token
        })

    else:
        failed_attempts[ip]["count"] += 1

        log_event({
            "type": "failed_login",
            "ip": ip,
            "timestamp": current_time
        })

        if failed_attempts[ip]["count"] >= MAX_ATTEMPTS:
            failed_attempts[ip]["lock_until"] = current_time + LOCK_TIME
            failed_attempts[ip]["count"] = 0

            alert = {
                "type": "brute_force_detected",
                "ip": ip,
                "timestamp": current_time
            }

            alerts.append(alert)
            log_event(alert)

            return jsonify({"message": "Too many attempts. IP blocked 🔒"}), 403

        return jsonify({"message": "Invalid credentials ❌"}), 401


@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid:
        return jsonify({
            "message": "Token valid ✅",
            "user": payload["user"]
        })
    else:
        return jsonify({
            "message": "Token tampered ❌"
        }), 403


@app.route("/alerts", methods=["GET"])
def view_alerts():
    return jsonify(alerts)


# ==============================
# Run Server
# ==============================

if __name__ == "__main__":
    app.run(debug=True)