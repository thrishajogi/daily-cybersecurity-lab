from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import hmac
import base64
import json
import time

app = Flask(__name__)
CORS(app)

# =========================
# CONFIGURATION
# =========================
SECRET_KEY = b"super_secret_key_change_this"
MAX_ATTEMPTS = 3
LOCK_TIME = 30

# =========================
# SIMULATED DATABASE
# =========================
users_db = {
    "1": {
        "username": "admin",
        "password_hash": hashlib.sha256("admin@123".encode()).hexdigest(),
        "role": "admin"
    },
    "2": {
        "username": "normal_user",
        "password_hash": hashlib.sha256("user@123".encode()).hexdigest(),
        "role": "user"
    }
}

# =========================
# RUNTIME STATE
# =========================
failed_attempts = {}
alerts = []

# =========================
# UTILITIES
# =========================
def log_event(event):
    with open("security_log.json", "a") as f:
        f.write(json.dumps(event) + "\n")


def generate_token(username, role):
    payload = {
        "user": username,
        "role": role,
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


# =========================
# AUTHENTICATION
# =========================
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

    # IP lock check
    if current_time < failed_attempts[ip]["lock_until"]:
        return jsonify({"message": "IP temporarily blocked 🔒"}), 403

    for user_id, user_data in users_db.items():
        if user_data["username"] == username:
            hashed_input = hashlib.sha256(password.encode()).hexdigest()

            if hashed_input == user_data["password_hash"]:
                failed_attempts[ip]["count"] = 0

                token = generate_token(username, user_data["role"])

                log_event({
                    "type": "successful_login",
                    "ip": ip,
                    "user": username,
                    "timestamp": current_time
                })

                return jsonify({
                    "message": "Login successful ✅",
                    "token": token
                })

    # Failed login
    failed_attempts[ip]["count"] += 1

    log_event({
        "type": "failed_login",
        "ip": ip,
        "attempted_user": username,
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


# =========================
# TOKEN VERIFICATION
# =========================
@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid:
        return jsonify({
            "message": "Token valid ✅",
            "user": payload["user"],
            "role": payload["role"]
        })
    else:
        return jsonify({
            "message": "Token tampered ❌"
        }), 403


# =========================
# SECURE PROFILE (RBAC FIXED)
# =========================
@app.route("/profile/<user_id>", methods=["POST"])
def secure_profile(user_id):
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if not valid:
        return jsonify({"message": "Invalid token"}), 403

    target_user = users_db.get(user_id)

    if not target_user:
        return jsonify({"message": "User not found"}), 404

    # Authorization logic
    if payload["role"] == "admin":
        return jsonify(target_user)

    if payload["user"] != target_user["username"]:
        log_event({
            "type": "unauthorized_access_attempt",
            "attacker": payload["user"],
            "target_user_id": user_id,
            "timestamp": time.time()
        })

        return jsonify({"message": "Access denied 🚫"}), 403

    return jsonify(target_user)


# =========================
# ALERTS MONITORING
# =========================
@app.route("/alerts", methods=["GET"])
def view_alerts():
    return jsonify(alerts)


# =========================
# SERVER START
# =========================
if __name__ == "__main__":
    app.run(debug=True)