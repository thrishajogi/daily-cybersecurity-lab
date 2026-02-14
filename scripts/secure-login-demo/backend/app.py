from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import hmac
import base64
import json
import time
import secrets

app = Flask(__name__)
CORS(app)

# =========================
# CONFIG
# =========================
SECRET_KEY = b"ultra_secret_key_rotate_me"
ACCESS_TOKEN_TTL = 30         # seconds
REFRESH_TOKEN_TTL = 300       # seconds

# =========================
# DATABASE
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
# SESSION STORE
# =========================
refresh_store = {}  # refresh_token → {username, expiry}

alerts = []

# =========================
# UTILITIES
# =========================
def log_event(event):
    with open("security_log.json", "a") as f:
        f.write(json.dumps(event) + "\n")


def sign_payload(payload):
    payload_str = json.dumps(payload)
    signature = hmac.new(
        SECRET_KEY,
        payload_str.encode(),
        hashlib.sha256
    ).hexdigest()

    token_data = f"{payload_str}.{signature}"
    return base64.b64encode(token_data.encode()).decode()


def verify_signed_token(token):
    try:
        decoded = base64.b64decode(token).decode()
        payload_str, received_signature = decoded.rsplit(".", 1)

        expected_signature = hmac.new(
            SECRET_KEY,
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(received_signature, expected_signature):
            return False, None

        payload = json.loads(payload_str)

        if payload["exp"] < time.time():
            return False, "expired"

        return True, payload

    except Exception:
        return False, None


# =========================
# LOGIN (ISSUES ACCESS + REFRESH)
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    for user_id, user_data in users_db.items():
        if user_data["username"] == username:
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            if hashed_input == user_data["password_hash"]:

                now = time.time()

                access_payload = {
                    "user": username,
                    "role": user_data["role"],
                    "exp": now + ACCESS_TOKEN_TTL
                }

                access_token = sign_payload(access_payload)

                refresh_token = secrets.token_hex(32)

                refresh_store[refresh_token] = {
                    "username": username,
                    "expiry": now + REFRESH_TOKEN_TTL
                }

                log_event({
                    "type": "login",
                    "user": username,
                    "timestamp": now
                })

                return jsonify({
                    "access_token": access_token,
                    "refresh_token": refresh_token
                })

    return jsonify({"message": "Invalid credentials"}), 401


# =========================
# REFRESH TOKEN ROTATION
# =========================
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    old_refresh = data.get("refresh_token")

    entry = refresh_store.get(old_refresh)

    if not entry:
        alerts.append({
            "type": "refresh_replay_detected",
            "timestamp": time.time()
        })
        return jsonify({"message": "Invalid refresh token"}), 403

    if entry["expiry"] < time.time():
        del refresh_store[old_refresh]
        return jsonify({"message": "Refresh expired"}), 403

    # ROTATION (CRITICAL)
    username = entry["username"]
    del refresh_store[old_refresh]

    new_refresh = secrets.token_hex(32)

    refresh_store[new_refresh] = {
        "username": username,
        "expiry": time.time() + REFRESH_TOKEN_TTL
    }

    new_access_payload = {
        "user": username,
        "role": users_db["1"]["role"] if username == "admin" else "user",
        "exp": time.time() + ACCESS_TOKEN_TTL
    }

    new_access = sign_payload(new_access_payload)

    return jsonify({
        "access_token": new_access,
        "refresh_token": new_refresh
    })


# =========================
# PROTECTED PROFILE
# =========================
@app.route("/profile", methods=["POST"])
def profile():
    data = request.json
    token = data.get("access_token")

    valid, payload = verify_signed_token(token)

    if valid is True:
        return jsonify({
            "user": payload["user"],
            "role": payload["role"]
        })

    elif payload == "expired":
        return jsonify({"message": "Access token expired"}), 401

    else:
        return jsonify({"message": "Invalid token"}), 403


# =========================
# ALERT VIEW
# =========================
@app.route("/alerts", methods=["GET"])
def view_alerts():
    return jsonify(alerts)


if __name__ == "__main__":
    app.run(debug=True)