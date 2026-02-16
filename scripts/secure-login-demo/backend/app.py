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
# CONFIG
# =========================
SECRET_KEY = b"phase2_ultra_secure_key"
TOKEN_TTL = 120  # seconds

# =========================
# DATABASE (Simulated)
# =========================
users = {
    "admin": {
        "password_hash": hashlib.sha256("admin@123".encode()).hexdigest(),
        "role": "admin"
    },
    "alice": {
        "password_hash": hashlib.sha256("alice@123".encode()).hexdigest(),
        "role": "user"
    }
}

documents = {
    "1": {"owner": "alice", "content": "Alice private document"},
    "2": {"owner": "admin", "content": "Admin confidential report"}
}

alerts = []

# =========================
# UTILITIES
# =========================

def sign_token(payload):
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

        if not hmac.compare_digest(received_signature, expected_signature):
            return False, None

        payload = json.loads(payload_str)

        if payload["exp"] < time.time():
            return False, "expired"

        return True, payload

    except Exception:
        return False, None


# =========================
# ROOT ROUTE
# =========================

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phase 2 Purple Capstone API Running 🚀"})


# =========================
# AUTHENTICATION
# =========================

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username not in users:
        return jsonify({"message": "Invalid credentials"}), 401

    hashed = hashlib.sha256(password.encode()).hexdigest()

    if hashed != users[username]["password_hash"]:
        return jsonify({"message": "Invalid credentials"}), 401

    payload = {
        "user": username,
        "exp": time.time() + TOKEN_TTL
    }

    token = sign_token(payload)

    return jsonify({"token": token})


# =========================
# LIST DOCUMENTS (RBAC SAFE)
# =========================

@app.route("/documents", methods=["POST"])
def list_documents():
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid is not True:
        return jsonify({"message": "Invalid or expired token"}), 403

    username = payload["user"]
    current_role = users[username]["role"]  # 🔐 LIVE ROLE CHECK

    if current_role == "admin":
        return jsonify(documents)

    user_docs = {
        doc_id: doc
        for doc_id, doc in documents.items()
        if doc["owner"] == username
    }

    return jsonify(user_docs)


# =========================
# VIEW SINGLE DOCUMENT (SECURE)
# =========================

@app.route("/document/<doc_id>", methods=["POST"])
def view_document(doc_id):
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid is not True:
        return jsonify({"message": "Invalid or expired token"}), 403

    username = payload["user"]

    if doc_id not in documents:
        return jsonify({"message": "Not found"}), 404

    doc = documents[doc_id]

    current_role = users[username]["role"]  # 🔐 LIVE ROLE CHECK

    # Admin override based on LIVE ROLE
    if current_role == "admin":
        return jsonify(doc)

    # Ownership enforcement
    if doc["owner"] != username:
        alerts.append({
            "type": "horizontal_privilege_escalation_attempt",
            "attacker": username,
            "target_doc": doc_id,
            "timestamp": time.time()
        })

        return jsonify({"message": "Access denied 🚫"}), 403

    return jsonify(doc)


# =========================
# CHANGE ROLE (SIMULATE PRIVILEGE DROP)
# =========================

@app.route("/change_role", methods=["POST"])
def change_role():
    data = request.json
    username = data.get("username")
    new_role = data.get("role")

    if username not in users:
        return jsonify({"message": "User not found"}), 404

    users[username]["role"] = new_role

    return jsonify({
        "message": f"{username} role updated to {new_role}"
    })


# =========================
# ALERTS
# =========================

@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(alerts)


# =========================
# SERVER START
# =========================

if __name__ == "__main__":
    app.run(debug=True)