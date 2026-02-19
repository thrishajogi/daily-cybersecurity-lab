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
SECRET_KEY = b"phase3_policy_engine_key"
TOKEN_TTL = 120

# =========================
# DATABASE
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
# PERMISSION MATRIX
# =========================

ROLE_PERMISSIONS = {
    "admin": ["view_all_documents", "view_own_documents"],
    "user": ["view_own_documents"]
}

def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, [])

# =========================
# TOKEN UTILITIES
# =========================

def sign_token(payload):
    payload_str = json.dumps(payload)
    signature = hmac.new(
        SECRET_KEY,
        payload_str.encode(),
        hashlib.sha256
    ).hexdigest()
    return base64.b64encode(f"{payload_str}.{signature}".encode()).decode()


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
# ROOT
# =========================

@app.route("/")
def home():
    return jsonify({"message": "Day 16 Permission Engine Active 🚀"})

# =========================
# LOGIN
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
# LIST DOCUMENTS
# =========================

@app.route("/documents", methods=["POST"])
def list_documents():
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid is not True:
        return jsonify({"message": "Invalid or expired token"}), 403

    username = payload["user"]
    role = users[username]["role"]  # LIVE ROLE CHECK

    if has_permission(role, "view_all_documents"):
        return jsonify(documents)

    if has_permission(role, "view_own_documents"):
        user_docs = {
            doc_id: doc
            for doc_id, doc in documents.items()
            if doc["owner"] == username
        }
        return jsonify(user_docs)

    return jsonify({"message": "Permission denied"}), 403

# =========================
# VIEW DOCUMENT
# =========================

@app.route("/document/<doc_id>", methods=["POST"])
def view_document(doc_id):
    data = request.json
    token = data.get("token")

    valid, payload = verify_token(token)

    if valid is not True:
        return jsonify({"message": "Invalid or expired token"}), 403

    username = payload["user"]
    role = users[username]["role"]

    if doc_id not in documents:
        return jsonify({"message": "Not found"}), 404

    document = documents[doc_id]

    if has_permission(role, "view_all_documents"):
        return jsonify(document)

    if has_permission(role, "view_own_documents"):
        if document["owner"] == username:
            return jsonify(document)

    alerts.append({
        "type": "unauthorized_document_access",
        "user": username,
        "doc_id": doc_id,
        "timestamp": time.time()
    })

    return jsonify({"message": "Access denied"}), 403

# =========================
# ALERTS
# =========================

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts)

if __name__ == "__main__":
    app.run(debug=True)