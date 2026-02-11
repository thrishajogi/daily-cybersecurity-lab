from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import time
import json

app = Flask(__name__)
CORS(app)

stored_username = "admin"
stored_password_hash = hashlib.sha256("admin@123".encode()).hexdigest()

MAX_ATTEMPTS = 3
LOCK_TIME = 30

failed_attempts = {}
alerts = []

def log_event(event):
    with open("security_log.json", "a") as f:
        f.write(json.dumps(event) + "\n")

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

    if current_time < failed_attempts[ip]["lock_until"]:
        return jsonify({"message": "IP temporarily blocked 🔒"}), 403

    hashed_input = hashlib.sha256(password.encode()).hexdigest()

    if username == stored_username and hashed_input == stored_password_hash:
        failed_attempts[ip]["count"] = 0
        log_event({
            "type": "successful_login",
            "ip": ip,
            "timestamp": current_time
        })
        return jsonify({"message": "Login successful ✅"})
    else:
        failed_attempts[ip]["count"] += 1

        log_event({
            "type": "failed_login",
            "ip": ip,
            "timestamp": current_time
        })

        if failed_attempts[ip]["count"] >= MAX_ATTEMPTS:
            failed_attempts[ip]["lock_until"] = current_time + LOCK_TIME

            alert = {
                "type": "brute_force_detected",
                "ip": ip,
                "timestamp": current_time
            }

            alerts.append(alert)
            log_event(alert)

            failed_attempts[ip]["count"] = 0

            return jsonify({"message": "Too many attempts. IP blocked 🔒"}), 403

        return jsonify({"message": "Invalid credentials ❌"}), 401


@app.route("/alerts", methods=["GET"])
def view_alerts():
    return jsonify(alerts)


if __name__ == "__main__":
    app.run(debug=True)