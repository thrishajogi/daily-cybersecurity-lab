from flask import Flask, request, jsonify
import threading
import time

app = Flask(__name__)

wallet = {
    "admin": 100
}

wallet_lock = threading.Lock()


@app.route("/balance/<user>", methods=["GET"])
def balance(user):
    if user in wallet:
        return jsonify({"balance": wallet[user]})
    return jsonify({"message": "User not found"}), 404


@app.route("/withdraw", methods=["POST"])
def withdraw():
    data = request.json
    user = data.get("user")
    amount = data.get("amount")

    if user not in wallet:
        return jsonify({"message": "User not found"}), 404

    with wallet_lock:  # CRITICAL FIX
        if wallet[user] < amount:
            return jsonify({"message": "Insufficient funds"}), 400

        time.sleep(1)
        wallet[user] -= amount

    return jsonify({"message": "Withdrawal successful", "balance": wallet[user]})


if __name__ == "__main__":
    app.run(debug=True, threaded=True)