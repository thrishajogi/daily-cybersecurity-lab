import requests

url = "http://127.0.0.1:5000/login"

passwords = ["1234", "admin", "password", "admin@123"]

for pwd in passwords:
    response = requests.post(url, json={
        "username": "admin",
        "password": pwd
    })

    print(f"Trying password: {pwd} → {response.json()['message']}")