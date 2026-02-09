import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

stored_username = "admin"
stored_password_hash = hash_password("admin@123")

username = input("Enter username: ")
password = input("Enter password: ")

if username == stored_username and hash_password(password) == stored_password_hash:
    print("Login successful ✅")
else:
    print("Login failed ❌")