import hashlib

# simulate user signup
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

stored_username = "admin"
stored_password_hash = hash_password("admin@123")

print("User registered successfully")
print("Stored hash:", stored_password_hash)