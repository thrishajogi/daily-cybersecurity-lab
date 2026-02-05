import hashlib

password = input("Enter password: ")

hashed_password = hashlib.sha256(password.encode()).hexdigest()

print("\nOriginal Password:", password)
print("Hashed Password (SHA-256):", hashed_password)