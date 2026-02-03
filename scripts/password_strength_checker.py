password = input("Enter password: ")

strength = 0

if len(password) >= 8:
    strength += 1
if any(char.isdigit() for char in password):
    strength += 1
if any(char.isupper() for char in password):
    strength += 1
if any(char.islower() for char in password):
    strength += 1

if strength <= 2:
    print("Weak password ")
elif strength == 3:
    print("Medium password ")
else:
    print("Strong password ")
