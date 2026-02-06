import time

correct_password = "admin123"
attempts = 0
max_attempts = 3

while attempts < max_attempts:
    password = input("Enter password: ")

    if password == correct_password:
        print("Login successful ✅")
        break
    else:
        attempts += 1
        print("Wrong password ❌")

        if attempts == max_attempts:
            print("Too many attempts! Account locked 🔒")
        else:
            print("Try again...\n")
            time.sleep(1)