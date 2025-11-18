"""
Secure Authentication System (Week 7 Lab)
CST1510 – Programming for Data Communications and Networks

This file implements:
- Password hashing (bcrypt)
- Password verification
- User registration
- Login system
- Input validation
- Command-line menu interface

"""

import bcrypt
import os

# Location of our simple "database" file
USER_DATA_FILE = "users.txt"


def hash_password(plain_text_password):
    """
    Hashes a plaintext password using bcrypt with a salt.

    Args:
        plain_text_password (str): The password to hash.

    Returns:
        str: The bcrypt hashed password as a UTF-8 string.
    """

    # Convert the password to bytes (bcrypt only supports byte strings)
    password_bytes = plain_text_password.encode("utf-8")

    # Generate a salt (bcrypt automatically handles security)
    salt = bcrypt.gensalt()

    # Perform the hashing
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Convert the hashed bytes back to a UTF-8 string for storage
    return hashed.decode("utf-8")


def verify_password(plain_text_password, hashed_password):
    """
    Verifies a password by comparing it to a stored hash.

    Args:
        plain_text_password (str): The password to verify.
        hashed_password (str): The stored bcrypt hash.

    Returns:
        bool: True if the password matches, otherwise False.
    """

    # Encode everything to bytes
    password_bytes = plain_text_password.encode("utf-8")
    hash_bytes = hashed_password.encode("utf-8")

    # bcrypt.checkpw() extracts the salt automatically
    return bcrypt.checkpw(password_bytes, hash_bytes)

def user_exists(username):
    """Checks if a username is already registered."""
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, _ = line.strip().split(",")
            if stored_username == username:
                return True

    return False


def register_user(username, password):
    """
    Registers a new user by hashing their password and storing the result.
    """
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

    hashed = hash_password(password)

    # Append to users.txt
    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username},{hashed}\n")

    print(f"Success: User '{username}' registered successfully!")
    return True


def login_user(username, password):
    """
    Logs a user in by validating the username and verifying the password.
    """

    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users registered yet.")
        return False

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_hash = line.strip().split(",")

            if stored_username == username:
                if verify_password(password, stored_hash):
                    print(f"Success: Welcome, {username}!")
                    return True
                else:
                    print("Error: Invalid password.")
                    return False

    print("Error: Username not found.")
    return False


def validate_username(username):
    """
    Validates a username:
    - Must be 3–20 characters
    - Must be alphanumeric
    """
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."

    if not username.isalnum():
        return False, "Username must contain only letters and numbers."

    return True, ""


def validate_password(password):
    """
    Validates password strength:
    - At least 6 characters
    - No spaces allowed
    """
    if " " in password:
        return False, "Password cannot contain spaces."

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    return True, ""


def display_menu():
    """Displays the main menu."""
    print("\n" + "="*50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)


def main():
    """Main loop of the authentication system."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            is_valid, msg = validate_username(username)
            if not is_valid:
                print(f"Error: {msg}")
                continue

            password = input("Enter a password: ").strip()
            is_valid, msg = validate_password(password)
            if not is_valid:
                print(f"Error: {msg}")
                continue

            confirm = input("Confirm password: ").strip()
            if password != confirm:
                print("Error: Passwords do not match.")
                continue

            register_user(username, password)

        elif choice == '2':
            print("\n--- USER LOGIN ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            login_user(username, password)

            input("\nPress Enter to return to main menu...")

        elif choice == '3':
            print("\nThank you for using the authentication system.")
            break

        else:
            print("Error: Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
