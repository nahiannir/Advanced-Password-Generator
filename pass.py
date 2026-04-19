import secrets # Secure random generator (better than random)
import string # Provides character sets (letters, digits, symbols)
import re # Used for password strength checking (regex)
import pyperclip # For copying password to clipboard
from cryptography.fernet import Fernet # For encryption
import os # For file handling (checking if key exists)

# ---------------- KEY MANAGEMENT ----------------
KEY_FILE = "key.key" # File where encryption key is stored

def load_or_create_key():
    # Check if key file already exists
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read() # Load existing key
    else:
        key = Fernet.generate_key() # Create new encryption key
        with open(KEY_FILE, "wb") as f:
            f.write(key) # Save key to file
        return key

cipher = Fernet(load_or_create_key()) # Create encryption object

# ---------------- PASSWORD GENERATOR ----------------
def generate_password(length=16,
                      use_upper=True,
                      use_lower=True,
                      use_digits=True,
                      use_symbols=True,
                      avoid_ambiguous=True):
    
    if length < 4:
        raise ValueError("Length must be at least 4.") # Basic validation

    # Character sets
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation

    # Remove confusing characters like O, 0, l, 1
    if avoid_ambiguous:
        ambiguous = "O0l1I"
        upper = ''.join(c for c in upper if c not in ambiguous)
        lower = ''.join(c for c in lower if c not in ambiguous)
        digits = ''.join(c for c in digits if c not in ambiguous)

    pools = [] # List to store selected character sets

    # Add selected character types
    if use_upper: pools.append(upper)
    if use_lower: pools.append(lower)
    if use_digits: pools.append(digits)
    if use_symbols: pools.append(symbols)

    if not pools:
        raise ValueError("Select at least one character type.")

    # Ensure at least one character from each selected type
    password = [secrets.choice(pool) for pool in pools]

    # Combine all characters
    all_chars = ''.join(pools)

    # Fill remaining length randomly
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]

    # Shuffle password securely
    secrets.SystemRandom().shuffle(password)

    return ''.join(password) # Convert list to string

# ---------------- MEMORABLE PASSWORD ----------------
def generate_memorable():
    words = ["shadow", "tiger", "nova", "storm", "falcon", "quantum"]

    # Combine words + number + symbol
    return (
        secrets.choice(words).capitalize() +
        secrets.choice(words) +
        str(secrets.randbelow(100)) +
        secrets.choice("!@#$%")
    )

# ---------------- PASSWORD STRENGTH CHECK ----------------
def check_strength(pwd):
    score = 0

    # Check different conditions
    if len(pwd) >= 12: score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"[a-z]", pwd): score += 1
    if re.search(r"\d", pwd): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd): score += 1

    # Strength levels
    levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]

    return levels[score - 1] if score > 0 else "Very Weak"

# ---------------- SAVE ENCRYPTED ----------------
def save_password(pwd):
    encrypted = cipher.encrypt(pwd.encode()) # Encrypt password

    # Append encrypted password to file
    with open("passwords.enc", "ab") as f:
        f.write(encrypted + b"\n")

# ---------------- MAIN PROGRAM ----------------
def main():
    while True: # Infinite loop for continuous usage
        print("\n==== PASSWORD TOOL ====")
        print("1. Generate strong password")
        print("2. Generate memorable password")
        print("3. Check password strength")
        print("4. Exit")

        choice = input("Choose: ")

        if choice == "1":
            try:
                length = int(input("Length (default 16): ") or 16)
                pwd = generate_password(length)
            except ValueError:
                print("Invalid length.")
                continue

        elif choice == "2":
            pwd = generate_memorable()

        elif choice == "3":
            user_pwd = input("Enter password: ")
            print("Strength:", check_strength(user_pwd))
            continue

        elif choice == "4":
            print("Goodbye.")
            break

        else:
            print("Invalid option.")
            continue

        # Common actions after generating password
        print("Password:", pwd)
        print("Strength:", check_strength(pwd))

        pyperclip.copy(pwd) # Copy to clipboard
        print("Copied to clipboard!")

        save_password(pwd) # Save encrypted
        print("Saved securely.\n")

# Run program
if __name__ == "__main__":
    main()