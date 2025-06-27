import re
import os
import json
import hashlib
import binascii
from cryptography.fernet import Fernet
import base64
import secrets

USERS_DIR = "users"

if not os.path.exists(USERS_DIR):
    os.makedirs(USERS_DIR)

def user_exists(username):
    return os.path.exists(os.path.join(USERS_DIR, f"{username}.json"))

def hash_password(password: str, salt: str) -> str:
    """Returns a hashed password using PBKDF2"""
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return binascii.hexlify(dk).decode()

def create_user(username, password, hint):
    salt = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
    hashed = hash_password(password, salt)
    profile = {
        "username": username,
        "password_hash": hashed,
        "salt": salt,
        "hint": hint,
        "passwords": []
    }
    with open(os.path.join(USERS_DIR, f"{username}.json"), "w") as f:
        json.dump(profile, f)

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def validate_login(username: str, password: str) -> bool:
    path = os.path.join(USERS_DIR, f"{username}.json")
    if not os.path.exists(path):
        return False

    with open(path, "r") as f:
        profile = json.load(f)
    salt = profile.get("salt")
    expected_hash = profile.get("password_hash")
    entered_hash = hash_password(password, salt)

    return entered_hash == expected_hash

def generate_key(master_password, salt):
    kdf = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt.encode(), 100000, dklen=32)
    return base64.urlsafe_b64encode(kdf)

def update_user_password(username: str, old_password: str, new_password: str) -> bool:
    """Update password hash and re-encrypt all saved passwords with the new key."""
    path = os.path.join(USERS_DIR, f"{username}.json")
    if not os.path.exists(path):
        return False

    with open(path, "r") as f:
        profile = json.load(f)
    salt = profile.get("salt")

    try:
        old_key = generate_key(old_password, salt)
        new_key = generate_key(new_password, salt)

        old_fernet = Fernet(old_key)
        new_fernet = Fernet(new_key)

        updated_passwords = []
        for entry in profile.get("passwords", []):
            try:
                decrypted_pw = old_fernet.decrypt(entry["password"].encode()).decode()
                encrypted_new_pw = new_fernet.encrypt(decrypted_pw.encode()).decode()
                entry["password"] = encrypted_new_pw
                updated_passwords.append(entry)
            except Exception:
                return False

        profile["password_hash"] = hash_password(new_password, salt)
        profile["passwords"] = updated_passwords

        with open(path, "w") as f:
            json.dump(profile, f, indent=4)

        return True
    except Exception:
        return False



