# VaultGuard

**VaultGuard** is a sleek and secure password manager built with Python and Tkinter. It features a modern, dark-themed interface, encrypted password storage, and user-based authentication. Designed with simplicity and security in mind, VaultGuard is perfect for learning and personal use.

---

## Features

- **User Sign-up and Login** – Create your account and log in securely.
- **Encrypted Password Vault** – Stores credentials with strong per-user encryption.
- **View & Manage Credentials** – Add, update, and delete saved passwords.
- **Password Strength Checker** – Rate password strength and estimate cracking time.
- **Profile Editing** – Change your username or main password after verifying identity.
- **Copy to Clipboard** – Copy passwords securely after verification.
- **Hint on Failed Login** – View your optional password hint after failed attempts.
- **Dark UI & Tabbed Layout** – Clean and intuitive dark-themed interface with tabs.
- **Splash Screen** – Smooth launch experience with a brief animated splash screen.

---

## File Structure

| File Name           | Description                                             |
|---------------------|---------------------------------------------------------|
| `main.py`           | Launches the login interface.                          |
| `signup_screen.py`  | Handles user registration.                             |
| `dashboard.py`      | Core application window with all main features.        |
| `user_manager.py`   | Manages user data, encryption, authentication logic.   |
| `splash_screen.py`  | Displays the initial animated splash screen.           |
| `run.py`            | (Optional) Entry point that opens splash → main app.   |

---

## How It Works

1. The user **signs up** with a username, password, and optional hint.
2. The password is hashed and saved securely.
3. On **login**, the password is verified, and the user enters their personal vault.
4. **All saved passwords are encrypted** using the main password as the encryption key.
5. When viewing or editing sensitive data, **re-verification is required**.
6. Passwords can be securely **copied to clipboard**, never displayed openly unless verified.

---

## License

This project is licensed under the **MIT License** – you are free to use, modify, and distribute it for personal or educational purposes.

---

## Tip

VaultGuard was created as a student-level project to demonstrate secure handling of credentials with GUI design in Python. Ideal for beginners interested in cybersecurity, encryption, and Python development.

---

