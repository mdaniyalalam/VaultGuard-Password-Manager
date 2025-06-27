import tkinter as tk
import os
import json
from tkinter import ttk
from signup_screen import open_signup_screen
from user_manager import validate_login
from dashboard import open_dashboard

def show_login_screen():
    root = tk.Tk()
    root.title("VaultGuard - Login")
    root.geometry("400x300")
    root.resizable(False, False)
    bg_color = "#1e1e1e"
    fg_color = "#ffffff"
    accent_color = "#3a3a3a"
    root.configure(bg=bg_color)

    frame = tk.Frame(root, bg=bg_color)
    frame.pack(expand=True)

    title = tk.Label(frame, text="VaultGuard", font=("Segoe UI", 20, "bold"), fg=fg_color, bg=bg_color)
    title.pack(pady=(10, 20))

    username_label = tk.Label(frame, text="Username:", fg=fg_color, bg=bg_color)
    username_label.pack()
    username_entry = ttk.Entry(frame, width=30)
    username_entry.pack(pady=(0, 10))

    password_label = tk.Label(frame, text="Main Password:", fg=fg_color, bg=bg_color)
    password_label.pack()
    password_entry = ttk.Entry(frame, width=30, show="*")
    password_entry.pack(pady=(0, 10))

    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()

        if validate_login(username, password):
            root.withdraw()
            open_dashboard(username, password, root)
        else:
            error_message = "Invalid username or password."
            user_file = os.path.join("users", f"{username}.json")

            if os.path.exists(user_file):
                with open(user_file, "r") as f:
                    user_data = json.load(f)
                hint = user_data.get("hint")
                if hint:
                    error_message += f"\nHint: {hint}"
            tk.messagebox.showerror("Login Failed", error_message)

    ttk.Button(root, text="Log In", command=attempt_login).pack(pady=10)

    signup_label = tk.Label(frame, text="Don't have an account? Sign up", fg="#7abaff", bg=bg_color, cursor="hand2")
    signup_label.pack()
    signup_label.bind("<Button-1>", lambda e: open_signup_screen())

    root.mainloop()
