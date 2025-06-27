import tkinter as tk
from tkinter import ttk
from user_manager import user_exists, create_user, is_strong_password
from tkinter import messagebox


def open_signup_screen():
    signup = tk.Toplevel()
    signup.title("VaultGuard - Sign Up")
    signup.geometry("400x400")
    signup.resizable(False, False)

    bg_color = "#1e1e1e"
    fg_color = "#ffffff"
    accent_color = "#3a3a3a"

    signup.configure(bg=bg_color)

    frame = tk.Frame(signup, bg=bg_color)
    frame.pack(expand=True)

    title = tk.Label(frame, text="Create Account", font=("Segoe UI", 18, "bold"), fg=fg_color, bg=bg_color)
    title.pack(pady=(10, 20))

    tk.Label(frame, text="Username:", fg=fg_color, bg=bg_color).pack()
    username_entry = ttk.Entry(frame, width=30)
    username_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Main Password:", fg=fg_color, bg=bg_color).pack()
    password_entry = ttk.Entry(frame, width=30, show="*")
    password_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Confirm Password:", fg=fg_color, bg=bg_color).pack()
    confirm_entry = ttk.Entry(frame, width=30, show="*")
    confirm_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Password Hint (optional):", fg=fg_color, bg=bg_color).pack()
    hint_entry = ttk.Entry(frame, width=30)
    hint_entry.pack(pady=(0, 10))

    def submit():
        username = username_entry.get().strip()
        password = password_entry.get()
        confirm = confirm_entry.get()
        hint = hint_entry.get()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "All fields except hint are required.")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        if not is_strong_password(password):
            messagebox.showerror("Weak Password", 
            "Password must be at least 8 characters and include:\n"
            "- Uppercase letter\n- Lowercase letter\n- Number\n- Special character")
            return
        
        if user_exists(username):
            messagebox.showerror("Error", "Username already exists.")
            return

        create_user(username, password, hint)
        messagebox.showinfo("Success", "Account created! You can now log in.")
        signup.destroy()

    ttk.Button(frame, text="Create Account", command=submit).pack(pady=15)
