import tkinter as tk
from tkinter import ttk
import json
import sys
import os
import subprocess
import base64
import hashlib
import math
from user_manager import is_strong_password
from tkinter import messagebox, simpledialog
from user_manager import validate_login
from user_manager import update_user_password, user_exists, hash_password, generate_key
from cryptography.fernet import Fernet

current_main_password = None
USERS_DIR = "users"

def open_dashboard(username, password, root):
    global current_main_password
    current_main_password = password
    dashboard = tk.Toplevel()
    dashboard.title("VaultGuard - Dashboard")
    dashboard.geometry("900x600")
    dashboard.configure(bg="#1e1e1e")

    header = tk.Label(dashboard, text=f"VaultGuard - Welcome, {username}", font=("Segoe UI", 14, "bold"), fg="white", bg="#1e1e1e")
    header.pack(pady=10)

    notebook = ttk.Notebook(dashboard)
    notebook.pack(expand=True, fill="both")

    style = ttk.Style()
    style.theme_use('default')
    style.configure('TNotebook', background="#2b2b2b", borderwidth=0)
    style.configure('TNotebook.Tab', background="#3a3a3a", foreground="white", padding=10)
    style.map('TNotebook.Tab', background=[('selected', '#4e4e4e')])

    # Saved Passwords Tab
    saved_tab = tk.Frame(notebook, bg="#2b2b2b")
    notebook.add(saved_tab, text="Saved Passwords")
    canvas = tk.Canvas(saved_tab, bg="#2b2b2b", highlightthickness=0)
    scrollbar = ttk.Scrollbar(saved_tab, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="#2b2b2b")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def load_saved_passwords():
        for widget in scrollable_frame.winfo_children():
            widget.destroy()

        user_file = os.path.join(USERS_DIR, f"{username}.json")
        with open(user_file, "r") as f:
            data = json.load(f)

        passwords = data.get("passwords", [])

        if not passwords:
            no_pw_label = tk.Label(scrollable_frame, text="No passwords saved yet.", fg="white", bg="#2b2b2b")
            no_pw_label.pack(pady=20)
        else:
            for index, entry in enumerate(passwords):
                app_name = entry.get("app_name", "Unknown App")
                app_user = entry.get("username", "N/A")
                stored_password = entry.get("password", "")
                container = tk.Frame(scrollable_frame, bg="#3a3a3a", padx=30, pady=10)
                container.pack(fill="x", pady=5, padx=30)
                label = tk.Label(container, text=f"{app_name} - {app_user}", fg="white", bg="#3a3a3a")
                label.pack(side="left")
                pw_label = tk.Label(container, text="", fg="white", bg="#3a3a3a")
                pw_label.pack(side="right", padx=5)

                def make_show_callback(encrypted_pw, label):
                    def callback():
                        entered_pw = simpledialog.askstring("Re-Verify", "Enter your main password:", show="*")
                        if not entered_pw:
                            return

                        user_file = os.path.join(USERS_DIR, f"{username}.json")
                        with open(user_file, "r") as f:
                            data = json.load(f)

                        salt = data.get("salt")

                        try:
                            key = generate_key(entered_pw, salt)
                            fernet = Fernet(key)
                            decrypted_pw = fernet.decrypt(encrypted_pw.encode()).decode()
                            label.config(text=decrypted_pw)
                            dashboard.clipboard_clear()
                            dashboard.clipboard_append(decrypted_pw)
                            messagebox.showinfo("Copied!", "Password shown and copied to clipboard.")
                        except Exception:
                            messagebox.showerror("Error", "Incorrect password or decryption failed.")
                    return callback

                def make_delete_callback(i):
                    def delete_password():
                        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?")
                        if confirm:
                            with open(user_file, "r") as f:
                                data = json.load(f)
                            del data["passwords"][i]
                            with open(user_file, "w") as f:
                                json.dump(data, f, indent=4)
                            load_saved_passwords()  # Refresh list
                    return delete_password

                show_btn = ttk.Button(container, text="Show", command=make_show_callback(stored_password, pw_label))
                show_btn.pack(side="right", padx=5)
                del_btn = ttk.Button(container, text="Delete", command=make_delete_callback(index))
                del_btn.pack(side="right", padx=5)
                
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        scrollable_frame.bind_all("<MouseWheel>", _on_mousewheel)

    load_saved_passwords()

    # Edit Profile Tab
    edit_tab = tk.Frame(notebook, bg="#2b2b2b")
    notebook.add(edit_tab, text="Edit Profile")
    edit_label = tk.Label(edit_tab, text="Edit your account here.", fg="white", bg="#2b2b2b")
    edit_label.pack(pady=20)

        # Change Password Section
    pw_change_label = tk.Label(edit_tab, text="Change Main Password", font=("Segoe UI", 12, "bold"), fg="white", bg="#2b2b2b")
    pw_change_label.pack(pady=(20, 5))
    current_pw_label = tk.Label(edit_tab, text="Current Password:", fg="white", bg="#2b2b2b")
    current_pw_label.pack()
    current_pw_entry = ttk.Entry(edit_tab, width=40, show="*")
    current_pw_entry.pack(pady=(0, 10))
    new_pw_label = tk.Label(edit_tab, text="New Password:", fg="white", bg="#2b2b2b")
    new_pw_label.pack()
    new_pw_entry = ttk.Entry(edit_tab, width=40, show="*")
    new_pw_entry.pack(pady=(0, 10))

    def change_password():
        current_pw = current_pw_entry.get()
        new_pw = new_pw_entry.get()

        if not current_pw or not new_pw:
            messagebox.showerror("Error", "Both fields are required.")
            return
        if not validate_login(username, current_pw):
            messagebox.showerror("Error", "Current password is incorrect.")
            return
        if not is_strong_password(new_pw):
            messagebox.showerror("Weak Password", 
                "New password must be at least 8 characters long and include:\n"
                "- Uppercase letter\n- Lowercase letter\n- Number\n- Special character (@$!%*?&)"
            )
            return
        
        global current_main_password
        if update_user_password(username, current_main_password, new_pw):
            messagebox.showinfo("Success", "Password updated! Please log in again.")
            current_main_password = new_pw
            current_pw_entry.delete(0, tk.END)
            new_pw_entry.delete(0, tk.END)
            dashboard.destroy()
            python_exe = sys.executable  # Path to the current Python interpreter
            run_path = os.path.join(os.path.dirname(__file__), "run.py")
            subprocess.Popen([python_exe, run_path])
            sys.exit()
        else:
            messagebox.showerror("Error", "Something went wrong while updating the password.")


    ttk.Button(edit_tab, text="Update Password", command=change_password).pack(pady=10)

    uname_change_label = tk.Label(edit_tab, text="Change Username", font=("Segoe UI", 12, "bold"), fg="white", bg="#2b2b2b")
    uname_change_label.pack(pady=(20, 5))
    new_uname_label = tk.Label(edit_tab, text="New Username:", fg="white", bg="#2b2b2b")
    new_uname_label.pack()
    new_uname_entry = ttk.Entry(edit_tab, width=40)
    new_uname_entry.pack(pady=(0, 10))
    pw_for_uname_label = tk.Label(edit_tab, text="Enter Main Password:", fg="white", bg="#2b2b2b")
    pw_for_uname_label.pack()
    pw_for_uname_entry = ttk.Entry(edit_tab, width=40, show="*")
    pw_for_uname_entry.pack(pady=(0, 10))

    def change_username():
        new_uname = new_uname_entry.get()
        pw_check = pw_for_uname_entry.get()

        if not new_uname or not pw_check:
            messagebox.showerror("Error", "All fields are required.")
            return
        if user_exists(new_uname):
            messagebox.showerror("Error", "Username already taken.")
            return
        if not validate_login(username, pw_check):
            messagebox.showerror("Error", "Incorrect password.")
            return
        old_path = os.path.join(USERS_DIR, f"{username}.json")
        new_path = os.path.join(USERS_DIR, f"{new_uname}.json")

        try:
            with open(old_path, "r") as f:
                data = json.load(f)

            data["username"] = new_uname
            with open(new_path, "w") as f:
                json.dump(data, f, indent=4)

            os.remove(old_path)
            messagebox.showinfo("Success", "Username updated! Please log in again.")

            dashboard.destroy()  
            python_exe = sys.executable 
            run_path = os.path.join(os.path.dirname(__file__), "run.py")
            subprocess.Popen([python_exe, run_path])
            sys.exit()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update username: {e}")

    ttk.Button(edit_tab, text="Update Username", command=change_username).pack(pady=10)

    # --- Add Password Tab ---
    add_tab = tk.Frame(notebook, bg="#2b2b2b")
    notebook.insert(1, add_tab, text="Add Password")
    add_title = tk.Label(add_tab, text="Add a New Password", font=("Segoe UI", 12, "bold"),
                         fg="white", bg="#2b2b2b")
    add_title.pack(pady=(20, 10))
    app_label = tk.Label(add_tab, text="Application/Website Name:", fg="white", bg="#2b2b2b")
    app_label.pack()
    app_entry = ttk.Entry(add_tab, width=40)
    app_entry.pack(pady=(0, 10))

    # Username/Email
    user_label = tk.Label(add_tab, text="Username/Email:", fg="white", bg="#2b2b2b")
    user_label.pack()
    user_entry = ttk.Entry(add_tab, width=40)
    user_entry.pack(pady=(0, 10))

    # Password
    pw_label = tk.Label(add_tab, text="Password:", fg="white", bg="#2b2b2b")
    pw_label.pack()
    pw_entry = ttk.Entry(add_tab, width=40)
    pw_entry.pack(pady=(0, 10))

    # Submit Button
    def save_password():
        app = app_entry.get()
        user = user_entry.get()
        pw = pw_entry.get()

        if not app or not user or not pw:
            tk.messagebox.showerror("Error", "All fields are required.")
            return
        if not is_strong_password(pw):
            tk.messagebox.showerror(
                "Weak Password",
                "Password must be at least 8 characters long and include:\n"
                "- Uppercase letter\n"
                "- Lowercase letter\n"
                "- Number\n"
                "- Special character (@$!%*?&)"
            )
            return
        user_file = os.path.join(USERS_DIR, f"{username}.json")
        with open(user_file, "r") as f:
            data = json.load(f)
        salt = data.get("salt")

        key = generate_key(current_main_password, salt)
        fernet = Fernet(key)
        encrypted_pw = fernet.encrypt(pw.encode()).decode()

        data["passwords"].append({
            "app_name": app,
            "username": user,
            "password": encrypted_pw
        })

        with open(user_file, "w") as f:
            json.dump(data, f, indent=4)

        tk.messagebox.showinfo("Success", "Password added!")
        app_entry.delete(0, tk.END)
        user_entry.delete(0, tk.END)
        pw_entry.delete(0, tk.END)

        load_saved_passwords()

    ttk.Button(add_tab, text="Save Password", command=save_password).pack(pady=20)

    def on_close():
        root.destroy() 
    dashboard.protocol("WM_DELETE_WINDOW", on_close)


    # Password Strength Tab
    strength_tab = tk.Frame(notebook, bg="#2b2b2b")
    notebook.add(strength_tab, text="Password Strength")

    strength_title = tk.Label(strength_tab, text="Check Password Strength", font=("Segoe UI", 12, "bold"),
                          fg="white", bg="#2b2b2b")
    strength_title.pack(pady=(20, 5))

    strength_info = tk.Label(
        strength_tab,
        text="Enter any password below to see how secure it is. We'll analyze its strength\n"
            "and estimate how long it would take for a hacker to crack it.",
        font=("Segoe UI", 9),
        fg="#cccccc",
        bg="#2b2b2b",
        justify="center"
    )
    strength_info.pack(pady=(0, 10))

    strength_entry = ttk.Entry(strength_tab, width=40)
    strength_entry.pack(pady=(0, 10))
    analyze_btn = ttk.Button(strength_tab, text="Analyze")
    analyze_btn.pack()
    result_label = tk.Label(strength_tab, text="", fg="white", bg="#2b2b2b", font=("Segoe UI", 10))
    result_label.pack(pady=10)

    def estimate_crack_time(password):
        charset_size = 0
        if any(c.islower() for c in password): charset_size += 26
        if any(c.isupper() for c in password): charset_size += 26
        if any(c.isdigit() for c in password): charset_size += 10
        if any(c in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|" for c in password): charset_size += 32

        guesses = charset_size ** len(password) if charset_size else 0
        guesses_per_second = 1e9
        seconds = guesses / guesses_per_second if guesses > 0 else 0

        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds // 86400)} days"
        else:
            return f"{int(seconds // 31536000)} years"
    

    def get_strength_rating(password):
        length = len(password)
        criteria = sum([
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|" for c in password)
        ])

        if length >= 12 and criteria >= 3:
            return "Very Strong"
        elif length >= 10 and criteria >= 3:
            return "Strong"
        elif length >= 8 and criteria >= 2:
            return "Moderate"
        else:
            return "Weak"
        
    def analyze_password():
        pw = strength_entry.get()
        if not pw:
            result_label.config(text="Please enter a password.")
            return
        strength = get_strength_rating(pw)
        time_to_crack = estimate_crack_time(pw)

        result = (
            f"Strength: {strength}\n"
            f"Estimated Time to Crack: {time_to_crack}"
        )
        result_label.config(text=result)

    analyze_btn.config(command=analyze_password)
