import tkinter as tk
from main import show_login_screen 

def show_splash():
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.configure(bg="#1e1e1e")

    width, height = 400, 250
    screen_width = splash.winfo_screenwidth()
    screen_height = splash.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    splash.geometry(f"{width}x{height}+{x}+{y}")

    label = tk.Label(splash, text="VaultGuard", font=("Segoe UI", 24, "bold"), fg="#ffffff", bg="#1e1e1e")
    label.pack(expand=True)

    loading = tk.Label(splash, text="Loading...", font=("Segoe UI", 10), fg="#cccccc", bg="#1e1e1e")
    loading.pack(pady=10)

    splash.after(2500, lambda: [splash.destroy(), show_login_screen()])
    splash.mainloop()
