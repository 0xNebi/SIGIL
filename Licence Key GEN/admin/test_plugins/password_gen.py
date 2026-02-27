import tkinter as tk
from tkinter import ttk
import secrets
import string
import pyperclip

user = globals().get("SIGIL_USER", "unknown")

LOWER   = string.ascii_lowercase
UPPER   = string.ascii_uppercase
DIGITS  = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

root = tk.Tk()
root.title("Password Generator")
root.geometry("360x340")
root.resizable(False, False)
root.configure(bg="#0a0a14")
root.lift()
root.attributes("-topmost", True)
root.focus_force()

tk.Label(root, text="Password Generator",
         font=("Arial", 15, "bold"), fg="#7af0a0", bg="#0a0a14").pack(pady=(16, 2))
tk.Label(root, text=f"Running as: {user}",
         font=("Arial", 9), fg="#444466", bg="#0a0a14").pack()

opts = tk.Frame(root, bg="#0a0a14")
opts.pack(pady=12, padx=20, fill="x")

tk.Label(opts, text="Length:", font=("Arial", 10), fg="#888899", bg="#0a0a14").grid(
    row=0, column=0, sticky="w", pady=4)
length_var = tk.IntVar(value=16)
length_lbl = tk.Label(opts, textvariable=length_var, width=3,
                      font=("Arial", 10, "bold"), fg="#c8c8ff", bg="#0a0a14")
length_lbl.grid(row=0, column=2, padx=(6, 0))
tk.Scale(opts, from_=8, to=48, orient="horizontal", variable=length_var,
         bg="#0a0a14", fg="#c8c8ff", troughcolor="#1a1a2e",
         highlightthickness=0, bd=0, showvalue=False, length=180).grid(
    row=0, column=1, padx=4)

use_upper   = tk.BooleanVar(value=True)
use_digits  = tk.BooleanVar(value=True)
use_symbols = tk.BooleanVar(value=True)

for row, (var, label) in enumerate([
    (use_upper,   "Include uppercase  A-Z"),
    (use_digits,  "Include digits  0-9"),
    (use_symbols, "Include symbols  !@#$…"),
], start=1):
    tk.Checkbutton(opts, text=label, variable=var,
                   font=("Arial", 10), fg="#c0c0ee", bg="#0a0a14",
                   selectcolor="#1a1a2e", activebackground="#0a0a14",
                   activeforeground="#ffffff").grid(
        row=row, column=0, columnspan=3, sticky="w", pady=2)

result_var = tk.StringVar(value="")
result_entry = tk.Entry(root, textvariable=result_var,
                        font=("Courier New", 12), fg="#7af0a0", bg="#0e0e1c",
                        insertbackground="#7af0a0", relief="flat",
                        justify="center", width=32)
result_entry.pack(pady=(0, 8), padx=20, ipady=6)

status_var = tk.StringVar(value="")
tk.Label(root, textvariable=status_var, font=("Arial", 9),
         fg="#888899", bg="#0a0a14").pack()

def generate():
    charset = LOWER
    if use_upper.get():   charset += UPPER
    if use_digits.get():  charset += DIGITS
    if use_symbols.get(): charset += SYMBOLS

    pwd = "".join(secrets.choice(charset) for _ in range(length_var.get()))
    result_var.set(pwd)
    status_var.set("")

def copy_pwd():
    pwd = result_var.get()
    if not pwd:
        status_var.set("Generate a password first.")
        return
    try:
        pyperclip.copy(pwd)
        status_var.set("Copied to clipboard!")
    except Exception:
        status_var.set("Clipboard unavailable — select manually.")

btn_frame = tk.Frame(root, bg="#0a0a14")
btn_frame.pack(pady=10)

BTN = dict(font=("Arial", 11), bg="#1a1a2e", fg="#c8c8ff",
           activebackground="#2a2a4e", activeforeground="#ffffff",
           relief="flat", padx=16, pady=6)

tk.Button(btn_frame, text="Generate", command=generate, **BTN).pack(side="left", padx=6)
tk.Button(btn_frame, text="Copy",     command=copy_pwd, **BTN).pack(side="left", padx=6)
tk.Button(btn_frame, text="Close",    command=root.destroy, **BTN).pack(side="left", padx=6)

generate()

root.mainloop()
