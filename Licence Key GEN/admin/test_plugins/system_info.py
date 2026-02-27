import tkinter as tk
import platform
import os
import socket

root = tk.Tk()
root.title("System Info")
root.geometry("400x260")
root.resizable(False, False)
root.configure(bg="#0a0a14")
root.lift()
root.attributes("-topmost", True)
root.focus_force()

user = globals().get("SIGIL_USER", "unknown")

rows = [
    ("SIGIL user",  user),
    ("Hostname",      socket.gethostname()),
    ("OS",            platform.system() + " " + platform.release()),
    ("Architecture",  platform.machine()),
    ("Python",        platform.python_version()),
    ("CPU cores",     str(os.cpu_count())),
]

tk.Label(root, text="System Info Plugin",
         font=("Arial", 14, "bold"), fg="#7af0a0", bg="#0a0a14").pack(pady=(14, 8))

frame = tk.Frame(root, bg="#0a0a14")
frame.pack(padx=20, fill="x")

for label, value in rows:
    row = tk.Frame(frame, bg="#0a0a14")
    row.pack(fill="x", pady=1)
    tk.Label(row, text=f"{label}:", width=16, anchor="w",
             font=("Arial", 10), fg="#888899", bg="#0a0a14").pack(side="left")
    tk.Label(row, text=value, anchor="w",
             font=("Arial", 10, "bold"), fg="#c8c8ff", bg="#0a0a14").pack(side="left")

tk.Button(root, text="Close", command=root.destroy,
          bg="#1a1a2e", fg="#c8c8ff", relief="flat", padx=20).pack(pady=14)

root.mainloop()
