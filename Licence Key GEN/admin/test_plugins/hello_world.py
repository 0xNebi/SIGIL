import tkinter as tk
import datetime

root = tk.Tk()
root.title("Hello from SIGIL Plugin")
root.geometry("340x180")
root.resizable(False, False)
root.configure(bg="#0a0a14")
root.lift()
root.attributes("-topmost", True)
root.focus_force()

user = globals().get("SIGIL_USER", "unknown")
ts   = datetime.datetime.now().strftime("%H:%M:%S")

tk.Label(root, text="Plugin System — OK",
         font=("Arial", 16, "bold"), fg="#7af0a0", bg="#0a0a14").pack(pady=(20, 6))
tk.Label(root, text=f"Launched for user:  {user}",
         font=("Arial", 12), fg="#c8c8ff", bg="#0a0a14").pack()
tk.Label(root, text=f"Loaded at:  {ts}",
         font=("Arial", 11), fg="#888899", bg="#0a0a14").pack()
tk.Label(root, text="[hello_world plugin]",
         font=("Arial", 9), fg="#444466", bg="#0a0a14").pack(pady=(12, 0))

tk.Button(root, text="Close", command=root.destroy,
          bg="#1a1a2e", fg="#c8c8ff", relief="flat", padx=20).pack(pady=12)

root.mainloop()
