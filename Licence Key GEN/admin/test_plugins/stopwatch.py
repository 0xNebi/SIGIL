import tkinter as tk
import time

user = globals().get("SIGIL_USER", "unknown")

root = tk.Tk()
root.title("Stopwatch")
root.geometry("300x360")
root.resizable(False, False)
root.configure(bg="#0a0a14")
root.lift()
root.attributes("-topmost", True)
root.focus_force()

_running   = False
_start_ts  = 0.0
_elapsed   = 0.0
_laps: list[str] = []

tk.Label(root, text="Stopwatch",
         font=("Arial", 14, "bold"), fg="#7af0a0", bg="#0a0a14").pack(pady=(14, 2))
tk.Label(root, text=f"User: {user}",
         font=("Arial", 9), fg="#444466", bg="#0a0a14").pack()

time_var = tk.StringVar(value="00:00.000")
tk.Label(root, textvariable=time_var,
         font=("Courier New", 30, "bold"), fg="#c8c8ff", bg="#0a0a14").pack(pady=(10, 0))

lap_frame = tk.Frame(root, bg="#0e0e1c", bd=0)
lap_frame.pack(fill="both", padx=20, pady=8, expand=True)
lap_box = tk.Listbox(lap_frame, font=("Courier New", 10),
                     bg="#0e0e1c", fg="#888899", selectbackground="#1a1a2e",
                     relief="flat", height=6, highlightthickness=0, bd=0)
lap_box.pack(fill="both", expand=True)

def _fmt(secs: float) -> str:
    mins = int(secs // 60)
    s    = secs % 60
    return f"{mins:02d}:{s:06.3f}"

def _tick():
    if _running:
        total = _elapsed + (time.perf_counter() - _start_ts)
        time_var.set(_fmt(total))
        root.after(33, _tick)

def start_stop():
    global _running, _start_ts, _elapsed
    if _running:
        _elapsed += time.perf_counter() - _start_ts
        _running  = False
        btn_start.config(text="Start")
    else:
        _start_ts = time.perf_counter()
        _running  = True
        btn_start.config(text="Stop")
        _tick()

def lap():
    if not _running:
        return
    total = _elapsed + (time.perf_counter() - _start_ts)
    lap_box.insert(tk.END, f"  Lap {lap_box.size()+1:>2}    {_fmt(total)}")
    lap_box.see(tk.END)

def reset():
    global _running, _elapsed
    _running = False
    _elapsed = 0.0
    time_var.set("00:00.000")
    btn_start.config(text="Start")
    lap_box.delete(0, tk.END)

btn_frame = tk.Frame(root, bg="#0a0a14")
btn_frame.pack(pady=8)

BTN = dict(font=("Arial", 11), bg="#1a1a2e", fg="#c8c8ff",
           activebackground="#2a2a4e", activeforeground="#ffffff",
           relief="flat", padx=14, pady=6)

btn_start = tk.Button(btn_frame, text="Start", command=start_stop, **BTN)
btn_start.pack(side="left", padx=5)
tk.Button(btn_frame, text="Lap",   command=lap,     **BTN).pack(side="left", padx=5)
tk.Button(btn_frame, text="Reset", command=reset,   **BTN).pack(side="left", padx=5)
tk.Button(btn_frame, text="Close", command=root.destroy, **BTN).pack(side="left", padx=5)

root.mainloop()
