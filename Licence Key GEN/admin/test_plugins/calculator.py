import tkinter as tk

BUTTON_STYLE = dict(font=("Arial", 14), bg="#1a1a2e", fg="#c8c8ff",
                    activebackground="#2a2a4e", activeforeground="#ffffff",
                    relief="flat", width=5, height=2)

root = tk.Tk()
root.title("Calculator Plugin")
root.geometry("280x380")
root.resizable(False, False)
root.configure(bg="#0a0a14")
root.lift()
root.attributes("-topmost", True)
root.focus_force()

user = globals().get("SIGIL_USER", "unknown")
expression = ""

display_var = tk.StringVar(value="0")

def update_display(val: str) -> None:
    display_var.set(val[-18:] if len(val) > 18 else val)

def on_press(char: str) -> None:
    global expression
    if char == "C":
        expression = ""
        update_display("0")
        return
    if char == "=":
        try:
            result = eval(expression, {"__builtins__": {}})
            expression = str(result)
        except Exception:
            expression = "Error"
        update_display(expression)
        return
    if char == "⌫":
        expression = expression[:-1]
        update_display(expression or "0")
        return
    expression += char
    update_display(expression)

tk.Label(root, text=f"[{user}]", font=("Arial", 9), fg="#444466", bg="#0a0a14").pack(anchor="e", padx=8)

disp = tk.Label(root, textvariable=display_var, font=("Arial", 22, "bold"),
                fg="#7af0a0", bg="#111124", anchor="e", padx=10)
disp.pack(fill="x", padx=8, pady=(0, 6), ipady=10)

buttons = [
    ["7", "8", "9", "/"],
    ["4", "5", "6", "*"],
    ["1", "2", "3", "-"],
    ["0", ".", "=", "+"],
    ["C", "⌫", "(", ")"],
]

for row in buttons:
    frame = tk.Frame(root, bg="#0a0a14")
    frame.pack(pady=2)
    for ch in row:
        color = "#2a1a3e" if ch in ("=", "C") else "#1a1a2e"
        btn = tk.Button(frame, text=ch, command=lambda c=ch: on_press(c),
                        **{**BUTTON_STYLE, "bg": color})
        btn.pack(side="left", padx=2)

root.mainloop()
