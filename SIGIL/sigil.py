import sys
import os
import math
import ctypes
import ctypes.wintypes
import uuid
import pygame
from pygame.math import Vector2
import pygame_gui
import hashlib
import random
import string
import time
import json
import subprocess
import base64
import hmac
import bcrypt
import pyperclip
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

if getattr(sys, 'frozen', False):

    BUNDLE_DIR   = sys._MEIPASS
    INSTALL_DIR  = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR   = os.path.dirname(os.path.abspath(__file__))
    INSTALL_DIR  = os.path.dirname(os.path.abspath(__file__))

ASSETS_DIR      = os.path.join(BUNDLE_DIR,  "src", "assets")
PUBLIC_KEY_FILE = os.path.join(BUNDLE_DIR,  "src", "config", "public_key.pem")

CONFIG_DIR = os.path.join(INSTALL_DIR, "src", "config")
SALT_FILE  = os.path.join(INSTALL_DIR, "src", "config", "app.salt")
USERS_FILE = os.path.join(INSTALL_DIR, "src", "config", "users.enc")

EXPECTED_PUBLIC_KEY_HASH = "acffa89ddf26d89a30d2ad280e2747bad15ff4d8160770e8b9ed6e4f45844f9e"

HMAC_SIZE = 32

PLUGINS_DIR = os.path.join(INSTALL_DIR, "plugins")

WIDTH, HEIGHT = 350, 500
TITLE_BAR_HEIGHT = 30
FOOTER_HEIGHT = 60
CENTER = Vector2(WIDTH / 2, HEIGHT / 2)
HEX_RADIUS = 120

def compute_file_hash(filepath: str):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def check_public_key() -> bool:
    if not os.path.exists(PUBLIC_KEY_FILE):
        print("[SIGIL] FATAL: public_key.pem not found.")
        return False
    if compute_file_hash(PUBLIC_KEY_FILE) != EXPECTED_PUBLIC_KEY_HASH:
        print("[SIGIL] FATAL: public_key.pem has been modified — aborting.")
        return False
    return True

def _load_or_create_salt() -> bytes:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(32)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def derive_master_key(hwid: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(hwid.encode()))

def load_users(master_key: bytes) -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "rb") as f:
        data = f.read()
    if len(data) < HMAC_SIZE:
        raise ValueError("users.enc is malformed — file too short")
    stored_mac = data[:HMAC_SIZE]
    encrypted  = data[HMAC_SIZE:]
    raw_key    = base64.urlsafe_b64decode(master_key)
    expected_mac = hmac.new(raw_key, encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("INTEGRITY FAILURE — users.enc has been tampered with")
    return json.loads(Fernet(master_key).decrypt(encrypted).decode())

def save_users(users: dict, master_key: bytes) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    encrypted = Fernet(master_key).encrypt(json.dumps(users).encode())
    raw_key = base64.urlsafe_b64decode(master_key)
    mac = hmac.new(raw_key, encrypted, hashlib.sha256).digest()
    with open(USERS_FILE, "wb") as f:
        f.write(mac + encrypted)

_HWID_JUNK = {"", "none", "to be filled by o.e.m.", "n/a", "default string",
               "not specified", "unknown", "chassis manufacture"}

def get_hwid() -> str:
    parts = []

    ps_script = (
        "(Get-WmiObject Win32_Processor | Select-Object -First 1).Name;"
        "(Get-WmiObject Win32_DiskDrive | Select-Object -First 1).SerialNumber;"
        "(Get-WmiObject Win32_BaseBoard | Select-Object -First 1).SerialNumber"
    )
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_script],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in out.splitlines():
            val = line.strip()
            if val.lower() not in _HWID_JUNK:
                parts.append(val)
    except Exception:
        pass

    try:
        mac = hex(uuid.getnode())
        if mac not in _HWID_JUNK:
            parts.append(mac)
    except Exception:
        pass

    if len(parts) < 2:
        print(f"HWID Warning: only {len(parts)} source(s) succeeded — fingerprint may be weak")
        if not parts:
            return None

    combined = "|".join(parts)
    return hashlib.sha256(combined.encode()).hexdigest()

def generate_session_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def generate_control_value():
    timestamp = int(time.time())
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    data_to_hash = f"{timestamp}{random_string}".encode()
    hashed_value = hashlib.sha256(data_to_hash).hexdigest()
    return hashed_value[:16]

def verify_license(license_key: str, data: str) -> bool:
    try:
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        public_key.verify(
            bytes.fromhex(license_key),
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def _validate_password(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None

def save_user(username: str, password: str, license_key: str,
              master_key: bytes, hwid: str) -> bool:
    users = load_users(master_key)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "password": pw_hash,
        "license": license_key,
        "hwid": hwid,
    }
    save_users(users, master_key)
    return True

_PLUGIN_MAGIC   = b"SGPL"
_PLUGIN_VERSION = 2
_SIG_SIZE       = 256
_NONCE_SIZE     = 32

def _plugin_fernet_key(nonce: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(EXPECTED_PUBLIC_KEY_HASH.encode()))

def load_plugin(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()

    min_size = 4 + 4 + _NONCE_SIZE + _SIG_SIZE + 1
    if len(data) < min_size:
        raise ValueError(f"Plugin too small to be valid: {path}")

    magic   = data[:4]
    version = int.from_bytes(data[4:8], "little")
    nonce   = data[8:8 + _NONCE_SIZE]
    sig     = data[8 + _NONCE_SIZE: 8 + _NONCE_SIZE + _SIG_SIZE]
    enc_src = data[8 + _NONCE_SIZE + _SIG_SIZE:]

    if magic != _PLUGIN_MAGIC:
        raise ValueError("Invalid plugin: wrong magic bytes")
    if version != _PLUGIN_VERSION:
        raise ValueError(f"Unsupported plugin version: {version}")

    signed_data = magic + data[4:8] + nonce + enc_src
    try:
        with open(PUBLIC_KEY_FILE, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        pub_key.verify(
            sig, signed_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("Plugin signature invalid — plugin is not authentic or has been tampered with")

    try:
        source = Fernet(_plugin_fernet_key(nonce)).decrypt(enc_src).decode()
    except Exception:
        raise ValueError("Plugin decryption failed")

    return source

def _find_python() -> str:
    return sys.executable

def run_plugin(source: str, username: str) -> None:
    import threading

    if getattr(sys, 'frozen', False):

        encoded = base64.b64encode(source.encode('utf-8')).decode('ascii')
        cmd = [sys.executable, '--run-plugin', encoded,
               '--plugin-user', username]
        tmp_path = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to launch plugin: {e}")
    else:

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                         delete=False, encoding='utf-8') as tf:
            tf.write(f'SIGIL_USER = {username!r}\n')
            tf.write(source)
            tmp_path = tf.name
        try:
            proc = subprocess.Popen(
                [sys.executable, tmp_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            os.remove(tmp_path)
            raise RuntimeError(f"Failed to launch plugin: {e}")

    def _monitor():
        try:
            _, stderr = proc.communicate(timeout=30)
            if proc.returncode and proc.returncode != 0:
                err = stderr.decode(errors='replace').strip()
                if err:
                    push_toast(f'Plugin error: {err[:80]}', duration=6.0)
        except Exception:
            pass
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    threading.Thread(target=_monitor, daemon=True).start()

def scan_plugins() -> list[tuple[str, str]]:
    if not os.path.isdir(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        return []
    results = []
    for fname in sorted(os.listdir(PLUGINS_DIR)):
        if fname.lower().endswith(".sgp"):
            results.append((fname[:-4], os.path.join(PLUGINS_DIR, fname)))
    return results

def blur_surface(surface, amt):
    scale = 1.0 / amt
    surf_size = surface.get_size()
    scaled_size = (max(1, int(surf_size[0] * scale)), max(1, int(surf_size[1] * scale)))
    surface = pygame.transform.smoothscale(surface, scaled_size)
    surface = pygame.transform.smoothscale(surface, surf_size)
    return surface

def get_global_mouse_pos():
    pt = ctypes.wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y

def draw_title_bar(surface, icon_img):
    title_bar_rect = pygame.Rect(0, 0, WIDTH, TITLE_BAR_HEIGHT)
    pygame.draw.rect(surface, (30, 30, 30), title_bar_rect)
    icon_size = TITLE_BAR_HEIGHT - 4
    icon_scaled = pygame.transform.smoothscale(icon_img, (icon_size, icon_size))
    surface.blit(icon_scaled, (2, 2))
    font = pygame.font.SysFont('Arial', 20)
    text_surface = font.render("SIGIL", True, (255, 255, 255))
    text_rect = text_surface.get_rect(center=(WIDTH // 2, TITLE_BAR_HEIGHT // 2))
    surface.blit(text_surface, text_rect)

def draw_background(surface, t):
    surface.fill((10, 10, 20))
    num_layers = 4
    for i in range(num_layers):
        radius = HEX_RADIUS + 50 * i + 20 * math.sin(t + i)
        rotation = t * (0.1 + 0.05 * i) * (1 if i % 2 == 0 else -1)
        vertices = []
        for j in range(6):
            angle = math.radians(60 * j) + rotation
            vertex = CENTER + Vector2(math.cos(angle), math.sin(angle)) * radius
            vertices.append(vertex)
        polygon_surface = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)
        alpha = 50 - i * 5
        color = (20 + i * 20, 20 + i * 20, 50 + i * 20, alpha)
        pygame.draw.polygon(polygon_surface, color, vertices, 0)
        surface.blit(polygon_surface, (0, 0))
    for i in range(5):
        angle = t * 0.5 + i * 1.2
        pos = CENTER + Vector2(math.cos(angle), math.sin(angle)) * (HEX_RADIUS + 100 + 30 * math.sin(t + i))
        radius = 30 + 10 * math.sin(t * 1.5 + i)
        circle_surface = pygame.Surface((radius * 2, radius * 2), pygame.SRCALPHA)
        pygame.draw.circle(circle_surface, (50, 50, 100, 80), (radius, radius), radius)
        surface.blit(circle_surface, (pos.x - radius, pos.y - radius))

class CustomButton:
    def __init__(self, rect, text, callback, font=None,
                 text_color=(255, 255, 255), hover_text_color=(200, 200, 200),
                 bg_color=(0, 0, 0), bg_alpha=30):
        self.rect = pygame.Rect(rect)
        self.text = text
        self.callback = callback
        self.font = font or pygame.font.SysFont('Arial', 20)
        self.text_color = text_color
        self.hover_text_color = hover_text_color
        self.bg_color = bg_color
        self.bg_alpha = bg_alpha
        self.hover = False

    def draw(self, surface):
        bg_surface = pygame.Surface(self.rect.size, pygame.SRCALPHA)
        bg_surface.fill((*self.bg_color, self.bg_alpha))
        surface.blit(bg_surface, self.rect.topleft)
        color = self.hover_text_color if self.hover else self.text_color
        text_surf = self.font.render(self.text, True, color)
        text_rect = text_surf.get_rect(center=self.rect.center)
        surface.blit(text_surf, text_rect)

    def handle_event(self, event):
        if event.type == pygame.MOUSEMOTION:
            self.hover = self.rect.collidepoint(event.pos)
        elif event.type == pygame.MOUSEBUTTONDOWN:
            if event.button == 1 and self.rect.collidepoint(event.pos):
                if self.callback:
                    self.callback()

class Toast:

    FONT: pygame.font.Font | None = None
    PADDING = 8

    def __init__(self, message: str, duration: float = 3.0,
                 bg: tuple = (30, 30, 55), fg: tuple = (230, 230, 255)):
        self.message  = message
        self.duration = duration
        self.bg       = bg
        self.fg       = fg
        self._born    = time.time()

    @property
    def alpha(self) -> int:
        remaining = self.duration - (time.time() - self._born)
        if remaining < 0:
            return 0
        if remaining < 0.5:
            return int(220 * (remaining / 0.5))
        return 220

    @property
    def expired(self) -> bool:
        return time.time() - self._born >= self.duration

    def render(self, surface: pygame.Surface, x: int, y: int) -> int:
        if Toast.FONT is None:
            Toast.FONT = pygame.font.SysFont("Arial", 14)
        font = Toast.FONT
        p    = Toast.PADDING
        words = self.message.split()
        lines: list[str] = []
        current = ""
        for w in words:
            test = (current + " " + w).strip()
            if font.size(test)[0] > 190:
                if current:
                    lines.append(current)
                current = w
            else:
                current = test
        if current:
            lines.append(current)

        line_h  = font.get_linesize()
        total_h = p * 2 + line_h * len(lines)
        bg_surf = pygame.Surface((200, total_h), pygame.SRCALPHA)
        bg_surf.fill((*self.bg, self.alpha))
        surface.blit(bg_surf, (x, y))

        for i, line in enumerate(lines):
            txt = font.render(line, True, self.fg)
            txt.set_alpha(self.alpha)
            surface.blit(txt, (x + p, y + p + i * line_h))
        return total_h

_toasts: list[Toast] = []

def push_toast(message: str, duration: float = 3.0) -> None:
    _toasts.append(Toast(message, duration))
    if len(_toasts) > 5:
        _toasts.pop(0)

def draw_toasts(surface: pygame.Surface) -> None:
    _toasts[:] = [t for t in _toasts if not t.expired]
    right_x = WIDTH - 210
    y = TITLE_BAR_HEIGHT + 5
    for toast in list(_toasts):
        h = toast.render(surface, right_x, y)
        y += h + 4

def main():
    pygame.init()

    if not check_public_key():
        pygame.quit()
        return

    hwid = get_hwid()
    if not hwid:
        print("[SIGIL] FATAL: could not build hardware fingerprint.")
        pygame.quit()
        return

    salt       = _load_or_create_salt()
    master_key = derive_master_key(hwid, salt)

    try:
        credentials = load_users(master_key)
    except ValueError as e:
        print(f"[SIGIL] FATAL: {e}")
        pygame.quit()
        return

    session_id    = generate_session_id()
    control_value = generate_control_value()
    client_id     = hwid
    admin_logged_in  = False
    logged_in_user   = None

    _login_state: dict[str, list] = {}

    try:
        icon_path = os.path.join(ASSETS_DIR, "sigil_logo.png")
        icon = pygame.image.load(icon_path)
    except Exception as e:
        print("Error loading icon:", e)
        icon = pygame.Surface((TITLE_BAR_HEIGHT - 4, TITLE_BAR_HEIGHT - 4))
    pygame.display.set_icon(icon)
    pygame.display.set_caption("SIGIL")
    window_surface = pygame.display.set_mode((WIDTH, HEIGHT), pygame.NOFRAME)
    clock = pygame.time.Clock()
    theme_path = os.path.join(BUNDLE_DIR, "src", "config", "theme.json")
    manager = pygame_gui.UIManager((WIDTH, HEIGHT), theme_path if os.path.exists(theme_path) else None)

    popup_window = None

    def show_message(title, message):
        nonlocal popup_window
        if popup_window is not None:
            popup_window.focus()
            return
        popup_window = pygame_gui.windows.UIMessageWindow(
            rect=pygame.Rect((WIDTH//2 - 150, HEIGHT//2 - 100), (300, 200)),
            html_message=message,
            window_title=title,
            manager=manager
        )
        popup_window.set_blocking(True)

    is_running = True
    can_drag = sys.platform == "win32"
    wm_info = pygame.display.get_wm_info()
    hwnd = wm_info.get('window') if can_drag else None

    def on_close():
        nonlocal is_running
        is_running = False

    def on_minimize():
        if can_drag:
            ctypes.windll.user32.ShowWindow(hwnd, 6)

    title_bar_buttons = [
        CustomButton(rect=(WIDTH - 30, 0, 30, TITLE_BAR_HEIGHT), text="X", callback=on_close),
        CustomButton(rect=(WIDTH - 60, 0, 30, TITLE_BAR_HEIGHT), text="―", callback=on_minimize)
    ]

    login_panel = pygame_gui.elements.UIPanel(
        relative_rect=pygame.Rect((WIDTH // 2 - 150, HEIGHT // 2 - 120), (300, 240)),
        starting_height=1,
        manager=manager
    )
    login_panel.image.fill((0, 0, 0, 30))

    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((75, 10), (150, 30)),
        text="Login",
        manager=manager,
        container=login_panel
    )
    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 50), (80, 30)),
        text="Username:",
        manager=manager,
        container=login_panel
    )
    username_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 50), (170, 30)),
        manager=manager,
        container=login_panel
    )
    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 90), (80, 30)),
        text="Password:",
        manager=manager,
        container=login_panel
    )
    password_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 90), (170, 30)),
        manager=manager,
        container=login_panel
    )
    password_entry.set_text_hidden(True)

    def on_login():
        nonlocal admin_logged_in, credentials, logged_in_user

        if not check_public_key():
            show_message("Error", "Key integrity check failed — aborting.")
            pygame.quit()
            return

        username = username_entry.get_text().strip()
        password = password_entry.get_text()

        if username.lower() == "admin":
            if admin_logged_in:
                show_message("Error", "Admin already authenticated this session.")
                return
            if verify_license(password, session_id + control_value):
                admin_logged_in = True
                show_message("Admin", "Admin login successful.")
            else:
                show_message("Error", "Invalid admin licence key.")
            return

        now = time.time()
        state = _login_state.setdefault(username, [0, 0.0])
        if now < state[1]:
            remaining = int(state[1] - now)
            show_message("Locked", f"Too many failed attempts.\nTry again in {remaining}s.")
            return

        if username not in credentials:
            show_message("Error", "User not found.")
            state[0] += 1
            return

        record       = credentials[username]
        stored_hwid  = record["hwid"]
        stored_hash  = record["password"].encode()

        if stored_hwid != hwid:
            show_message("Error", "This account is not registered on this machine.")
            return

        if bcrypt.checkpw(password.encode(), stored_hash):
            state[0] = 0
            logged_in_user = username
            welcome_label.set_text(f"Welcome,  {username}")
            login_panel.hide()
            dashboard_panel.show()
            refresh_plugins()
        else:
            state[0] += 1
            if state[0] >= 3:
                state[1] = now + 30.0
                show_message("Locked", "3 failed attempts — account locked for 30 seconds.")
            else:
                remaining_attempts = 3 - state[0]
                show_message("Error", f"Incorrect password.\n{remaining_attempts} attempt(s) remaining.")

    def on_switch_to_register():
        login_panel.hide()
        registration_panel.show()

    login_container_rect = login_panel.get_container().get_abs_rect()
    login_panel_buttons = [
        CustomButton(
            rect=(login_container_rect.x + 20, login_container_rect.y + 140, 120, 40),
            text="Login",
            callback=on_login
        ),
        CustomButton(
            rect=(login_container_rect.x + 160, login_container_rect.y + 140, 120, 40),
            text="Register",
            callback=on_switch_to_register
        )
    ]

    registration_panel = pygame_gui.elements.UIPanel(
        relative_rect=pygame.Rect((WIDTH // 2 - 150, HEIGHT // 2 - 160), (300, 320)),
        starting_height=1,
        manager=manager
    )
    registration_panel.image.fill((0, 0, 0, 30))
    registration_panel.hide()

    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((75, 10), (150, 30)),
        text="Register",
        manager=manager,
        container=registration_panel
    )
    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 50), (80, 30)),
        text="Username:",
        manager=manager,
        container=registration_panel
    )
    reg_username_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 50), (170, 30)),
        manager=manager,
        container=registration_panel
    )
    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 90), (80, 30)),
        text="Password:",
        manager=manager,
        container=registration_panel
    )
    reg_password_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 90), (170, 30)),
        manager=manager,
        container=registration_panel
    )
    reg_password_entry.set_text_hidden(True)
    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 130), (80, 30)),
        text="Confirm:",
        manager=manager,
        container=registration_panel
    )
    reg_confirm_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 130), (170, 30)),
        manager=manager,
        container=registration_panel
    )
    reg_confirm_entry.set_text_hidden(True)

    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 170), (100, 30)),
        text="Licence Key:",
        manager=manager,
        container=registration_panel
    )
    reg_license_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 170), (170, 30)),
        manager=manager,
        container=registration_panel
    )

    pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((20, 210), (80, 30)),
        text="HWID:",
        manager=manager,
        container=registration_panel
    )
    client_id_entry = pygame_gui.elements.UITextEntryLine(
        relative_rect=pygame.Rect((110, 210), (170, 30)),
        manager=manager,
        container=registration_panel
    )
    client_id_entry.set_text(client_id)
    client_id_entry.disable()

    def on_register():
        nonlocal credentials
        username    = reg_username_entry.get_text().strip()
        password    = reg_password_entry.get_text()
        confirm     = reg_confirm_entry.get_text()
        license_key = reg_license_entry.get_text().strip()

        if username.lower() == "admin":
            show_message("Error", "Username 'admin' is reserved.")
            return
        if not username or not password or not license_key:
            show_message("Error", "All fields are required.")
            return
        if password != confirm:
            show_message("Error", "Passwords do not match.")
            return

        pw_error = _validate_password(password)
        if pw_error:
            show_message("Weak Password", pw_error)
            return

        if not verify_license(license_key, hwid):
            show_message("Error", "Invalid licence key for this machine.")
            return

        if username in credentials:
            show_message("Error", "Username already registered.")
            return

        save_user(username, password, license_key, master_key, hwid)
        show_message("Success", "Registration successful! You may now log in.")
        reg_username_entry.set_text("")
        reg_password_entry.set_text("")
        reg_confirm_entry.set_text("")
        reg_license_entry.set_text("")
        registration_panel.hide()
        login_panel.show()
        credentials = load_users(master_key)

    def on_reg_back():
        registration_panel.hide()
        login_panel.show()

    reg_container_rect = registration_panel.get_container().get_abs_rect()
    registration_panel_buttons = [
        CustomButton(
            rect=(reg_container_rect.x + 20, reg_container_rect.y + 260, 120, 40),
            text="Register",
            callback=on_register
        ),
        CustomButton(
            rect=(reg_container_rect.x + 160, reg_container_rect.y + 260, 120, 40),
            text="Back",
            callback=on_reg_back
        )
    ]

    DASH_X, DASH_Y = 15, 45
    DASH_W, DASH_H = 320, 370

    dashboard_panel = pygame_gui.elements.UIPanel(
        relative_rect=pygame.Rect((DASH_X, DASH_Y), (DASH_W, DASH_H)),
        starting_height=1,
        manager=manager
    )
    dashboard_panel.image.fill((0, 0, 0, 30))
    dashboard_panel.hide()

    welcome_label = pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((10, 10), (300, 30)),
        text="Welcome",
        manager=manager,
        container=dashboard_panel
    )
    plugins_title = pygame_gui.elements.UILabel(
        relative_rect=pygame.Rect((10, 50), (300, 25)),
        text="— Plugins —",
        manager=manager,
        container=dashboard_panel
    )

    _plugin_entries: list[tuple[str, str]] = []
    _plugin_buttons: list[CustomButton]    = []
    _plugin_error_labels: list[str]        = []
    PLUGIN_BTN_Y0 = DASH_Y + 90
    PLUGIN_BTN_H  = 36
    PLUGIN_BTN_GAP = 4
    PLUGIN_MAX_VISIBLE = 6

    def _build_plugin_buttons() -> None:
        _plugin_buttons.clear()
        _plugin_error_labels.clear()
        for i, (name, path) in enumerate(_plugin_entries[:PLUGIN_MAX_VISIBLE]):
            y = PLUGIN_BTN_Y0 + i * (PLUGIN_BTN_H + PLUGIN_BTN_GAP)

            ok = True
            try:
                load_plugin(path)
            except ValueError:
                ok = False
            status = "▶" if ok else "✗"
            label  = f"{status}  {name[:22]}"
            _plugin_error_labels.append("" if ok else "Invalid signature / tampered")

            def _make_cb(p, valid):
                def _cb():
                    if not valid:
                        show_message("Plugin Error",
                                     "This plugin failed signature verification\nand cannot be run.")
                        return
                    try:
                        src = load_plugin(p)
                        run_plugin(src, logged_in_user or "?")
                        push_toast(f"▶ {p.rpartition(os.sep)[2][:-4]} launched")
                    except Exception as exc:
                        show_message("Plugin Error", str(exc))
                return _cb

            _plugin_buttons.append(CustomButton(
                rect=(DASH_X + 10, y, DASH_W - 20, PLUGIN_BTN_H),
                text=label,
                callback=_make_cb(path, ok),
                font=pygame.font.SysFont("Arial", 16),
                bg_color=(20, 20, 40),
                bg_alpha=120,
            ))

    def refresh_plugins() -> None:
        _plugin_entries.clear()
        _plugin_entries.extend(scan_plugins())
        _build_plugin_buttons()
        count = len(_plugin_entries)
        plugins_title.set_text(f"— {count} Plugin{'s' if count != 1 else ''} —")

    DASH_BTN_Y = DASH_Y + DASH_H - 10

    def on_logout() -> None:
        nonlocal logged_in_user
        logged_in_user = None
        dashboard_panel.hide()
        login_panel.show()
        username_entry.set_text("")
        password_entry.set_text("")

    dashboard_buttons = [
        CustomButton(
            rect=(DASH_X + 10,       DASH_BTN_Y, 140, 38),
            text="⟳  Refresh",
            callback=refresh_plugins,
        ),
        CustomButton(
            rect=(DASH_X + DASH_W - 150, DASH_BTN_Y, 140, 38),
            text="Logout",
            callback=on_logout,
        ),
    ]

    def on_copy_client_id():
        try:
            pyperclip.copy(client_id)
            push_toast("HWID copied to clipboard")
        except Exception as e:
            show_message("Error", f"Clipboard copy failed: {e}")

    footer_button = CustomButton(
        rect=(10, HEIGHT - FOOTER_HEIGHT + 10, 100, 40),
        text="░░░░",
        callback=on_copy_client_id
    )
    footer_buttons = [footer_button]

    footer_label_text = client_id[:16] + "..."

    dragging = False
    drag_offset = (0, 0)

    time_delta = 0.0
    start_time = pygame.time.get_ticks() / 1000.0

    while is_running:
        current_time = pygame.time.get_ticks() / 1000.0
        t = current_time - start_time

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                is_running = False

            if can_drag:
                if event.type == pygame.MOUSEBUTTONDOWN:
                    if event.button == 1 and event.pos[1] < TITLE_BAR_HEIGHT and event.pos[0] < WIDTH - 60:
                        dragging = True
                        mouse_global = get_global_mouse_pos()
                        window_pos = pygame.display.get_window_position()
                        drag_offset = (mouse_global[0] - window_pos[0], mouse_global[1] - window_pos[1])
                elif event.type == pygame.MOUSEBUTTONUP:
                    if event.button == 1:
                        dragging = False
                elif event.type == pygame.MOUSEMOTION and dragging:
                    mouse_global = get_global_mouse_pos()
                    new_x = mouse_global[0] - drag_offset[0]
                    new_y = mouse_global[1] - drag_offset[1]
                    ctypes.windll.user32.MoveWindow(hwnd, new_x, new_y, WIDTH, HEIGHT, True)

            manager.process_events(event)
            if event.type == pygame_gui.UI_WINDOW_CLOSE:
                if hasattr(event, 'ui_element') and event.ui_element == popup_window:
                    popup_window = None

            for button in title_bar_buttons:
                button.handle_event(event)
            if login_panel.visible:
                for button in login_panel_buttons:
                    button.handle_event(event)
            if registration_panel.visible:
                for button in registration_panel_buttons:
                    button.handle_event(event)
            if dashboard_panel.visible:
                for button in dashboard_buttons:
                    button.handle_event(event)
                for button in _plugin_buttons:
                    button.handle_event(event)
            for button in footer_buttons:
                button.handle_event(event)

        manager.update(time_delta)
        draw_background(window_surface, t)

        if login_panel.visible:
            panel_rect = login_panel.relative_rect
            panel_background = window_surface.subsurface(panel_rect).copy()
            blurred = blur_surface(panel_background, 10)
            window_surface.blit(blurred, panel_rect.topleft)
        if registration_panel.visible:
            panel_rect = registration_panel.relative_rect
            panel_background = window_surface.subsurface(panel_rect).copy()
            blurred = blur_surface(panel_background, 10)
            window_surface.blit(blurred, panel_rect.topleft)
        if dashboard_panel.visible:
            panel_rect = dashboard_panel.relative_rect
            panel_background = window_surface.subsurface(panel_rect).copy()
            blurred = blur_surface(panel_background, 10)
            window_surface.blit(blurred, panel_rect.topleft)
        footer_rect = pygame.Rect(0, HEIGHT - FOOTER_HEIGHT, WIDTH, FOOTER_HEIGHT)
        footer_background = window_surface.subsurface(footer_rect).copy()
        footer_blurred = blur_surface(footer_background, 20)
        window_surface.blit(footer_blurred, footer_rect.topleft)
        glass_overlay = pygame.Surface(footer_rect.size, pygame.SRCALPHA)
        glass_overlay.fill((30, 30, 30, 20))
        window_surface.blit(glass_overlay, footer_rect.topleft)

        label_font = pygame.font.SysFont('Arial', 20)
        label_surface = label_font.render(footer_label_text, True, (255, 255, 255))
        label_x = footer_button.rect.right + 30
        label_y = footer_button.rect.centery - label_surface.get_height() // 2
        window_surface.blit(label_surface, (label_x, label_y))

        draw_title_bar(window_surface, icon)
        for button in title_bar_buttons:
            button.draw(window_surface)
        if login_panel.visible:
            for button in login_panel_buttons:
                button.draw(window_surface)
        if registration_panel.visible:
            for button in registration_panel_buttons:
                button.draw(window_surface)
        if dashboard_panel.visible:
            for button in dashboard_buttons:
                button.draw(window_surface)
            for button in _plugin_buttons:
                button.draw(window_surface)
        for button in footer_buttons:
            button.draw(window_surface)

        manager.draw_ui(window_surface)
        draw_toasts(window_surface)

        pygame.display.update()
        time_delta = clock.tick(60) / 1000.0

    pygame.quit()

if __name__ == '__main__':

    if '--run-plugin' in sys.argv:
        try:
            idx = sys.argv.index('--run-plugin')
            encoded_source = sys.argv[idx + 1]
            plugin_source  = base64.b64decode(encoded_source).decode('utf-8')

            plugin_user = 'unknown'
            if '--plugin-user' in sys.argv:
                uidx = sys.argv.index('--plugin-user')
                if uidx + 1 < len(sys.argv):
                    plugin_user = sys.argv[uidx + 1]

            exec_globals = {
                '__name__'    : '__main__',
                'SIGIL_USER': plugin_user,
            }
            exec(plugin_source, exec_globals)
        except (IndexError, ValueError) as e:
            print(f'[SIGIL] Plugin runner argument error: {e}', file=sys.stderr)
            sys.exit(1)
        except SystemExit:
            pass
        except Exception as e:
            import traceback
            print(f'[SIGIL] Plugin runtime error: {e}', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    main()
