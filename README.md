A secure, offline desktop application launcher for Windows.  
SIGIL lets you register as a user using a hardware-bound licence key, log in, and run signed plugin scripts — all through a clean, animated GUI with no browser or internet required.

---

## What does it do?

- **Hardware-locked accounts** — your account is tied to the machine you register on
- **Licence key registration** — an admin issues you a key signed to your specific hardware ID
- **Plugin launcher** — run signed `.sgp` plugin bundles directly from the dashboard
- **Encrypted user database** — all credentials are stored encrypted, with tamper detection
- **Offline** — everything runs locally, no network calls

---

## Requirements

- Windows 10 / 11
- Python 3.12+ (only needed if running from source)

---

## Running the Program

### Option A — Standalone EXE (recommended)

1. Download or build `SIGIL.exe` (see **Build** section below)
2. Place it in the same folder as the `src/` directory:
   ```
   SIGIL.exe
   src/
     assets/
     config/
       public_key.pem    ← required
   plugins/              ← place .sgp plugin files here
   ```
3. Double-click `SIGIL.exe` — the app window will open

### Option B — From source

```powershell
cd SIGIL
pip install -r requirements.txt
python SIGIL.py
```

---

## First-Time Setup (Admin)

Before any users can register, an admin must generate a keypair once:

```powershell
cd "Licence Key GEN/admin"
pip install -r ../requirements-admin.txt
python admin_tools.py
# Select option [1] Generate RSA Keypair
```

This creates:
- `private_key.pem` — **keep this secret, never share or commit it**
- `public_key.pem` — copy this to `SIGIL/src/config/public_key.pem`

Then update the `EXPECTED_PUBLIC_KEY_HASH` constant in `SIGIL.py` using option **[4] Hash Key** in admin tools.

---

## Registering as a New User

1. Run the application — the login screen appears
2. Click **Register**
3. Note your **HWID** shown in the registration form (64-character hex string)
4. Send your HWID to the admin
5. Admin runs `python admin_tools.py`, selects **[2] Generate Licence Key**, pastes your HWID, and sends you the licence key  
   *(the key is auto-copied to clipboard and saved to `last_licence.txt`)*
6. Enter your username, password (8+ chars, 1 uppercase, 1 digit), and paste the licence key
7. Click **Register** — on success, you can now log in

> Accounts are machine-specific. If you move to a different computer, you need a new licence key.

---

## Logging In

1. Enter your username and password on the login screen
2. Click **Login**
3. After 3 failed attempts, the account locks for 30 seconds

---

## Using the Dashboard

After login you'll see the plugin dashboard:

| Element | Description |
|---------|-------------|
| Plugin list | All `.sgp` files found in the `plugins/` folder |
| ▶ prefix | Plugin is valid and ready to run |
| ✗ prefix | Plugin signature is invalid — cannot be launched |
| ⟳ Refresh | Re-scan the plugins folder |
| Logout | Return to the login screen |
| Footer button | Copy your full HWID to clipboard |

Click a valid plugin button to launch it. It runs in a separate process, isolated from the main app.

---

## Plugins

Plugins are `.sgp` files — RSA-signed and encrypted Python scripts packaged by the admin.

To create a plugin:

```powershell
cd "Licence Key GEN/admin"
python admin_tools.py
# Select option [5] Sign Plugin, provide the path to your .py file
```

Place the resulting `.sgp` file in `SIGIL/plugins/` and click **Refresh** in the dashboard.

---

## Building the EXE

```powershell
cd SIGIL
.\build.ps1
```

Requires `pyinstaller` (`pip install pyinstaller`).  
Output: `dist/SIGIL.exe` (~63 MB, single file, no console window).

---

## Distribution Package (EXE)

When distributing to end users, create a zip containing exactly these files:

```
SIGIL/
  SIGIL.exe           ← the compiled executable
  src/
    assets/
      SIGIL_logo.png  ← app icon (displayed in title bar)
    config/
      public_key.pem    ← required for licence and plugin verification
  plugins/
    hello_world.sgp     ← example plugins (include as many or as few as you like)
    system_info.sgp
    calculator.sgp
    password_gen.sgp
    stopwatch.sgp
```

**Do NOT include:**
- `app.salt` — generated per-machine on first run
- `users.enc` — contains user account data
- `src/config/theme.json` — bundled inside the .exe automatically
- Any `private_key.pem` — must never leave the admin machine

---

## Security Notes

- `private_key.pem` must never be committed or shared
- `app.salt` is machine-generated — deleting it invalidates all user accounts on that machine
- `users.enc` is HMAC-verified and Fernet-encrypted — any modification causes a fatal error
- The master encryption key is derived at runtime from your hardware ID — nothing static is stored in the binary

---

## Project Structure

```
SIGIL/
  SIGIL.py          ← main application
  build.ps1           ← PyInstaller build script
  requirements.txt
  plugins/            ← .sgp plugin bundles go here
  src/
    assets/           ← logo
    config/
      public_key.pem  ← distributed with every build
      app.salt        ← auto-generated on first run (not committed)
      users.enc       ← encrypted user database (not committed)

Licence Key GEN/
  admin/
    admin_tools.py    ← unified admin CLI (key gen, licence gen, plugin signing)
    private_key.pem   ← SECRET — never commit
    public_key.pem    ← copy to SIGIL/src/config/
  requirements-admin.txt

docs/                 ← architecture, development guide, security audit
```

---

## Licence

MIT — see [LICENSE](LICENSE).
