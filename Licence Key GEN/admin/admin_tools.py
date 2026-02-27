import os
import sys
import base64
import hashlib
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

BASE          = Path(__file__).parent.resolve()
PRIVATE_KEY   = BASE / "private_key.pem"
PUBLIC_KEY    = BASE / "public_key.pem"

EXPECTED_PUBLIC_KEY_HASH = "acffa89ddf26d89a30d2ad280e2747bad15ff4d8160770e8b9ed6e4f45844f9e"

_MAGIC    = b"SGPL"
_VERSION  = (2).to_bytes(4, "little")
_SIG_SIZE = 256

def _require_crypto() -> None:
    if not _CRYPTO_OK:
        _err("cryptography package not installed. Run: pip install cryptography")

def _ok(msg: str) -> None:
    print(f"  [OK]  {msg}")

def _err(msg: str) -> None:
    print(f"  [!!]  {msg}")
    sys.exit(1)

def _info(msg: str) -> None:
    print(f"        {msg}")

def _load_private_key():
    if not PRIVATE_KEY.exists():
        _err(f"private_key.pem not found: {PRIVATE_KEY}\n"
             "        Run option [1] Generate RSA Keypair first.")
    with PRIVATE_KEY.open("rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def _load_public_key():
    if not PUBLIC_KEY.exists():
        _err(f"public_key.pem not found: {PUBLIC_KEY}\n"
             "        Run option [1] Generate RSA Keypair first.")
    with PUBLIC_KEY.open("rb") as f:
        return serialization.load_pem_public_key(f.read())

def _plugin_fernet_key(nonce: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(EXPECTED_PUBLIC_KEY_HASH.encode()))

def cmd_gen_keys() -> None:
    _require_crypto()
    if PRIVATE_KEY.exists():
        ans = input("  private_key.pem already exists. Overwrite? [y/N] ").strip().lower()
        if ans != "y":
            _info("Aborted.")
            return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with PRIVATE_KEY.open("wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    pub = priv.public_key()
    with PUBLIC_KEY.open("wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    _ok(f"Private key: {PRIVATE_KEY}")
    _ok(f"Public key:  {PUBLIC_KEY}")
    print()
    _info("Next steps:")
    _info("  1. Copy public_key.pem  →  SIGIL/src/config/")
    _info("  2. Run option [4] Hash Key  to get the SHA-256 hash")
    _info("  3. Paste the hash into sigil.py as EXPECTED_PUBLIC_KEY_HASH")
    _info("  4. Also update EXPECTED_PUBLIC_KEY_HASH at the top of THIS file")

def cmd_gen_licence() -> None:
    _require_crypto()
    priv = _load_private_key()

    print()
    print("  Paste the user's HWID (64-char hex shown in the program footer).")
    hwid = input("  Enter client HWID: ").strip()

    if len(hwid) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hwid):
        print("  [WARN] Input doesn't look like a 64-char hex HWID — signing anyway.")

    sig = priv.sign(
        hwid.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    key_hex = sig.hex()

    out_file = BASE / "last_licence.txt"
    out_file.write_text(key_hex, encoding="utf-8")

    print()
    print("  " + "=" * 58)
    print(f"  Licence Key ({len(key_hex)} hex chars):")

    for i in range(0, len(key_hex), 64):
        print("  " + key_hex[i:i+64])
    print("  " + "=" * 58)
    print(f"  Saved to: {out_file}")

    try:
        import pyperclip
        pyperclip.copy(key_hex)
        _ok("Licence key copied to clipboard automatically.")
    except Exception:
        _info("(pyperclip not available — copy from the file above)")

    print()

def cmd_verify_licence() -> None:
    _require_crypto()
    pub = _load_public_key()

    print()
    hwid        = input("  Enter HWID   : ").strip()
    licence_hex = input("  Enter licence: ").strip()

    try:
        pub.verify(
            bytes.fromhex(licence_hex),
            hwid.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        _ok("Licence key is VALID for this HWID.")
    except ValueError:
        _err("Licence hex string is malformed.")
    except Exception:
        print("  [FAIL] Licence key is INVALID — wrong HWID or wrong private key.")

def cmd_hash_key() -> None:
    if not PUBLIC_KEY.exists():
        _err(f"public_key.pem not found: {PUBLIC_KEY}")

    h = hashlib.sha256()
    with PUBLIC_KEY.open("rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    digest = h.hexdigest()

    print()
    print("  " + "=" * 58)
    print(f"  SHA-256 of {PUBLIC_KEY.name}:")
    print(f"  {digest}")
    print("  " + "=" * 58)
    _info("Paste this value into sigil.py as EXPECTED_PUBLIC_KEY_HASH")
    _info("and also update EXPECTED_PUBLIC_KEY_HASH at the top of this file.")

    if digest != EXPECTED_PUBLIC_KEY_HASH:
        print()
        print("  [WARN] This hash does NOT match the current EXPECTED_PUBLIC_KEY_HASH")
        print(f"         in admin_tools.py  ({EXPECTED_PUBLIC_KEY_HASH[:16]}...).")
        print("         Update both sigil.py and this file if you regenerated the key.")

def cmd_sign_plugin(plugin_path_str: str) -> None:
    _require_crypto()
    priv = _load_private_key()

    plugin_path = Path(plugin_path_str).resolve()
    if not plugin_path.exists():
        _err(f"File not found: {plugin_path}")
    if plugin_path.suffix.lower() != ".py":
        print("  [WARN] Expected a .py file.")

    source = plugin_path.read_text(encoding="utf-8")

    nonce            = os.urandom(32)
    encrypted_source = Fernet(_plugin_fernet_key(nonce)).encrypt(source.encode())

    to_sign = _MAGIC + _VERSION + nonce + encrypted_source
    sig     = priv.sign(
        to_sign,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    assert len(sig) == _SIG_SIZE

    output_path = plugin_path.with_suffix(".sgp")
    with output_path.open("wb") as f:
        f.write(_MAGIC + _VERSION + nonce + sig + encrypted_source)

    size_kb = output_path.stat().st_size / 1024
    _ok(f"Plugin signed: {output_path}  ({size_kb:.1f} KB)")
    _info("Place the .sgp file in the SIGIL/plugins/ folder.")

MENU = """
╔══════════════════════════════════════════════╗
║          SIGIL  —  Admin Tools             ║
╠══════════════════════════════════════════════╣
║  [1]  Generate RSA Keypair (run once ever)   ║
║  [2]  Generate Licence Key for user          ║
║  [3]  Verify Licence Key                     ║
║  [4]  Hash public_key.pem                    ║
║  [5]  Sign a Plugin  (.py → .sgp)            ║
║  [0]  Exit                                   ║
╚══════════════════════════════════════════════╝
"""

def run_menu() -> None:
    while True:
        print(MENU)
        choice = input("  Select option: ").strip()
        print()
        if choice == "1":
            cmd_gen_keys()
        elif choice == "2":
            cmd_gen_licence()
        elif choice == "3":
            cmd_verify_licence()
        elif choice == "4":
            cmd_hash_key()
        elif choice == "5":
            path = input("  Path to .py plugin file: ").strip().strip('"')
            cmd_sign_plugin(path)
        elif choice == "0":
            print("  Bye.")
            break
        else:
            print("  Unknown option.")
        print()

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="admin_tools.py",
        description="SIGIL Admin Tools — all admin operations in one CLI",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--gen-keys",      action="store_true",
                   help="Generate RSA-2048 keypair")
    g.add_argument("--gen-licence",   action="store_true",
                   help="Generate a licence key (interactive HWID prompt)")
    g.add_argument("--verify-licence", action="store_true",
                   help="Verify a licence key against an HWID")
    g.add_argument("--hash-key",      action="store_true",
                   help="Print SHA-256 hash of public_key.pem")
    g.add_argument("--sign-plugin",   metavar="PLUGIN.PY",
                   help="Sign and encrypt a plugin file  →  .sgp")
    return p

def main() -> None:
    if not _CRYPTO_OK:
        print("[ERROR] cryptography package not installed.")
        print("        Run: pip install cryptography")
        sys.exit(1)

    parser = build_arg_parser()
    args, _ = parser.parse_known_args()

    if args.gen_keys:
        cmd_gen_keys()
    elif args.gen_licence:
        cmd_gen_licence()
    elif args.verify_licence:
        cmd_verify_licence()
    elif args.hash_key:
        cmd_hash_key()
    elif args.sign_plugin:
        cmd_sign_plugin(args.sign_plugin)
    else:
        run_menu()

if __name__ == "__main__":
    main()
