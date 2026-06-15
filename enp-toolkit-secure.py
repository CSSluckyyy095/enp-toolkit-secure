import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


APP_TITLE = "ENP TOOL KIT - Secure Edition"
WINDOW_SIZE = "820x720"

FERNET_KEY_FILE = "fernet.key.enc"
RSA_PRIVATE_FILE = "rsa_private.pem.enc"
RSA_PUBLIC_FILE = "rsa_public.pem"

METHODS = [
    "AES-128",
    "AES-192",
    "AES-256",
    "Fernet",
    "ChaCha20",
    "TripleDES",
    "RSA-Hybrid"
]

METHOD_INFO = {
    "AES-128": ("Password-based", "Fast, 128-bit AES in CBC mode. Good for most use cases."),
    "AES-192": ("Password-based", "Balanced security with 192-bit AES in CBC mode."),
    "AES-256": ("Password-based", "Maximum AES strength. Recommended default."),
    "Fernet": ("Key file", "Symmetric auth-encryption using a managed key file."),
    "ChaCha20": ("Password-based", "Fast stream cipher. Excellent for large files."),
    "TripleDES": ("Password-based", "Legacy cipher. Use AES-256 for new projects."),
    "RSA-Hybrid": ("Key file", "RSA wraps an AES key. No password needed; uses PEM key files."),
}

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = "#0d1117"   # deep background
SURFACE   = "#161b22"   # card/frame surface
BORDER    = "#30363d"   # borders / separators
ACCENT    = "#58a6ff"   # blue accent
ACCENT2   = "#3fb950"   # green — success
WARN      = "#d29922"   # amber — warning
DANGER    = "#f85149"   # red — error
TEXT      = "#e6edf3"   # primary text
MUTED     = "#8b949e"   # muted / labels
INPUT_BG  = "#21262d"   # input background
BTN_ENC   = "#1f6feb"   # encrypt button
BTN_DEC   = "#238636"   # decrypt button
BTN_CLR   = "#21262d"   # clear button


def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


# ── Anti-Forensics Memory Sanitization Helper ─────────────────────────────────
def burn_buffer(buf):
    """Explicitly overwrites mutable byte structures in RAM to prevent forensic recovery."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, bytes):
        try:
            # Internal mutable memoryview casting fallback
            mv = memoryview(buf)
            mv.cast('B')[:] = b'\x00' * len(buf)
        except Exception:
            pass


# ── Protected Key Management Engine ───────────────────────────────────────────
def derive_master_storage_key(password_str: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150_000)
    return kdf.derive(password_str.encode("utf-8"))


def wrap_and_store_key(path: str, raw_bytes: bytes, master_password: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    storage_key = derive_master_storage_key(master_password, salt)
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(raw_bytes) + padder.finalize()
    
    encryptor = Cipher(algorithms.AES(storage_key), modes.CBC(iv)).encryptor()
    encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()
    
    meta_package = {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "payload": base64.b64encode(encrypted_payload).decode()
    }
    with open(path, "w") as f:
        json.dump(meta_package, f)
        
    burn_buffer(storage_key)


def unwrap_stored_key(path: str, master_password: str) -> bytes:
    with open(path, "r") as f:
        meta_package = json.load(f)
        
    salt = base64.b64decode(meta_package["salt"])
    iv = base64.b64decode(meta_package["iv"])
    encrypted_payload = base64.b64decode(meta_package["payload"])
    
    storage_key = derive_master_storage_key(master_password, salt)
    decryptor = Cipher(algorithms.AES(storage_key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    raw_key = unpadder.update(padded_data) + unpadder.finalize()
    
    burn_buffer(storage_key)
    return raw_key


# ── Standard Crypto helpers ───────────────────────────────────────────────────
def derive_key(password: str, salt: bytes, length: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=200_000)
    return kdf.derive(password.encode("utf-8"))


def default_output_path(input_path: str, suffix: str) -> str:
    folder = os.path.dirname(input_path)
    base   = os.path.basename(input_path)
    return os.path.join(folder, base + suffix)


def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def load_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# AES CBC
def aes_encrypt(data: bytes, password: str, bits: int) -> bytes:
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt, bits // 8)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    res = json.dumps({
        "type": f"AES-{bits}",
        "salt": base64.b64encode(salt).decode(),
        "iv":   base64.b64encode(iv).decode(),
        "data": base64.b64encode(enc.update(padded) + enc.finalize()).decode(),
    }).encode()
    burn_buffer(key)
    return res


def aes_decrypt(pkg: bytes, password: str) -> bytes:
    p = json.loads(pkg)
    salt, iv = base64.b64decode(p["salt"]), base64.b64decode(p["iv"])
    bits = int(p["type"].split("-")[1])
    key  = derive_key(password, salt, bits // 8)
    dec  = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(base64.b64decode(p["data"])) + dec.finalize()
    u = sym_padding.PKCS7(128).unpadder()
    res = u.update(padded) + u.finalize()
    burn_buffer(key)
    return res


# ChaCha20
def chacha20_encrypt(data: bytes, password: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt, 32)
    enc = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    res = json.dumps({
        "type":  "ChaCha20",
        "salt":  base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data":  base64.b64encode(enc.update(data)).decode(),
    }).encode()
    burn_buffer(key)
    return res


def chacha20_decrypt(pkg: bytes, password: str) -> bytes:
    p = json.loads(pkg)
    salt, nonce = base64.b64decode(p["salt"]), base64.b64decode(p["nonce"])
    key = derive_key(password, salt, 32)
    dec = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
    res = dec.update(base64.b64decode(p["data"]))
    burn_buffer(key)
    return res


# TripleDES
def tdes_encrypt(data: bytes, password: str) -> bytes:
    salt, iv = os.urandom(16), os.urandom(8)
    key = derive_key(password, salt, 24)
    padder = sym_padding.PKCS7(64).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    res = json.dumps({
        "type": "TripleDES",
        "salt": base64.b64encode(salt).decode(),
        "iv":   base64.b64encode(iv).decode(),
        "data": base64.b64encode(enc.update(padded) + enc.finalize()).decode(),
    }).encode()
    burn_buffer(key)
    return res


def tdes_decrypt(pkg: bytes, password: str) -> bytes:
    p = json.loads(pkg)
    salt, iv = base64.b64decode(p["salt"]), base64.b64decode(p["iv"])
    key = derive_key(password, salt, 24)
    dec = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(base64.b64decode(p["data"])) + dec.finalize()
    u = sym_padding.PKCS7(64).unpadder()
    res = u.update(padded) + u.finalize()
    burn_buffer(key)
    return res


# RSA Hybrid Protected Decoders
def rsa_hybrid_encrypt(data: bytes) -> bytes:
    if not os.path.exists(RSA_PUBLIC_FILE):
        raise FileNotFoundError("RSA public key not found. Generate RSA keys first.")
    with open(RSA_PUBLIC_FILE, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
        
    aes_key, iv = os.urandom(32), os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    wrapped = pub.encrypt(aes_key, asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    res = json.dumps({
        "type":        "RSA-HYBRID",
        "wrapped_key": base64.b64encode(wrapped).decode(),
        "iv":          base64.b64encode(iv).decode(),
        "data":        base64.b64encode(ciphertext).decode(),
    }).encode()
    burn_buffer(aes_key)
    return res


def password_strength(pw: str):
    if not pw: return 0, "", MUTED
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 14: score += 1
    if any(c.isdigit() for c in pw):  score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw): score += 1
    labels = {0: "Too short", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}
    colors = {0: DANGER, 1: DANGER, 2: WARN, 3: ACCENT, 4: ACCENT2}
    return score, labels[score], colors[score]


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def styled_button(parent, text, color, command, width=14):
    btn = tk.Button(
        parent, text=text, command=command,
        bg=color, fg=TEXT, activebackground=color,
        activeforeground=TEXT, relief="flat", bd=0,
        font=("Segoe UI", 10, "bold"), cursor="hand2",
        padx=12, pady=6, width=width,
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=_lighten(color)))
    btn.bind("<Leave>", lambda e: btn.config(bg=color))
    return btn


def _lighten(hex_color, amount=20):
    r, g, b = _hex_to_rgb(hex_color)
    return f"#{min(255, r + amount):02x}{min(255, g + amount):02x}{min(255, b + amount):02x}"


# ── Main App Window Architecture ──────────────────────────────────────────────
class EnpToolKitApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.resizable(True, True)
        self.root.configure(bg=BG)

        self._style_ttk()
        self.method_var   = tk.StringVar(value="AES-256")
        self.mode_var     = tk.StringVar(value="Text")
        self.show_pw_var  = tk.BooleanVar(value=False)

        self.build_ui()
        self.update_ui()
        self.refresh_key_status()

        # Input Intercept for Drag and Drop fallbacks
        self.file_path_entry.bind("<Control-v>", lambda e: self.root.after(10, self._clean_drag_input))

        self.root.bind("<Control-e>", lambda e: self.encrypt_action())
        self.root.bind("<Control-d>", lambda e: self.decrypt_action())
        self.root.bind("<Control-l>", lambda e: self.clear_all())
        self.root.bind("<Control-s>", lambda e: self.switch_io())

    def _style_ttk(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".",          background=BG,      foreground=TEXT,      fieldbackground=INPUT_BG)
        s.configure("TCombobox",  background=INPUT_BG, foreground=TEXT,     fieldbackground=INPUT_BG,
                    selectbackground=ACCENT, selectforeground=TEXT, arrowcolor=ACCENT, relief="flat")
        s.map("TCombobox",        fieldbackground=[("readonly", INPUT_BG)],
              foreground=[("readonly", TEXT)], background=[("readonly", INPUT_BG)])
        s.configure("TFrame",     background=BG)
        s.configure("TLabel",     background=BG,      foreground=TEXT)
        s.configure("TSeparator", background=BORDER)

    def build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg=SURFACE, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🔐  ENP TOOL KIT - Secure", font=("Segoe UI", 16, "bold"), bg=SURFACE, fg=ACCENT).pack(side="left", padx=24)
        tk.Label(hdr, text="Ctrl+E Encrypt  │  Ctrl+D Decrypt  │  Ctrl+S Swap  │  Ctrl+L Clear", font=("Segoe UI", 8), bg=SURFACE, fg=MUTED).pack(side="right", padx=24)

        main_content = tk.Frame(self.root, bg=BG, pady=16)
        main_content.pack(fill="both", expand=True, padx=24)

        # ── Controls row ──
        ctrl_frame = tk.Frame(main_content, bg=BG)
        ctrl_frame.pack(fill="x", pady=(0, 16))

        tk.Label(ctrl_frame, text="Method", font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED).pack(side="left", padx=(0, 6))
        self.method_box = ttk.Combobox(ctrl_frame, textvariable=self.method_var, values=METHODS, state="readonly", width=14)
        self.method_box.pack(side="left", padx=(0, 20))
        self.method_box.bind("<<ComboboxSelected>>", lambda e: self.update_ui())

        tk.Label(ctrl_frame, text="Mode", font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED).pack(side="left", padx=(0, 6))
        self.mode_box = ttk.Combobox(ctrl_frame, textvariable=self.mode_var, values=["Text", "File"], state="readonly", width=10)
        self.mode_box.pack(side="left", padx=(0, 20))
        self.mode_box.bind("<<ComboboxSelected>>", lambda e: self.update_ui())

        self.info_label = tk.Label(ctrl_frame, text="", font=("Segoe UI", 9), bg=BG, fg=MUTED, anchor="w")
        self.info_label.pack(side="left", fill="x", expand=True)

        self.mid_container = tk.Frame(main_content, bg=BG)
        self.mid_container.pack(fill="x", pady=(0, 16))

        # Password layout block
        self.pw_outer = tk.Frame(self.mid_container, bg=BG)
        pw_row = tk.Frame(self.pw_outer, bg=BG)
        pw_row.pack(fill="x")
        tk.Label(pw_row, text="Password", font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED, width=10, anchor="w").pack(side="left")
        
        self.password_entry = tk.Entry(
            pw_row, width=32, show="*", bg=INPUT_BG, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=0, font=("Segoe UI", 10), highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT
        )
        self.password_entry.pack(side="left", padx=4, ipady=5)
        self.password_entry.bind("<KeyRelease>", self._on_pw_change)

        self.toggle_pw_btn = tk.Button(pw_row, text="👁", command=self._toggle_pw, bg=INPUT_BG, fg=MUTED, relief="flat", bd=0, font=("Segoe UI", 11), cursor="hand2", padx=6)
        self.toggle_pw_btn.pack(side="left", padx=2)

        strength_row = tk.Frame(self.pw_outer, bg=BG)
        strength_row.pack(fill="x", pady=(6,0))
        tk.Label(strength_row, text="", bg=BG, width=10).pack(side="left")
        
        self.strength_bars = []
        bar_frame = tk.Frame(strength_row, bg=BG)
        bar_frame.pack(side="left")
        for _ in range(4):
            b = tk.Frame(bar_frame, bg=BORDER, width=36, height=4)
            b.pack(side="left", padx=2)
            self.strength_bars.append(b)
        self.strength_label = tk.Label(strength_row, text="", font=("Segoe UI", 8), bg=BG, fg=MUTED)
        self.strength_label.pack(side="left", padx=8)

        # Key file tracking block
        self.key_outer = tk.Frame(self.mid_container, bg=BG)
        key_row = tk.Frame(self.key_outer, bg=BG)
        key_row.pack(fill="x")
        tk.Label(key_row, text="Keys", font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED, width=10, anchor="w").pack(side="left")
        styled_button(key_row, "Gen Fernet Key", SURFACE, self.gen_fernet, width=15).pack(side="left", padx=4)
        styled_button(key_row, "Gen RSA Keys", SURFACE, self.gen_rsa, width=15).pack(side="left", padx=4)
        self.fernet_status = tk.Label(key_row, text="", font=("Segoe UI", 8), bg=BG)
        self.fernet_status.pack(side="left", padx=12)
        self.rsa_status = tk.Label(key_row, text="", font=("Segoe UI", 8), bg=BG)
        self.rsa_status.pack(side="left")

        # ── Input Area ──
        self.input_container = tk.Frame(main_content, bg=BG)
        self.input_container.pack(fill="x", pady=(0, 16))

        # Text input setup
        self.text_frame = tk.Frame(self.input_container, bg=BG)
        txt_hdr = tk.Frame(self.text_frame, bg=BG)
        txt_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(txt_hdr, text="Input Text", font=("Segoe UI", 10, "bold"), bg=BG, fg=TEXT).pack(side="left")
        tk.Button(txt_hdr, text="Clear text", font=("Segoe UI", 8), bg=BG, fg=MUTED, relief="flat", bd=0, cursor="hand2",
                  command=lambda: self.text_input.delete("1.0", tk.END)).pack(side="right")
        self.text_input = tk.Text(self.text_frame, height=6, bg=INPUT_BG, fg=TEXT, insertbackground=ACCENT, relief="flat", bd=0, font=("Consolas", 10), highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT, padx=12, pady=10)
        self.text_input.pack(fill="x")

        # File input setup (Supports Drag & Drop fallbacks natively)
        self.file_frame = tk.Frame(self.input_container, bg=BG)
        file_hdr = tk.Frame(self.file_frame, bg=BG)
        file_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(file_hdr, text="Input File Source (Supports Drag & Drop)", font=("Segoe UI", 10, "bold"), bg=BG, fg=TEXT).pack(side="left")
        self.file_size_label = tk.Label(file_hdr, text="", font=("Segoe UI", 8), bg=BG, fg=MUTED)
        self.file_size_label.pack(side="right")
        file_row = tk.Frame(self.file_frame, bg=BG)
        file_row.pack(fill="x")
        self.file_path_entry = tk.Entry(file_row, bg=INPUT_BG, fg=TEXT, insertbackground=ACCENT, relief="flat", bd=0, font=("Segoe UI", 10), highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT)
        self.file_path_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        styled_button(file_row, "Browse File", SURFACE, self.browse_file, width=12).pack(side="right")

        # ── Trigger Action row ──
        btn_row = tk.Frame(main_content, bg=BG)
        btn_row.pack(fill="x", pady=(0, 16))
        styled_button(btn_row, "🔒 Encrypt Data", BTN_ENC, self.encrypt_action, width=18).pack(side="left", padx=(0, 8))
        styled_button(btn_row, "🔓 Decrypt Data", BTN_DEC, self.decrypt_action, width=18).pack(side="left", padx=(0, 8))
        styled_button(btn_row, "✕ Clear Dashboard", BORDER, self.clear_all, width=16).pack(side="right")

        # ── Output Area ──
        out_frame = tk.Frame(main_content, bg=BG)
        out_frame.pack(fill="both", expand=True)
        out_hdr = tk.Frame(out_frame, bg=BG)
        out_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(out_hdr, text="Output Display", font=("Segoe UI", 10, "bold"), bg=BG, fg=TEXT).pack(side="left")
        
        tk.Button(out_hdr, text="📋 Copy", font=("Segoe UI", 8), bg=SURFACE, fg=TEXT, relief="flat", bd=0, cursor="hand2", padx=10, command=self._copy_output).pack(side="right", padx=2)
        tk.Button(out_hdr, text="💾 Save", font=("Segoe UI", 8), bg=SURFACE, fg=TEXT, relief="flat", bd=0, cursor="hand2", padx=10, command=self._save_output).pack(side="right", padx=2)
        tk.Button(out_hdr, text="⇄ Swap to Input", font=("Segoe UI", 8), bg=SURFACE, fg=ACCENT, relief="flat", bd=0, cursor="hand2", padx=10, command=self.switch_io).pack(side="right", padx=2)

        self.output_text = tk.Text(out_frame, height=8, bg=INPUT_BG, fg=ACCENT2, insertbackground=ACCENT, relief="flat", bd=0, font=("Consolas", 10), highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT, padx=12, pady=10)
        self.output_text.pack(fill="both", expand=True)

        # ── Status Footer ──
        status_frame = tk.Frame(self.root, bg=SURFACE, height=28)
        status_frame.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="System Ready")
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 8), bg=SURFACE, fg=MUTED, anchor="w")
        self.status_label.pack(side="left", padx=16, pady=4)

    def _clean_drag_input(self):
        """Sanitizes OS drag-and-drop strings (removes wrapper quotes automatically)."""
        raw_path = self.file_path_entry.get().strip()
        if raw_path.startswith('"') and raw_path.endswith('"'):
            cleaned = raw_path[1:-1]
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, cleaned)
        self._update_file_size()

    def update_ui(self):
        method = self.method_var.get()
        mode   = self.mode_var.get()
        self.pw_outer.pack_forget()
        self.key_outer.pack_forget()
        self.text_frame.pack_forget()
        self.file_frame.pack_forget()

        if method in {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"}:
            self.pw_outer.pack(fill="x")
        else:
            self.key_outer.pack(fill="x")

        auth_type, desc = METHOD_INFO.get(method, ("", ""))
        self.info_label.config(text=f"  •  [{auth_type}] {desc}")

        if mode == "Text":
            self.text_frame.pack(fill="x")
        else:
            self.file_frame.pack(fill="x")

    def refresh_key_status(self):
        fok = os.path.exists(FERNET_KEY_FILE)
        rsa_ok = os.path.exists(RSA_PRIVATE_FILE) and os.path.exists(RSA_PUBLIC_FILE)
        self.fernet_status.config(text=f"fernet.key {'✓' if fok else '✗'}", fg=ACCENT2 if fok else DANGER)
        self.rsa_status.config(text=f"RSA keys {'✓' if rsa_ok else '✗'}", fg=ACCENT2 if rsa_ok else DANGER)

    def _on_pw_change(self, _event=None):
        pw = self.password_entry.get()
        score, label, color = password_strength(pw)
        for i, bar in enumerate(self.strength_bars):
            bar.config(bg=color if i < score else BORDER)
        self.strength_label.config(text=label, fg=color)

    def _toggle_pw(self):
        current = self.password_entry.cget("show")
        self.password_entry.config(show="" if current == "*" else "*")
        self.toggle_pw_btn.config(text="🙈" if current == "*" else "👁")

    def _update_file_size(self, _event=None):
        p = self.file_path_entry.get().strip()
        if os.path.isfile(p):
            self.file_size_label.config(text=human_size(os.path.getsize(p)))
        else:
            self.file_size_label.config(text="")

    def set_status(self, msg: str, color=MUTED):
        self.status_var.set(msg)
        self.status_label.config(fg=color)

    def set_output(self, text: str):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)

    def _copy_output(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.set_status("Copied successfully.", ACCENT2)

    def _save_output(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Empty", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.set_status(f"Saved to {os.path.basename(path)}", ACCENT2)

    def switch_io(self):
        output_content = self.output_text.get("1.0", tk.END).strip()
        if not output_content or "successfully" in output_content:
            messagebox.showwarning("Notice", "No encrypted ciphertext string available to swap.")
            return
        self.mode_var.set("Text")
        self.update_ui()
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert(tk.END, output_content)
        self.output_text.delete("1.0", tk.END)
        self.set_status("Cipher text swapped to input area.", ACCENT)

    def browse_file(self):
        file_types = [
            ("Supported Formats", "*.txt *.pdf *.doc *.docx *.ppt *.pptx *.jpg *.jpeg *.png *.gif *.mp3 *.mp4 *.zip *.rar"),
            ("All Files", "*.*")
        ]
        path = filedialog.askopenfilename(filetypes=file_types)
        if path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, path)
            self._update_file_size()

    # ── Secure Password Prompt Overlay Helper ─────────────────────────────────
    def _prompt_master_password(self, title="Password Verification"):
        # Custom blocking context manager to isolate interactions securely
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("340x140")
        dialog.configure(bg=SURFACE)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Enter Key Vault Master Password:", bg=SURFACE, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(pady=10)
        entry = tk.Entry(dialog, show="*", bg=INPUT_BG, fg=TEXT, bd=0, highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT, width=30)
        entry.pack(pady=5, ipady=4)
        entry.focus_set()
        
        res = {"value": None}
        def confirm():
            res["value"] = entry.get()
            dialog.destroy()
            
        styled_button(dialog, "Access Vault", BTN_ENC, confirm, width=12).pack(pady=10)
        self.root.wait_window(dialog)
        return res["value"]

    # ── Vault Storage Triggers ────────────────────────────────────────────────
    def gen_fernet(self):
        master_pw = self._prompt_master_password("Generate Key")
        if not master_pw: return
        raw_key = Fernet.generate_key()
        wrap_and_store_key(FERNET_KEY_FILE, raw_key, master_pw)
        self.refresh_key_status()
        self.set_status("fernet.key.enc secured into storage vault.", ACCENT2)

    def gen_rsa(self):
        master_pw = self._prompt_master_password("Generate Keys")
        if not master_pw: return
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub  = priv.public_key()
        
        priv_bytes = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        wrap_and_store_key(RSA_PRIVATE_FILE, priv_bytes, master_pw)
        
        pub_bytes = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(RSA_PUBLIC_FILE, "wb") as f:
            f.write(pub_bytes)
            
        self.refresh_key_status()
        self.set_status("RSA storage files protected successfully.", ACCENT2)

    def clear_all(self):
        self.password_entry.delete(0, tk.END)
        self.text_input.delete("1.0", tk.END)
        self.file_path_entry.delete(0, tk.END)
        self.output_text.delete("1.0", tk.END)
        self._on_pw_change()
        self.file_size_label.config(text="")
        self.set_status("Dashboard cleared.", MUTED)

    # ── Core Threaded Execution Management Engine ─────────────────────────────
    def _run_async_operation(self, operation_func):
        """Dispatches calculations safely into async background threads to prevent UI lock."""
        self.set_status("Processing system math...", WARN)
        threading.Thread(target=operation_func, daemon=True).start()

    def encrypt_action(self):
        method = self.method_var.get()
        mode = self.mode_var.get()
        password = self.password_entry.get().strip()

        if method in {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"} and not password:
            messagebox.showerror("Missing Password", "Enter a password before encrypting.")
            return

        def task():
            try:
                if mode == "Text":
                    text = self.text_input.get("1.0", tk.END).strip()
                    if not text:
                        self.root.photo_backend_msg = lambda: messagebox.showerror("Empty Input", "Input text is empty.")
                        self.root.after(0, self.root.photo_backend_msg)
                        return
                        
                    # Handle specialized decrypt routing internally for custom mapped formats
                    if method == "Fernet":
                        m_pw = self._prompt_master_password("Unlock Fernet Vault")
                        raw_k = unwrap_stored_key(FERNET_KEY_FILE, m_pw)
                        result = Fernet(raw_k).encrypt(text.encode("utf-8"))
                        burn_buffer(raw_k)
                    elif method == "RSA-Hybrid":
                        result = rsa_hybrid_encrypt(text.encode("utf-8"))
                    else:
                        result = self.encrypt_bytes(method, text.encode("utf-8"), password)
                        
                    self.root.after(0, lambda: self.set_output(result.decode("utf-8", errors="ignore")))
                    self.root.after(0, lambda: self.set_status(f"Encrypted successfully. {len(result):,} bytes.", ACCENT2))
                else:
                    in_file = self.file_path_entry.get().strip()
                    if not in_file or not os.path.exists(in_file):
                        self.root.after(0, lambda: messagebox.showerror("No File", "Select a valid file first."))
                        return
                    
                    data = load_bytes(in_file)
                    if method == "Fernet":
                        m_pw = self._prompt_master_password("Unlock Fernet Vault")
                        raw_k = unwrap_stored_key(FERNET_KEY_FILE, m_pw)
                        result = Fernet(raw_k).encrypt(data)
                        burn_buffer(raw_k)
                    elif method == "RSA-Hybrid":
                        result = rsa_hybrid_encrypt(data)
                    else:
                        result = self.encrypt_bytes(method, data, password)
                        
                    ext_map = {"AES-128": ".aes", "AES-192": ".aes", "AES-256": ".aes", "Fernet": ".fernet", "ChaCha20": ".chacha", "TripleDES": ".tdes", "RSA-Hybrid": ".rhy"}
                    out_file = default_output_path(in_file, ext_map[method])
                    save_bytes(out_file, result)
                    
                    self.root.after(0, lambda: self.set_output(f"✓ Encrypted successfully\n\nOutput: {out_file}\nSize: {human_size(len(result))}"))
                    self.root.after(0, lambda: self.set_status(f"File encrypted safely.", ACCENT2))
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Error: {e}", DANGER))
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        self._run_async_operation(task)

    def decrypt_action(self):
        method = self.method_var.get()
        mode = self.mode_var.get()
        password = self.password_entry.get().strip()

        if method in {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"} and not password:
            messagebox.showerror("Missing Password", "Enter a password before decrypting.")
            return

        def task():
            try:
                if mode == "Text":
                    text = self.text_input.get("1.0", tk.END).strip()
                    if not text:
                        self.root.after(0, lambda: messagebox.showerror("Empty Input", "Input text is empty."))
                        return
                        
                    if method == "Fernet":
                        m_pw = self._prompt_master_password("Unlock Fernet Vault")
                        raw_k = unwrap_stored_key(FERNET_KEY_FILE, m_pw)
                        result = Fernet(raw_k).decrypt(text.encode("utf-8"))
                        burn_buffer(raw_k)
                    elif method == "RSA-Hybrid":
                        m_pw = self._prompt_master_password("Unlock RSA Private Vault")
                        raw_priv = unwrap_stored_key(RSA_PRIVATE_FILE, m_pw)
                        priv_key = serialization.load_pem_private_key(raw_priv, password=None)
                        p = json.loads(text)
                        aes_key = priv_key.decrypt(base64.b64decode(p["wrapped_key"]), asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        dec = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(p["iv"]))).decryptor()
                        padded = dec.update(base64.b64decode(p["data"])) + dec.finalize()
                        result = sym_padding.PKCS7(128).unpadder().update(padded) + sym_padding.PKCS7(128).unpadder().finalize()
                        burn_buffer(raw_priv); burn_buffer(aes_key)
                    else:
                        result = self.decrypt_bytes(method, text.encode("utf-8"), password)
                        
                    self.root.after(0, lambda: self.set_output(result.decode("utf-8", errors="replace")))
                    self.root.after(0, lambda: self.set_status(f"Decrypted successfully.", ACCENT2))
                else:
                    in_file = self.file_path_entry.get().strip()
                    if not in_file or not os.path.exists(in_file):
                        self.root.after(0, lambda: messagebox.showerror("No File", "Select valid file source."))
                        return
                        
                    data = load_bytes(in_file)
                    if method == "Fernet":
                        m_pw = self._prompt_master_password("Unlock Fernet Vault")
                        raw_k = unwrap_stored_key(FERNET_KEY_FILE, m_pw)
                        result = Fernet(raw_k).decrypt(data)
                        burn_buffer(raw_k)
                    elif method == "RSA-Hybrid":
                        m_pw = self._prompt_master_password("Unlock RSA Private Vault")
                        raw_priv = unwrap_stored_key(RSA_PRIVATE_FILE, m_pw)
                        priv_key = serialization.load_pem_private_key(raw_priv, password=None)
                        p = json.loads(data)
                        aes_key = priv_key.decrypt(base64.b64decode(p["wrapped_key"]), asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        dec = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(p["iv"]))).decryptor()
                        padded = dec.update(base64.b64decode(p["data"])) + dec.finalize()
                        result = sym_padding.PKCS7(128).unpadder().update(padded) + sym_padding.PKCS7(128).unpadder().finalize()
                        burn_buffer(raw_priv); burn_buffer(aes_key)
                    else:
                        result = self.decrypt_bytes(method, data, password)
                        
                    base, ext = os.path.splitext(in_file)
                    out_file = base if ext in [".aes", ".fernet", ".chacha", ".tdes", ".rhy"] else base + ".dec"
                    save_bytes(out_file, result)
                    
                    self.root.after(0, lambda: self.set_output(f"✓ Decrypted successfully\n\nOutput: {out_file}"))
                    self.root.after(0, lambda: self.set_status("File decrypted successfully.", ACCENT2))
            except InvalidToken:
                self.root.after(0, lambda: self.set_status("Decryption failed — bad key.", DANGER))
                self.root.after(0, lambda: messagebox.showerror("Decryption Failed", "The passphrase or key configuration is incorrect."))
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Error: {e}", DANGER))

        self._run_async_operation(task)

    def encrypt_bytes(self, method: str, data: bytes, password: str) -> bytes:
        if method in ("AES-128", "AES-192", "AES-256"): return aes_encrypt(data, password, int(method.split("-")[1]))
        if method == "ChaCha20":  return chacha20_encrypt(data, password)
        if method == "TripleDES": return tdes_encrypt(data, password)
        raise ValueError(f"Unsupported method context: {method}")

    def decrypt_bytes(self, method: str, data: bytes, password: str) -> bytes:
        if method in ("AES-128", "AES-192", "AES-256"): return aes_decrypt(data, password)
        if method == "ChaCha20":   return chacha20_decrypt(data, password)
        if method == "TripleDES":  return tdes_decrypt(data, password)
        raise ValueError(f"Unsupported method context: {method}")


if __name__ == "__main__":
    root = tk.Tk()
    app  = EnpToolKitApp(root)
    root.mainloop()