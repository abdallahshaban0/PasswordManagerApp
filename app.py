import tkinter as tk
from tkinter import simpledialog, messagebox
from ttkbootstrap import Style, Button, Entry
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import os
import json

DATA_DIR = "data"
VAULT_FILE = os.path.join(DATA_DIR, "vault.enc")
MASTER_HASH_FILE = os.path.join(DATA_DIR, "master.hash")
SALT_FILE = os.path.join(DATA_DIR, "salt.bin")

# --- Encryption helpers ---
def get_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: dict, key: bytes):
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(token: bytes, key: bytes):
    f = Fernet(key)
    return json.loads(f.decrypt(token).decode())

# --- Master password logic ---
def set_master_password(password: str):
    salt = get_salt()
    key = derive_key(password, salt)
    # Store hash of key for verification
    with open(MASTER_HASH_FILE, "wb") as f:
        f.write(key)
    # Create empty vault
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data({}, key))

def verify_master_password(password: str):
    salt = get_salt()
    key = derive_key(password, salt)
    if not os.path.exists(MASTER_HASH_FILE):
        return False
    with open(MASTER_HASH_FILE, "rb") as f:
        stored = f.read()
    return key == stored

# --- GUI ---
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.style = Style(theme="darkly")
        self.root.title("Password Manager")
        self.root.geometry("540x600")
        self.root.resizable(False, False)
        self.center_window(540, 600)
        self.key = None
        self.vault = {}
        self.main_frame = tk.Frame(self.root, bg=self.style.colors.bg)
        self.main_frame.pack(fill="both", expand=True)
        self.show_login()

    def center_window(self, width, height):
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_frame()
        is_first = not os.path.exists(MASTER_HASH_FILE)
        label = tk.Label(self.main_frame, text="Set Master Password" if is_first else "Enter Master Password", font=("Segoe UI", 16, "bold"), fg=self.style.colors.primary, bg=self.style.colors.bg)
        label.pack(pady=30)
        self.pw_entry = Entry(self.main_frame, show="*", width=25, font=("Segoe UI", 12))
        self.pw_entry.pack(pady=10)
        self.pw_entry.focus()
        btn = Button(self.main_frame, text="Set" if is_first else "Unlock", bootstyle="primary", command=self.set_master if is_first else self.unlock)
        btn.pack(pady=10)

    def set_master(self):
        pw = self.pw_entry.get()
        if len(pw) < 6:
            messagebox.showerror("Error", "Password too short (min 6 chars)")
            return
        os.makedirs(DATA_DIR, exist_ok=True)
        set_master_password(pw)
        messagebox.showinfo("Success", "Master password set!")
        self.show_login()

    def unlock(self):
        pw = self.pw_entry.get()
        if not verify_master_password(pw):
            messagebox.showerror("Error", "Incorrect master password")
            return
        self.key = derive_key(pw, get_salt())
        self.load_vault()
        self.show_main()

    def load_vault(self):
        if not os.path.exists(VAULT_FILE):
            self.vault = {}
            return
        with open(VAULT_FILE, "rb") as f:
            enc = f.read()
        try:
            self.vault = decrypt_data(enc, self.key)
        except InvalidToken:
            self.vault = {}

    def save_vault(self):
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(self.vault, self.key))

    def show_main(self):
        self.clear_frame()
        title = tk.Label(self.main_frame, text="Your Passwords", font=("Segoe UI", 16, "bold"), fg=self.style.colors.primary, bg=self.style.colors.bg)
        title.pack(pady=20)
        # List passwords
        for site, info in self.vault.items():
            frame = tk.Frame(self.main_frame, bg=self.style.colors.bg)
            frame.pack(fill="x", padx=20, pady=5)
            tk.Label(frame, text=site, font=("Segoe UI", 12, "bold"), fg=self.style.colors.info, bg=self.style.colors.bg).pack(side="left")
            Button(frame, text="Copy Username", bootstyle="secondary", command=lambda u=info['username']: self.copy_to_clipboard(u, 'Username')).pack(side="right", padx=2)
            Button(frame, text="Copy Password", bootstyle="secondary", command=lambda pw=info['password']: self.copy_to_clipboard(pw, 'Password')).pack(side="right", padx=2)
            Button(frame, text="Update", bootstyle="warning", command=lambda s=site: self.show_update(s)).pack(side="right", padx=2)
            Button(frame, text="Delete", bootstyle="danger", command=lambda s=site: self.confirm_delete(s)).pack(side="right", padx=2)
        Button(self.main_frame, text="Add New", bootstyle="success", command=self.show_add).pack(pady=20)
        Button(self.main_frame, text="Lock", bootstyle="secondary", command=self.show_login).pack(pady=5)

    def show_add(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Add New Password", font=("Segoe UI", 16, "bold"), fg=self.style.colors.primary, bg=self.style.colors.bg).pack(pady=20)
        tk.Label(self.main_frame, text="Site/Service", bg=self.style.colors.bg, fg=self.style.colors.fg).pack()
        site_entry = Entry(self.main_frame, width=25)
        site_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Username", bg=self.style.colors.bg, fg=self.style.colors.fg).pack()
        user_entry = Entry(self.main_frame, width=25)
        user_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Password", bg=self.style.colors.bg, fg=self.style.colors.fg).pack()
        pw_entry = Entry(self.main_frame, width=25)
        pw_entry.pack(pady=5)
        def save():
            site = site_entry.get().strip()
            user = user_entry.get().strip()
            pw = pw_entry.get().strip()
            if not site or not user or not pw:
                messagebox.showerror("Error", "All fields required")
                return
            if site in self.vault:
                messagebox.showerror("Error", "Site already exists. Use update instead.")
                return
            self.vault[site] = {"username": user, "password": pw}
            self.save_vault()
            self.show_main()
        Button(self.main_frame, text="Save", bootstyle="success", command=save).pack(pady=10)
        Button(self.main_frame, text="Cancel", bootstyle="secondary", command=self.show_main).pack()

    def show_update(self, site):
        self.clear_frame()
        tk.Label(self.main_frame, text=f"Update: {site}", font=("Segoe UI", 16, "bold"), fg=self.style.colors.primary, bg=self.style.colors.bg).pack(pady=20)
        tk.Label(self.main_frame, text="Username", bg=self.style.colors.bg, fg=self.style.colors.fg).pack()
        user_entry = Entry(self.main_frame, width=25)
        user_entry.insert(0, self.vault[site]["username"])
        user_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Password", bg=self.style.colors.bg, fg=self.style.colors.fg).pack()
        pw_entry = Entry(self.main_frame, width=25)
        pw_entry.insert(0, self.vault[site]["password"])
        pw_entry.pack(pady=5)
        def update():
            if messagebox.askyesno("Confirm Update", f"Update credentials for {site}?"):
                self.vault[site]["username"] = user_entry.get().strip()
                self.vault[site]["password"] = pw_entry.get().strip()
                self.save_vault()
                self.show_main()
        Button(self.main_frame, text="Update", bootstyle="warning", command=update).pack(pady=10)
        Button(self.main_frame, text="Cancel", bootstyle="secondary", command=self.show_main).pack()

    def confirm_delete(self, site):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {site}?"):
            del self.vault[site]
            self.save_vault()
            self.show_main()

    def copy_to_clipboard(self, text, label):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", f"{label} copied to clipboard!")

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop() 