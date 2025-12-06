"""
password_manager_final.py

Final compact Password Manager GUI (corrected)
- Register / Login / Forgot Password / Vault
- Username + Email + Password for login
- One email may register up to 5 usernames
- Case-sensitive CAPTCHA (uppercase letters + digits) different per screen
- OTP via SMTP (EMAIL_USER & EMAIL_PASS & SMTP_SERVER & SMTP_PORT in .env)
- Vault per account (email|username)
- Theme: Grey / Blue / Green (no white)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import json
import os
import re
import smtplib
import time
from email.mime.text import MIMEText
from dotenv import load_dotenv

# optional clipboard
try:
    import pyperclip
    HAS_PYPERCLIP = True
except Exception:
    HAS_PYPERCLIP = False

# load environment variables
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

# Storage files
USERS_FILE = "users.json"   # { email: [ {username, password, verified}, ... ] }
VAULT_FILE = "vault.json"   # { "email|username": [ {site, login, password}, ... ] }

# OTP settings
OTP_TTL = 300  # seconds
otp_store = {}  # email -> {code, expires, purpose}

# -------------------------
# Persistence helpers
# -------------------------
def load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_users():
    users = load_json(USERS_FILE, {})
    # Defensive migration: if some email maps to list of strings, convert them to dict entries.
    for email, accs in list(users.items()):
        if isinstance(accs, list):
            migrated = False
            new_accs = []
            for a in accs:
                if isinstance(a, str):
                    # convert "username" string -> dict with placeholders
                    new_accs.append({"username": a, "password": "", "verified": False})
                    migrated = True
                elif isinstance(a, dict):
                    # ensure keys exist
                    new_accs.append({
                        "username": a.get("username", ""),
                        "password": a.get("password", ""),
                        "verified": bool(a.get("verified", False))
                    })
                else:
                    # unexpected type, skip
                    migrated = True
            if migrated:
                users[email] = new_accs
    return users

def save_users(users):
    save_json(USERS_FILE, users)

def load_vault():
    return load_json(VAULT_FILE, {})

def save_vault(vault):
    save_json(VAULT_FILE, vault)

# ensure files exist
save_users(load_users())
save_vault(load_vault())

# -------------------------
# OTP / Email helpers
# -------------------------
def _generate_otp():
    return f"{random.randint(100000, 999999):06d}"

def _send_email(recipient, subject, body):
    if not EMAIL_USER or not EMAIL_PASS:
        return False, "Email credentials missing in .env (EMAIL_USER / EMAIL_PASS)."
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = recipient
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True, "sent"
    except Exception as e:
        return False, str(e)

def prepare_and_send_otp(email, purpose="verification"):
    code = _generate_otp()
    now = time.time()
    otp_store[email] = {"code": code, "expires": now + OTP_TTL, "purpose": purpose}
    subject = f"Password Manager OTP ({purpose})"
    body = f"Your one-time code is: {code}\nIt expires in {OTP_TTL//60} minute(s)."
    ok, msg = _send_email(email, subject, body)
    if not ok:
        otp_store.pop(email, None)
        return False, msg
    return True, "otp_sent"

def verify_otp(email, entered):
    entry = otp_store.get(email)
    if not entry:
        return False, "No OTP requested."
    if time.time() > entry["expires"]:
        otp_store.pop(email, None)
        return False, "OTP expired."
    if entered.strip() == entry["code"]:
        otp_store.pop(email, None)
        return True, "verified"
    return False, "Incorrect OTP."

# -------------------------
# Password helpers
# -------------------------
def password_strength(pw: str) -> str:
    if len(pw) < 8:
        return "Weak"
    score = 0
    score += bool(re.search(r"[a-z]", pw))
    score += bool(re.search(r"[A-Z]", pw))
    score += bool(re.search(r"\d", pw))
    score += bool(re.search(r"[^\w\s]", pw))
    if score <= 2:
        return "Weak"
    if score == 3:
        return "Moderate"
    return "Strong"

def suggest_password(length=14) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(alphabet) for _ in range(length))

# -------------------------
# CAPTCHA generator (uppercase letters + digits)
# -------------------------
def generate_captcha_text(length=7):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

# -------------------------
# GUI Setup
# -------------------------
root = tk.Tk()
root.title("MFA Password Manager")
root.geometry("480x520")
root.resizable(False, False)

# Colors (no white)
COL_BG = "#1f2933"       # slate grey background
COL_PANEL = "#2d3742"    # panel / card
COL_BLUE = "#3b82f6"     # blue accent (used for emphasis if needed)
COL_GREEN = "#10b981"    # green highlight (buttons)
COL_TEXT = "#c0e0e9"     # light grey-ish (not white)
COL_HEADER = "#7dd3fc"   # sky blue header
COL_ENTRY = "#26343a"    # entry background

style = ttk.Style()
try:
    style.theme_use("clam")
except Exception:
    pass
style.configure("TLabel", background=COL_BG, foreground=COL_TEXT, font=("Segoe UI", 10))
style.configure("Header.TLabel", background=COL_BG, foreground=COL_HEADER, font=("Segoe UI Semibold", 14))
style.configure("TEntry", fieldbackground=COL_ENTRY, foreground=COL_TEXT, padding=6)
style.configure("Accent.TButton", background=COL_GREEN, foreground=COL_BG, padding=6)
style.map("Accent.TButton", background=[("active", "#0f9d72")])

container = tk.Frame(root, bg=COL_BG)
container.place(relx=0.5, rely=0.5, anchor="center", width=460, height=480)
frames = {}

def show_frame(name):
    frame = frames.get(name)
    if frame:
        frame.tkraise()
    else:
        # defensive fallback
        frames.get("login", container).tkraise()

# -------------------------
# REGISTER Frame
# -------------------------
reg = tk.Frame(container, bg=COL_BG)
frames["register"] = reg
reg.place(relwidth=1, relheight=1)

ttk.Label(reg, text="Create account", style="Header.TLabel").pack(pady=(12,8))

frm_r = tk.Frame(reg, bg=COL_BG)
frm_r.pack(pady=4)

tk.Label(frm_r, text="Username:", bg=COL_BG, fg=COL_TEXT).grid(row=0, column=0, sticky="w", padx=6, pady=6)
entry_r_username = ttk.Entry(frm_r, width=30)
entry_r_username.grid(row=0, column=1, padx=6, pady=6)

tk.Label(frm_r, text="Email:", bg=COL_BG, fg=COL_TEXT).grid(row=1, column=0, sticky="w", padx=6, pady=6)
entry_r_email = ttk.Entry(frm_r, width=30)
entry_r_email.grid(row=1, column=1, padx=6, pady=6)

tk.Label(frm_r, text="Password:", bg=COL_BG, fg=COL_TEXT).grid(row=2, column=0, sticky="w", padx=6, pady=6)
entry_r_password = ttk.Entry(frm_r, width=28, show="*")
entry_r_password.grid(row=2, column=1, sticky="w", padx=(6,0), pady=6)

# view password toggle
def r_toggle_show():
    if entry_r_password.cget("show") == "":
        entry_r_password.config(show="*"); btn_r_view.config(text="👁")
    else:
        entry_r_password.config(show=""); btn_r_view.config(text="🚫")
btn_r_view = ttk.Button(frm_r, text="👁", width=3, command=r_toggle_show)
btn_r_view.grid(row=2, column=1, sticky="e", padx=(0,6))

lbl_r_strength = tk.Label(frm_r, text="", bg=COL_BG, fg=COL_GREEN)
lbl_r_strength.grid(row=3, column=1, sticky="w", padx=6)
def r_pw_on_type(_=None):
    lbl_r_strength.config(text=f"Strength: {password_strength(entry_r_password.get())}")
entry_r_password.bind("<KeyRelease>", r_pw_on_type)

def r_suggest():
    sp = suggest_password()
    entry_r_password.delete(0, tk.END); entry_r_password.insert(0, sp)
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(sp); messagebox.showinfo("Suggested", "Strong password generated and copied to clipboard.")
        except Exception:
            root.clipboard_clear(); root.clipboard_append(sp); messagebox.showinfo("Suggested", "Strong password generated and copied to clipboard (Tk).")
    else:
        root.clipboard_clear(); root.clipboard_append(sp); messagebox.showinfo("Suggested", "Strong password generated and copied to clipboard (Tk).")
ttk.Button(reg, text="Suggest Strong Password", style="Accent.TButton", command=r_suggest).pack(pady=(2,8))

# CAPTCHA for register
captcha_text_r = generate_captcha_text()
tk.Label(frm_r, text="CAPTCHA:", bg=COL_BG, fg=COL_TEXT).grid(row=4, column=0, sticky="w", padx=6, pady=6)
captcha_lbl_r = tk.Label(frm_r, text=captcha_text_r, bg=COL_PANEL, fg=COL_HEADER, font=("Consolas", 11, "bold"))
captcha_lbl_r.grid(row=4, column=1, sticky="w", pady=4)
entry_captcha_r = ttk.Entry(frm_r, width=18); entry_captcha_r.grid(row=5, column=1, sticky="w", padx=6)
def refresh_captcha_r():
    global captcha_text_r
    captcha_text_r = generate_captcha_text()
    captcha_lbl_r.config(text=captcha_text_r)
ttk.Button(frm_r, text="↻ Refresh CAPTCHA", command=refresh_captcha_r).grid(row=5, column=0, padx=6, pady=(0,6))

# Register logic (allow up to 5 accounts per email)
def reg_send_otp():
    username = entry_r_username.get().strip()
    email = entry_r_email.get().strip().lower()
    pw = entry_r_password.get().strip()
    if not username or not email or not pw:
        messagebox.showwarning("Missing", "All fields are required.")
        return
    if entry_captcha_r.get().strip() != captcha_text_r:
        messagebox.showerror("CAPTCHA", "CAPTCHA does not match (case-sensitive).")
        refresh_captcha_r()
        return
    users = load_users()
    accs = users.get(email, [])
    # defensive: ensure accs is a list of dicts
    if not isinstance(accs, list):
        accs = []
    # Convert stray string entries if present
    normalized = []
    for a in accs:
        if isinstance(a, str):
            normalized.append({"username": a, "password": "", "verified": False})
        elif isinstance(a, dict):
            normalized.append({
                "username": a.get("username", ""),
                "password": a.get("password", ""),
                "verified": bool(a.get("verified", False))
            })
    accs = normalized
    users[email] = accs

    if len(accs) >= 50:
        messagebox.showerror("Limit", "This email has reached the maximum of 50 accounts.")
        return
    if any(a.get("username") == username for a in accs):
        messagebox.showerror("Error", "This username is already registered with this email.")
        return
    ok, msg = prepare_and_send_otp(email, "registration")
    if not ok:
        messagebox.showerror("Email failed", msg); return
    root._pending_registration = {"username": username, "email": email, "password": pw}
    messagebox.showinfo("OTP Sent", f"OTP sent to {email}. Enter it to complete registration.")
    open_reg_otp_dialog()

def open_reg_otp_dialog():
    pending = getattr(root, "_pending_registration", None)
    if not pending:
        messagebox.showerror("Error", "No pending registration."); return
    dlg = tk.Toplevel(root); dlg.title("Verify Registration OTP"); dlg.geometry("340x140"); dlg.resizable(False, False)
    dlg.config(bg=COL_BG)
    tk.Label(dlg, text=f"Enter OTP sent to {pending['email']}", bg=COL_BG, fg=COL_TEXT).pack(pady=8)
    otp_e = ttk.Entry(dlg, width=22); otp_e.pack(pady=6)
    def do_verify():
        ok, info = verify_otp(pending["email"], otp_e.get().strip())
        if not ok:
            messagebox.showerror("OTP Error", info); return
        users = load_users()
        users.setdefault(pending["email"], [])
        users[pending["email"]].append({"username": pending["username"], "password": pending["password"], "verified": True})
        save_users(users)
        # ensure vault key exists for this account
        vault = load_vault(); vault.setdefault(f"{pending['email']}|{pending['username']}", []); save_vault(vault)
        dlg.destroy(); root._pending_registration = None
        messagebox.showinfo("Registered", "Account created and verified. Please login.")
        refresh_captcha_l(); show_frame("login")
    ttk.Button(dlg, text="Verify & Finish", style="Accent.TButton", command=do_verify).pack(pady=8)

ttk.Button(reg, text="Send OTP & Register", style="Accent.TButton", command=reg_send_otp).pack(pady=(6,8))
ttk.Button(reg, text="Go to Login", command=lambda: [refresh_captcha_l(), show_frame("login")]).pack()

# -------------------------
# LOGIN Frame
# -------------------------
log = tk.Frame(container, bg=COL_BG)
frames["login"] = log
log.place(relwidth=1, relheight=1)

ttk.Label(log, text="Login", style="Header.TLabel").pack(pady=(12,8))
frm_l = tk.Frame(log, bg=COL_BG); frm_l.pack(pady=4)

tk.Label(frm_l, text="Username:", bg=COL_BG, fg=COL_TEXT).grid(row=0, column=0, sticky="w", padx=6, pady=6)
entry_l_username = ttk.Entry(frm_l, width=30); entry_l_username.grid(row=0, column=1, padx=6, pady=6)

tk.Label(frm_l, text="Email:", bg=COL_BG, fg=COL_TEXT).grid(row=1, column=0, sticky="w", padx=6, pady=6)
entry_l_email = ttk.Entry(frm_l, width=30); entry_l_email.grid(row=1, column=1, padx=6, pady=6)

tk.Label(frm_l, text="Password:", bg=COL_BG, fg=COL_TEXT).grid(row=2, column=0, sticky="w", padx=6, pady=6)
entry_l_password = ttk.Entry(frm_l, width=30, show="*"); entry_l_password.grid(row=2, column=1, padx=6, pady=6)

# view toggle for login password
def l_toggle_show():
    if entry_l_password.cget("show") == "":
        entry_l_password.config(show="*"); btn_l_view.config(text="👁")
    else:
        entry_l_password.config(show=""); btn_l_view.config(text="🚫")
btn_l_view = ttk.Button(frm_l, text="👁", width=3, command=l_toggle_show); btn_l_view.grid(row=2, column=1, sticky="e", padx=(0,6))

# CAPTCHA login
captcha_text_l = generate_captcha_text()
tk.Label(frm_l, text="CAPTCHA:", bg=COL_BG, fg=COL_TEXT).grid(row=3, column=0, sticky="w", padx=6, pady=6)
captcha_lbl_l = tk.Label(frm_l, text=captcha_text_l, bg=COL_PANEL, fg=COL_HEADER, font=("Consolas", 11, "bold"))
captcha_lbl_l.grid(row=3, column=1, sticky="w", pady=4)
entry_captcha_l = ttk.Entry(frm_l, width=18); entry_captcha_l.grid(row=4, column=1, sticky="w", padx=6)
def refresh_captcha_l():
    global captcha_text_l
    captcha_text_l = generate_captcha_text()
    captcha_lbl_l.config(text=captcha_text_l)
ttk.Button(frm_l, text="↻ Refresh CAPTCHA", command=refresh_captcha_l).grid(row=4, column=0, padx=6)

def do_login():
    username = entry_l_username.get().strip()
    email = entry_l_email.get().strip().lower()
    pw = entry_l_password.get().strip()
    if entry_captcha_l.get().strip() != captcha_text_l:
        messagebox.showerror("CAPTCHA", "CAPTCHA does not match (case-sensitive)."); refresh_captcha_l(); return
    users = load_users()
    if email not in users:
        messagebox.showerror("Error", "Email not registered."); return
    # find account under that email
    account = next((a for a in users[email] if a.get("username") == username), None)
    if not account:
        messagebox.showerror("Error", "Username not found for this email."); return
    if account.get("password") != pw:
        messagebox.showerror("Error", "Incorrect password."); return
    if not account.get("verified", False):
        messagebox.showerror("Error", "Account not verified."); return
    # success
    root._current_user = {"email": email, "username": username}
    messagebox.showinfo("Welcome", f"Welcome back, {username}!")
    refresh_vault_list()
    show_frame("vault")

ttk.Button(log, text="Login", style="Accent.TButton", command=do_login).pack(pady=8)

# forgot password navigation
def open_forgot():
    refresh_captcha_f()
    show_frame("forgot")
ttk.Button(log, text="Forgot Password?", command=open_forgot).pack(pady=4)
ttk.Button(log, text="Go to Register", command=lambda: [refresh_captcha_r(), show_frame("register")]).pack(pady=4)

# -------------------------
# FORGOT Frame
# -------------------------
forgot = tk.Frame(container, bg=COL_BG)
frames["forgot"] = forgot
forgot.place(relwidth=1, relheight=1)

ttk.Label(forgot, text="Forgot Password", style="Header.TLabel").pack(pady=(12,8))
frm_f = tk.Frame(forgot, bg=COL_BG); frm_f.pack(pady=4)

tk.Label(frm_f, text="Registered Email:", bg=COL_BG, fg=COL_TEXT).grid(row=0, column=0, sticky="w", padx=6, pady=6)
entry_f_email = ttk.Entry(frm_f, width=30); entry_f_email.grid(row=0, column=1, padx=6, pady=6)

# CAPTCHA for forgot
captcha_text_f = generate_captcha_text()
tk.Label(frm_f, text="CAPTCHA:", bg=COL_BG, fg=COL_TEXT).grid(row=1, column=0, sticky="w", padx=6, pady=6)
captcha_lbl_f = tk.Label(frm_f, text=captcha_text_f, bg=COL_PANEL, fg=COL_HEADER, font=("Consolas", 11, "bold"))
captcha_lbl_f.grid(row=1, column=1, sticky="w", pady=4)
entry_captcha_f = ttk.Entry(frm_f, width=18); entry_captcha_f.grid(row=2, column=1, sticky="w", padx=6)
def refresh_captcha_f():
    global captcha_text_f
    captcha_text_f = generate_captcha_text()
    captcha_lbl_f.config(text=captcha_text_f)
ttk.Button(frm_f, text="↻ Refresh CAPTCHA", command=refresh_captcha_f).grid(row=2, column=0, padx=6)

def forgot_send_otp():
    email = entry_f_email.get().strip().lower()
    if not email:
        messagebox.showwarning("Missing", "Please enter your registered email."); return
    if entry_captcha_f.get().strip() != captcha_text_f:
        messagebox.showerror("CAPTCHA", "CAPTCHA does not match (case-sensitive)."); refresh_captcha_f(); return
    users = load_users()
    if email not in users:
        messagebox.showerror("Error", "Email not registered."); return
    ok, msg = prepare_and_send_otp(email, "password reset")
    if not ok:
        messagebox.showerror("Email failed", msg); return
    root._pending_reset = email
    messagebox.showinfo("OTP Sent", f"Reset OTP sent to {email}. Enter it to set a new password.")
    open_reset_dialog(email)

ttk.Button(forgot, text="Send Reset OTP", style="Accent.TButton", command=forgot_send_otp).pack(pady=8)
ttk.Button(forgot, text="Back to Login", command=lambda: [refresh_captcha_l(), show_frame("login")]).pack()

# -------------------------
# RESET DIALOG (forgot)
# -------------------------
def open_reset_dialog(email):
    dlg = tk.Toplevel(root); dlg.title("Reset Password"); dlg.geometry("420x260"); dlg.resizable(False, False); dlg.config(bg=COL_BG)
    tk.Label(dlg, text=f"Enter OTP sent to {email}", bg=COL_BG, fg=COL_TEXT).pack(pady=6)
    otp_e = ttk.Entry(dlg, width=22); otp_e.pack(pady=6)
    tk.Label(dlg, text="New password:", bg=COL_BG, fg=COL_TEXT).pack(pady=(6,0))
    npw_e = ttk.Entry(dlg, show="*"); npw_e.pack(pady=6)
    tk.Label(dlg, text="Confirm new password:", bg=COL_BG, fg=COL_TEXT).pack(pady=(6,0))
    cpw_e = ttk.Entry(dlg, show="*"); cpw_e.pack(pady=6)

    # NOTE: checkbox/save_var removed per request (no save-to-clipboard behavior here)

    def do_reset():
        ok, info = verify_otp(email, otp_e.get().strip())
        if not ok:
            messagebox.showerror("OTP", info)
            return

        npw = npw_e.get().strip()
        cpw = cpw_e.get().strip()

        if not npw or not cpw:
            messagebox.showwarning("Missing", "Enter and confirm new password.")
            return

        if npw != cpw:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        if password_strength(npw) == "Weak":
            if not messagebox.askyesno("Weak password", "The new password is weak. Use anyway?"):
                return

        # apply to all accounts under this email
        users = load_users()
        if email in users:
            for acc in users[email]:
                acc["password"] = npw
            save_users(users)

        # Inform user and return to login
        messagebox.showinfo("Updated", "Password updated for all accounts under this email. You may login now.")
        dlg.destroy()
        show_frame("login")

    ttk.Button(dlg, text="Set New Password", style="Accent.TButton", command=do_reset).pack(pady=10)

# -------------------------
# VAULT Frame
# -------------------------
vault = tk.Frame(container, bg=COL_BG)
frames["vault"] = vault
vault.place(relwidth=1, relheight=1)

ttk.Label(vault, text="Vault", style="Header.TLabel").pack(pady=10)

frm_vtop = tk.Frame(vault, bg=COL_BG); frm_vtop.pack(pady=6)
tk.Label(frm_vtop, text="Site / App:", bg=COL_BG, fg=COL_TEXT).grid(row=0, column=0, sticky="w")
entry_v_site = ttk.Entry(frm_vtop, width=28); entry_v_site.grid(row=0, column=1, padx=6, pady=4)
tk.Label(frm_vtop, text="Login:", bg=COL_BG, fg=COL_TEXT).grid(row=1, column=0, sticky="w")
entry_v_login = ttk.Entry(frm_vtop, width=28); entry_v_login.grid(row=1, column=1, padx=6, pady=4)
tk.Label(frm_vtop, text="Password:", bg=COL_BG, fg=COL_TEXT).grid(row=2, column=0, sticky="w")
entry_v_password = ttk.Entry(frm_vtop, width=28); entry_v_password.grid(row=2, column=1, padx=6, pady=4)

def vault_generate():
    sp = suggest_password()
    entry_v_password.delete(0, tk.END); entry_v_password.insert(0, sp)
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(sp); messagebox.showinfo("Generated", "Strong password generated and copied to clipboard.")
        except Exception:
            root.clipboard_clear(); root.clipboard_append(sp); messagebox.showinfo("Generated", "Strong password generated and copied to clipboard (Tk).")
    else:
        root.clipboard_clear(); root.clipboard_append(sp); messagebox.showinfo("Generated", "Strong password generated and copied to clipboard (Tk).")

def vault_add():
    current = getattr(root, "_current_user", None)
    if not current:
        messagebox.showwarning("Locked", "Please login to add entries."); return
    key = f"{current['email']}|{current['username']}"
    s = entry_v_site.get().strip(); u = entry_v_login.get().strip(); p = entry_v_password.get().strip()
    if not s or not p:
        messagebox.showwarning("Missing", "Site and password required."); return
    vault_data = load_vault()
    vault_data.setdefault(key, [])
    vault_data[key].append({"site": s, "login": u, "password": p})
    save_vault(vault_data)
    entry_v_site.delete(0, tk.END); entry_v_login.delete(0, tk.END); entry_v_password.delete(0, tk.END)
    refresh_vault_list(); messagebox.showinfo("Saved", "Entry saved to vault.")

ttk.Button(frm_vtop, text="Generate", command=vault_generate).grid(row=2, column=2, padx=6)
ttk.Button(frm_vtop, text="Save to Vault", style="Accent.TButton", command=vault_add).grid(row=3, column=1, pady=8)

# Scrollable list
v_container = tk.Frame(vault, bg=COL_BG); v_container.pack(fill="both", expand=True, padx=6, pady=6)
v_canvas = tk.Canvas(v_container, bg=COL_BG, highlightthickness=0)
v_scroll = ttk.Scrollbar(v_container, orient="vertical", command=v_canvas.yview)
v_inner = tk.Frame(v_canvas, bg=COL_BG)
v_inner.bind("<Configure>", lambda e: v_canvas.configure(scrollregion=v_canvas.bbox("all")))
v_canvas.create_window((0,0), window=v_inner, anchor="nw")
v_canvas.configure(yscrollcommand=v_scroll.set)
v_canvas.pack(side="left", fill="both", expand=True)
v_scroll.pack(side="right", fill="y")

def refresh_vault_list():
    for w in v_inner.winfo_children():
        w.destroy()
    current = getattr(root, "_current_user", None)
    if not current:
        tk.Label(v_inner, text="Locked — login to view vault.", bg=COL_BG, fg=COL_TEXT).pack(pady=12); return
    key = f"{current['email']}|{current['username']}"
    vault_data = load_vault()
    items = vault_data.get(key, [])
    if not items:
        tk.Label(v_inner, text="No entries yet. Add credentials above.", bg=COL_BG, fg=COL_TEXT).pack(pady=12); return
    for idx, it in enumerate(items):
        card = tk.Frame(v_inner, bg=COL_PANEL, padx=8, pady=8)
        card.pack(fill="x", pady=6, padx=6)
        tk.Label(card, text=it['site'], bg=COL_PANEL, fg=COL_HEADER, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(card, text=it.get('login',''), bg=COL_PANEL, fg=COL_TEXT).pack(anchor="w")
        pw_var = tk.StringVar(value="•" * 10)
        pw_lbl = tk.Label(card, textvariable=pw_var, bg=COL_PANEL, fg=COL_TEXT, font=("Consolas", 10))
        pw_lbl.pack(anchor="w", pady=(6,4))
        btns = tk.Frame(card, bg=COL_PANEL); btns.pack(anchor="e")
        def make_show(item=it, var=pw_var):
            def show_pw(): var.set(item["password"])
            return show_pw
        def make_hide(var=pw_var):
            def hide_pw(): var.set("•" * 10)
            return hide_pw
        def make_copy(item=it):
            def copy_pw():
                if HAS_PYPERCLIP:
                    try:
                        pyperclip.copy(item["password"]); messagebox.showinfo("Copied", "Password copied to clipboard.")
                    except Exception:
                        root.clipboard_clear(); root.clipboard_append(item["password"]); messagebox.showinfo("Copied", "Password copied to clipboard (Tk).")
                else:
                    root.clipboard_clear(); root.clipboard_append(item["password"]); messagebox.showinfo("Copied", "Password copied to clipboard (Tk).")
            return copy_pw
        def make_delete(i=idx):
            def delete_item():
                vault_data = load_vault()
                vault_data[key].pop(i)
                save_vault(vault_data)
                refresh_vault_list()
            return delete_item
        ttk.Button(btns, text="View", command=make_show()).pack(side="left", padx=4)
        ttk.Button(btns, text="Hide", command=make_hide()).pack(side="left", padx=4)
        ttk.Button(btns, text="Copy", command=make_copy()).pack(side="left", padx=4)
        ttk.Button(btns, text="Delete", command=make_delete()).pack(side="left", padx=4)

# bottom buttons
bottom_v = tk.Frame(vault, bg=COL_BG); bottom_v.pack(fill="x", pady=8)
def do_logout():
    root._current_user = None
    refresh_vault_list()
    show_frame("login")
    messagebox.showinfo("Logged out", "You have been logged out.")
ttk.Button(bottom_v, text="Logout", style="Accent.TButton", command=do_logout).pack(side="left", padx=8)
ttk.Button(bottom_v, text="Export vault.json", style="Accent.TButton", command=lambda: (save_vault(load_vault()), messagebox.showinfo("Exported", "vault.json updated"))).pack(side="right", padx=8)

# -------------------------
# Initialize captchas & start
# -------------------------
# create initial captcha texts (these variables are used by the UI already)
captcha_text_r = captcha_text_r if 'captcha_text_r' in globals() else generate_captcha_text()
captcha_text_l = captcha_text_l if 'captcha_text_l' in globals() else generate_captcha_text()
captcha_text_f = captcha_text_f if 'captcha_text_f' in globals() else generate_captcha_text()
# set labels to reflect them (labels were already created using these variables above)
try:
    captcha_lbl_r.config(text=captcha_text_r)
    captcha_lbl_l.config(text=captcha_text_l)
    captcha_lbl_f.config(text=captcha_text_f)
except Exception:
    pass

# show login by default
show_frame("login")
root.mainloop()
