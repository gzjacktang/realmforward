#!/usr/bin/env python3
import secrets
import sqlite3
import subprocess
import sys
import urllib.request
import ssl
import json

try:
    import bcrypt
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "bcrypt"])
    import bcrypt

DB = "/var/lib/realmfp/panel.db"
alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
plain = "".join(secrets.choice(alphabet) for _ in range(16))
hashed = bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

conn = sqlite3.connect(DB)
row = conn.execute("SELECT username FROM users WHERE id=1").fetchone()
user = row[0] if row else "admin"
conn.execute(
    "UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=1",
    (hashed,),
)
if conn.total_changes == 0:
    user = "admin"
    conn.execute(
        "INSERT INTO users(id, username, password_hash) VALUES(1, ?, ?)",
        (user, hashed),
    )
conn.execute("DELETE FROM sessions")
conn.commit()
conn.close()

ctx = ssl._create_unverified_context()
base = "/"
try:
    with open("/var/lib/realmfp/config.json") as f:
        base = (json.load(f).get("base_path") or "/").rstrip("/")
except Exception:
    pass
login_url = f"https://127.0.0.1:2888{base}/api/login"
req = urllib.request.Request(
    login_url,
    data=json.dumps({"username": user, "password": plain}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        ok = resp.read().decode()
except Exception as e:
    ok = f"login_check_failed: {e}"

print(f"USER={user}")
print(f"PASS={plain}")
print(f"LOGIN_URL={login_url}")
print(f"CHECK={ok}")
