"""Falcon MAG - User model & database"""
import sqlite3
from pathlib import Path
from datetime import datetime
from core.config import settings
from core.security import hash_password, verify_password

DB_PATH = Path(settings.USERS_DB)

def init_users_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            language TEXT DEFAULT 'ar',
            theme TEXT DEFAULT 'dark',
            created_at REAL NOT NULL,
            last_login REAL
        )
    """)
    conn.commit()
    conn.close()

def create_user(username: str, email: str, password: str, role: str = "user") -> dict:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, hash_password(password), role, datetime.now().timestamp())
        )
        conn.commit()
        user_id = cur.lastrowid
        return {"id": user_id, "username": username, "email": email, "role": role}
    except sqlite3.IntegrityError as e:
        raise ValueError(f"User already exists: {e}")
    finally:
        conn.close()

def get_user_by_username(username: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def authenticate_user(username: str, password: str) -> dict | None:
    user = get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().timestamp(), user["id"]))
    conn.commit()
    conn.close()
    return user