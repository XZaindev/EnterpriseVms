"""Users, password hashing, role checks, login throttling."""
import time
from functools import wraps

from flask import abort, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db, now_iso
from .models import ROLES

RANK = {"viewer": 1, "analyst": 2, "admin": 3}
MIN_PASSWORD = 10
_FAILS = {}  # (username, ip) -> (count, first_ts)
MAX_FAILS, WINDOW = 5, 300


def validate_password(pw):
    if len(pw or "") < MIN_PASSWORD:
        raise ValueError(f"Password must be at least {MIN_PASSWORD} characters.")


def create_user(db, username, password, role):
    username = (username or "").strip()
    if not (3 <= len(username) <= 40):
        raise ValueError("Username must be 3-40 characters.")
    if role not in ROLES:
        raise ValueError("Invalid role.")
    validate_password(password)
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise ValueError("Username already exists.")
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES (?,?,?,?)",
               (username, generate_password_hash(password), role, now_iso()))
    db.commit()


def throttled(key):
    c, t = _FAILS.get(key, (0, 0))
    if c >= MAX_FAILS and time.time() - t < WINDOW:
        return True
    if time.time() - t >= WINDOW:
        _FAILS.pop(key, None)
    return False


def register_fail(key):
    c, t = _FAILS.get(key, (0, time.time()))
    _FAILS[key] = (c + 1, t)


def authenticate(db, username, password):
    row = db.execute("SELECT * FROM users WHERE username=?", ((username or "").strip(),)).fetchone()
    if row and check_password_hash(row["password_hash"], password or ""):
        return row
    return None


def load_user():
    uid = session.get("uid")
    g.user = get_db().execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone() if uid else None


def login_required(role="viewer"):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            load_user()
            if g.user is None:
                return redirect(url_for("main.login", next=request.path))
            if RANK[g.user["role"]] < RANK[role]:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco
