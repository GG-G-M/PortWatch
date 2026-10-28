import os
import hashlib
import hmac
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort

from core.db import DB


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = salt.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310000)
    return dk.hex(), salt.hex()


def verify_password(password: str, password_hash_hex: str, salt_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        dk_check, _ = hash_password(password, salt)
        return hmac.compare_digest(dk_check, password_hash_hex)
    except Exception:
        return False


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('auth_bp.login', next=request.url))
        return f(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to continue.', 'warning')
                return redirect(url_for('auth_bp.login', next=request.url))
            user_role = session.get('role_name', '')
            if roles and user_role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def get_current_user(db_path: str = None):
    if 'user_id' not in session:
        return None
    db = DB(db_path)
    conn = db.connect()
    try:
        cur = conn.execute("""
            SELECT u.id, u.username, u.active, r.name as role_name, r.id as role_id
            FROM users u
            JOIN roles r ON r.id = u.role_id
            WHERE u.id = ?
        """, (session['user_id'],))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
