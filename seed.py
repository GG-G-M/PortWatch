# PortWatch seed script
import os
import json
from core.db import init_db, DB
from app.auth import hash_password
from config import Config


def seed():
    os.makedirs(Config.INSTANCE_DIR, exist_ok=True)
    init_db()
    db = DB()

    # Roles
    db.upsert_role('Administrator', 'Full access')
    db.upsert_role('Lab Technician / Security Analyst', 'Scan and triage')
    db.upsert_role('Viewer', 'Read-only')

    # Get role ids
    conn = db.connect()
    try:
        cur = conn.execute("SELECT id, name FROM roles")
        roles = {r['name']: r['id'] for r in cur.fetchall()}
    finally:
        conn.close()

    # Admin user
    pw_hash, salt = hash_password('admin123')
    conn = db.connect()
    try:
        conn.execute("INSERT OR IGNORE INTO users (username, password_hash, salt, role_id, active) VALUES (?, ?, ?, ?, 1)",
                     ('admin', pw_hash, salt, roles['Administrator']))
        conn.commit()
    finally:
        conn.close()

    # Demo device
    did = db.add_device('127.0.0.1', hostname='localhost', location='lab')
    conn = db.connect()
    try:
        conn.execute("INSERT OR IGNORE INTO authorizations (device_id, authorized_by, reason, expires_at) VALUES (?, 'admin', 'demo', '2099-12-31T23:59:59Z')", (did,))
        conn.commit()
    finally:
        conn.close()

    # Allowlist
    db.add_allowlist_entry(did, 22, 'tcp', 'ssh')
    db.add_allowlist_entry(did, 80, 'tcp', 'http')

    print('Seed complete. Login: admin / admin123')


if __name__ == '__main__':
    seed()
