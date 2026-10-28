from flask import Blueprint, render_template
from app.auth import login_required, get_current_user
from core.db import DB
from config import Config

dashboard_bp = Blueprint('dashboard_bp', __name__)


@dashboard_bp.route('/')
@login_required
def dashboard():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT COUNT(*) as c FROM devices")
        devices_count = cur.fetchone()['c']
        cur = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status = 'open'")
        open_findings = cur.fetchone()['c']
        cur = conn.execute("SELECT COUNT(*) as c FROM scans")
        scans_count = cur.fetchone()['c']
        cur = conn.execute("SELECT * FROM findings WHERE status = 'open' ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id DESC LIMIT 10")
        findings = [dict(r) for r in cur.fetchall()]
        user = get_current_user()
        return render_template('dashboard.html', devices_count=devices_count, open_findings=open_findings, scans_count=scans_count, findings=findings, user=user)
    finally:
        conn.close()
