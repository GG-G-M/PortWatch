from flask import Blueprint, render_template
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from config import Config

audit_bp = Blueprint('audit_bp', __name__)


@audit_bp.route('/audit')
@login_required
@role_required('Administrator')
def audit():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id ORDER BY a.id DESC LIMIT 200")
        logs = [dict(r) for r in cur.fetchall()]
        user = get_current_user()
        return render_template('audit.html', logs=logs, user=user)
    finally:
        conn.close()
