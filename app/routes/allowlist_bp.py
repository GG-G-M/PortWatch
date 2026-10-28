from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from config import Config

allowlist_bp = Blueprint('allowlist_bp', __name__)


@allowlist_bp.route('/allowlist')
@login_required
def allowlist():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT a.*, d.ip_address, d.hostname FROM allowlist a JOIN devices d ON d.id = a.device_id ORDER BY d.ip_address, a.port")
        entries = [dict(r) for r in cur.fetchall()]
        cur2 = conn.execute("SELECT * FROM devices ORDER BY ip_address")
        devices = [dict(r) for r in cur2.fetchall()]
        user = get_current_user()
        return render_template('allowlist.html', entries=entries, devices=devices, user=user)
    finally:
        conn.close()


@allowlist_bp.route('/allowlist/add', methods=['POST'])
@login_required
@role_required('Administrator')
def add_allowlist():
    device_id = request.form.get('device_id')
    port = request.form.get('port')
    protocol = request.form.get('protocol', 'tcp')
    service = request.form.get('service', '').strip()
    if not device_id or not port:
        flash('Device and port are required.', 'danger')
        return redirect(url_for('allowlist_bp.allowlist'))
    try:
        port_i = int(port)
    except ValueError:
        flash('Invalid port.', 'danger')
        return redirect(url_for('allowlist_bp.allowlist'))
    db = DB(Config.DATABASE)
    db.add_allowlist_entry(int(device_id), port_i, protocol, service)
    flash('Allowlist entry added.', 'success')
    return redirect(url_for('allowlist_bp.allowlist'))
