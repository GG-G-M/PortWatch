from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from core.gate import authorize_target, GateError
from config import Config

scans_bp = Blueprint('scans_bp', __name__)


@scans_bp.route('/scans')
@login_required
def scans():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT s.*, u.username FROM scans s LEFT JOIN users u ON u.id = s.requested_by ORDER BY s.id DESC")
        scans = [dict(r) for r in cur.fetchall()]
        cur2 = conn.execute("SELECT * FROM devices ORDER BY ip_address")
        devices = [dict(r) for r in cur2.fetchall()]
        user = get_current_user()
        return render_template('scans.html', scans=scans, devices=devices, user=user)
    finally:
        conn.close()


@scans_bp.route('/scans/trigger', methods=['POST'])
@login_required
@role_required('Administrator', 'Lab Technician / Security Analyst')
def trigger_scan():
    ip = request.form.get('ip_address', '').strip()
    if not ip:
        flash('IP address is required.', 'danger')
        return redirect(url_for('scans_bp.scans'))
    try:
        authorize_target(ip)
    except GateError as e:
        db = DB(Config.DATABASE)
        db.log_audit('GATE_REJECT', target_ip=ip, actor_id=session.get('user_id'), details={'code': e.code, 'reason': e.reason})
        flash(f'Scan blocked by gate: {e.code} {e.reason}', 'danger')
        return redirect(url_for('scans_bp.scans'))
    db = DB(Config.DATABASE)
    db.log_audit('SCAN_TRIGGER', target_ip=ip, actor_id=session.get('user_id'), details={})
    flash('Scan authorization passed (gate OK). Scanner integration pending.', 'info')
    return redirect(url_for('scans_bp.scans'))
