from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from config import Config

devices_bp = Blueprint('devices_bp', __name__)


@devices_bp.route('/devices')
@login_required
def devices():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT * FROM devices ORDER BY id")
        devices = [dict(r) for r in cur.fetchall()]
        user = get_current_user()
        return render_template('devices.html', devices=devices, user=user)
    finally:
        conn.close()


@devices_bp.route('/devices/add', methods=['POST'])
@login_required
@role_required('Administrator')
def add_device():
    ip = request.form.get('ip_address', '').strip()
    hostname = request.form.get('hostname', '').strip()
    location = request.form.get('location', '').strip()
    if not ip:
        flash('IP address is required.', 'danger')
        return redirect(url_for('devices_bp.devices'))
    db = DB(Config.DATABASE)
    db.add_device(ip, hostname, location)
    flash('Device added.', 'success')
    return redirect(url_for('devices_bp.devices'))
