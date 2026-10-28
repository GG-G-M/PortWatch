from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from config import Config

findings_bp = Blueprint('findings_bp', __name__)


@findings_bp.route('/findings')
@login_required
def findings():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT * FROM findings ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id DESC")
        findings = [dict(r) for r in cur.fetchall()]
        user = get_current_user()
        return render_template('findings.html', findings=findings, user=user)
    finally:
        conn.close()


@findings_bp.route('/findings/ack', methods=['POST'])
@login_required
@role_required('Administrator', 'Lab Technician / Security Analyst')
def ack_finding():
    fid = request.form.get('finding_id')
    if not fid:
        flash('Missing finding.', 'danger')
        return redirect(url_for('findings_bp.findings'))
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        conn.execute("UPDATE findings SET status = 'acknowledged' WHERE id = ?", (fid,))
        conn.commit()
        flash('Finding acknowledged.', 'success')
    finally:
        conn.close()
    return redirect(url_for('findings_bp.findings'))


@findings_bp.route('/findings/close', methods=['POST'])
@login_required
@role_required('Administrator', 'Lab Technician / Security Analyst')
def close_finding():
    fid = request.form.get('finding_id')
    note = request.form.get('note', '').strip()
    if not fid:
        flash('Missing finding.', 'danger')
        return redirect(url_for('findings_bp.findings'))
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        conn.execute("UPDATE findings SET status = 'closed', note = ? WHERE id = ?", (note, fid))
        conn.commit()
        flash('Finding closed.', 'success')
    finally:
        conn.close()
    return redirect(url_for('findings_bp.findings'))
