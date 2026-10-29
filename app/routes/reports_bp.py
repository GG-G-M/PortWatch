from flask import Blueprint, render_template, send_file
from app.auth import login_required, role_required, get_current_user
from core.db import DB
from config import Config
from app.reports import export_findings_csv
import os
from datetime import datetime

reports_bp = Blueprint('reports_bp', __name__)


@reports_bp.route('/reports')
@login_required
def reports():
    user = get_current_user()
    return render_template('reports.html', user=user)


@reports_bp.route('/reports/findings.csv')
@login_required
@role_required('Administrator', 'Lab Technician / Security Analyst')
def findings_csv():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT * FROM findings ORDER BY id DESC")
        findings = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    out_path = os.path.join(Config.INSTANCE_DIR, 'findings_export.csv')
    export_findings_csv(findings, out_path)
    return send_file(out_path, as_attachment=True, download_name='PortWatch_findings.csv')


@reports_bp.route('/reports/print')
@login_required
def print_report():
    db = DB(Config.DATABASE)
    conn = db.connect()
    try:
        cur = conn.execute("SELECT * FROM findings ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id DESC")
        findings = [dict(r) for r in cur.fetchall()]
        cur2 = conn.execute("SELECT * FROM devices ORDER BY ip_address")
        devices = [dict(r) for r in cur2.fetchall()]
    finally:
        conn.close()
    user = get_current_user()
    return render_template('report_print.html', findings=findings, devices=devices, user=user, now=datetime.now().strftime('%Y-%m-%d %H:%M'))
