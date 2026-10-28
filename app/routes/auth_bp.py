from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from core.db import DB
from app.auth import verify_password, get_current_user
from config import Config

auth_bp = Blueprint('auth_bp', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = DB(Config.DATABASE)
        conn = db.connect()
        try:
            cur = conn.execute("SELECT id, username, password_hash, salt, role_id, active FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            if not user or not user['active']:
                flash('Invalid credentials.', 'danger')
                return render_template('login.html')
            if not verify_password(password, user['password_hash'], user['salt']):
                flash('Invalid credentials.', 'danger')
                return render_template('login.html')
            # get role
            cur2 = conn.execute("SELECT name FROM roles WHERE id = ?", (user['role_id'],))
            role = cur2.fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role_name'] = role['name'] if role else ''
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next') or url_for('dashboard_bp.dashboard')
            return redirect(next_url)
        finally:
            conn.close()
    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('auth_bp.login'))
