import os
from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)

    from app.routes.auth_bp import auth_bp
    from app.routes.dashboard_bp import dashboard_bp
    from app.routes.devices_bp import devices_bp
    from app.routes.allowlist_bp import allowlist_bp
    from app.routes.scans_bp import scans_bp
    from app.routes.findings_bp import findings_bp
    from app.routes.audit_bp import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(allowlist_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(audit_bp)

    return app
