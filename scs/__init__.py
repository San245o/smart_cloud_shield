import os
import uuid
from pathlib import Path

from flask import Flask, request, url_for
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from scs.config import Config
from scs.models import User, db

csrf = CSRFProtect()
login_manager = LoginManager()

from scs.routes import admin_bp, auth_bp, files_bp


def create_app(db_uri=None, config_class=Config):
    """Application factory for Smart Cloud Shield."""
    base_path = Path(__file__).resolve().parent
    template_dir = base_path / "templates"
    static_dir = base_path / "static"

    # Fallback to root templates/static if not yet moved
    if not template_dir.exists():
        template_dir = base_path.parent / "templates"
    if not static_dir.exists():
        static_dir = base_path.parent / "static"

    app = Flask(
        __name__,
        instance_path=str(config_class.INSTANCE_DIR),
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    import jinja2
    app.jinja_loader = jinja2.ChoiceLoader([
        jinja2.FileSystemLoader(str(template_dir)),
        jinja2.FileSystemLoader(str(base_path.parent / "templates")),
    ])
    app.config.from_object(config_class)

    if db_uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = db_uri

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)

    # Official Flask URL build error handler for seamless legacy endpoint aliasing
    endpoint_aliases = {
        "login": "auth.login",
        "register": "auth.register",
        "otp": "auth.otp",
        "logout": "auth.logout",
        "index": "files.index",
        "files": "files.files",
        "upload": "files.upload",
        "download": "files.download",
        "delete": "files.delete",
        "dashboard": "admin.dashboard",
        "api_stats": "admin.api_stats",
        "incidents": "admin.incidents",
        "resolve_incident": "admin.resolve_incident",
        "users": "admin.users",
        "update_user": "admin.update_user",
        "audit_view": "admin.audit_view",
        "preview": "files.preview",
        "quarantine_file": "admin.toggle_quarantine",
        "integrity_check": "admin.integrity_check",
        "ai_insights": "admin.ai_insights",
        "landing": "files.landing",
    }

    def handle_url_build_error(error, endpoint, values):
        target = endpoint_aliases.get(endpoint)
        if target:
            return url_for(target, **values)
        return None

    app.url_build_error_handlers.append(handle_url_build_error)

    # Security headers & device cookie middleware
    @app.after_request
    def apply_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        resp.headers["Cache-Control"] = "no-store"
        if not request.cookies.get("did") and not request.headers.get("X-Demo-Device"):
            resp.set_cookie(
                "did",
                uuid.uuid4().hex,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax",
            )
        return resp

    with app.app_context():
        db.create_all()
        # Safe schema migration for new columns on SQLite
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE file ADD COLUMN min_clearance INTEGER DEFAULT 1"))
                conn.commit()
        except Exception:
            pass
        # Auto-seed baseline users, encrypted files, and telemetry events if not present
        try:
            from scripts.seed import seed_if_needed
            seed_if_needed()
        except Exception as e:
            app.logger.warning(f"seed_if_needed skipped: {e}")

        # Auto-sync user emails to configured accounts (handles cloud deployments where DB was seeded before env vars)
        try:
            target_admin = os.environ.get("ADMIN_ALERT_EMAIL") or os.environ.get("MAIL_USER") or "uiuxlab123456@gmail.com"
            if "sankeerth" in target_admin.lower():
                target_admin = "uiuxlab123456@gmail.com"
            target_alice = os.environ.get("ALICE_EMAIL") or "raghavendranr28781@gmail.com"
            target_bob = os.environ.get("BOB_EMAIL") or "raghavendranr1218@gmail.com"

            admin_u = User.query.filter_by(username="admin").first()
            if admin_u and ("corp.example" in admin_u.email or admin_u.email != target_admin):
                admin_u.email = target_admin

            alice_u = User.query.filter_by(username="alice").first()
            if alice_u and "corp.example" in alice_u.email:
                alice_u.email = target_alice

            bob_u = User.query.filter_by(username="bob").first()
            if bob_u and "corp.example" in bob_u.email:
                bob_u.email = target_bob

            db.session.commit()
        except Exception:
            pass

    return app
