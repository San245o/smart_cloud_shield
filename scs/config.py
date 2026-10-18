import os
import secrets
from datetime import timedelta
from pathlib import Path

os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

# Auto-load .env file if present
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    for _line in _env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

# Generate or load runtime secret key
_secret_key_file = INSTANCE_DIR / "secret.key"
if not _secret_key_file.exists():
    _secret_key_file.write_text(secrets.token_hex(32))


class Config:
    """Base application configuration."""
    BASE_DIR = BASE_DIR
    INSTANCE_DIR = INSTANCE_DIR
    SECRET_KEY = os.environ.get("SECRET_KEY") or _secret_key_file.read_text().strip()
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL") or f"sqlite:///{INSTANCE_DIR / 'scs.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB upload limit
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"
    SHOW_OTP = os.environ.get("SHOW_OTP", "0") == "1"
    TZ_OFFSET_MIN = int(os.environ.get("TZ_OFFSET_MIN", "330"))  # IST (+05:30)
    DEBUG_OTPS = {}

    # Email Pipeline (Brevo HTTPS REST API or SMTP Relay)
    BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1").lower() in ("1", "true", "yes")
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "0").lower() in ("1", "true", "yes")
    MAIL_USER = os.environ.get("MAIL_USER")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_FROM = os.environ.get("MAIL_FROM", "security@smartcloudshield.local")
    ADMIN_ALERT_EMAIL = os.environ.get("ADMIN_ALERT_EMAIL")

    # GenAI / LLM Threat Intelligence Configuration
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
