import hashlib
import json
import os
import secrets
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps

from flask import abort, current_app, flash, request, session
from flask_login import current_user, login_required
from scs.models import Device, Event, Otp, db, utcnow
from scs.services import access


def device_id() -> str:
    if current_app.config.get("DEMO_MODE") and request.headers.get("X-Demo-Device"):
        return request.headers["X-Demo-Device"]
    return request.cookies.get("did") or request.environ.get("scs_did", "unknown")


def current_hour() -> int:
    if current_app.config.get("DEMO_MODE") and request.headers.get("X-Demo-Hour"):
        return int(request.headers["X-Demo-Hour"])
    offset = current_app.config.get("TZ_OFFSET_MIN", 330)
    return (utcnow() + timedelta(minutes=offset)).hour


def touch_device(user):
    did = device_id()
    d = Device.query.filter_by(user_id=user.id, device_id=did).first()
    if d is None:
        db.session.add(Device(user_id=user.id, device_id=did))
    else:
        d.last_seen = utcnow()


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user.is_authenticated:
            if request.path.startswith("/api/"):
                return {"success": False, "error": "Authentication required. Please sign in as admin."}, 401
            from scs import login_manager
            return login_manager.unauthorized()
        if not access.can(current_user, "dashboard"):
            if request.path.startswith("/api/"):
                return {"success": False, "error": "Admin clearance required."}, 403
            abort(403)
        return fn(*a, **kw)

    return wrapper


def log_event(user_id, action, outcome, file=None, nbytes=0, score=None, reasons=None):
    ev = Event(
        user_id=user_id,
        action=action,
        outcome=outcome,
        file_id=file.id if file else None,
        nbytes=nbytes,
        ip=request.remote_addr,
        device_id=device_id(),
        risk_score=score,
        reasons_json=json.dumps(reasons) if reasons else None,
    )
    db.session.add(ev)
    db.session.flush()
    return ev


def send_otp(user):
    code = f"{secrets.randbelow(10**6):06d}"
    Otp.query.filter_by(user_id=user.id, used=False).update({"used": True})
    db.session.add(
        Otp(
            user_id=user.id,
            code_hash=hashlib.sha256(f"{user.id}:{code}".encode()).hexdigest(),
            expires_at=utcnow() + timedelta(minutes=5),
        )
    )
    db.session.commit()
    current_app.config["DEBUG_OTPS"][user.id] = code if current_app.config.get("DEMO_MODE") else None

    # Dispatch branded verification email via proper mailer
    from scs.services import mailer
    mailer.send_otp_email(
        user=user,
        code=code,
        ip=request.remote_addr or "127.0.0.1",
        device_id=device_id(),
    )

    # Always log OTP exclusively to terminal console
    print(f"\n{'='*56}", flush=True)
    print(f" [MFA VERIFICATION] User: '{user.username}' ({user.email})", flush=True)
    print(f" >>> ONE-TIME PASSCODE (OTP): {code} <<<", flush=True)
    print(f"{'='*56}\n", flush=True)

    flash(f"Verification code sent to {user.email}.", "info")
