import hashlib
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="employee")  # admin | employee | guest
    department = db.Column(db.String(40), default="general")
    clearance = db.Column(db.Integer, default=1)  # 0..3
    status = db.Column(db.String(20), default="active")  # active | restricted
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)


class Device(db.Model):
    __tablename__ = "device"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    device_id = db.Column(db.String(64), index=True)
    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)
    trusted = db.Column(db.Boolean, default=False)


class Otp(db.Model):
    __tablename__ = "otp"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    code_hash = db.Column(db.String(64))
    expires_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)


class File(db.Model):
    __tablename__ = "file"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    original_name = db.Column(db.String(255))
    stored_name = db.Column(db.String(64), index=True)
    content_hash = db.Column(db.String(64), index=True)
    is_deduplicated = db.Column(db.Boolean, default=False)
    is_quarantined = db.Column(db.Boolean, default=False)
    size = db.Column(db.Integer)
    department = db.Column(db.String(40))
    sensitivity = db.Column(db.String(30))
    sensitivity_score = db.Column(db.Integer)
    min_clearance = db.Column(db.Integer, default=1)  # 0: Public, 1: Internal, 2: Confidential, 3: Top Secret
    dlp_json = db.Column(db.Text)  # counts only
    wrapped_dek = db.Column(db.LargeBinary)
    created_at = db.Column(db.DateTime, default=utcnow)
    owner = db.relationship("User")


class Event(db.Model):
    __tablename__ = "event"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    action = db.Column(db.String(20), index=True)  # login|login_fail|upload|download|denied
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"))
    nbytes = db.Column(db.Integer, default=0)
    ip = db.Column(db.String(45))
    device_id = db.Column(db.String(64))
    outcome = db.Column(db.String(20))  # allowed | warned | blocked | denied | ok | failed
    risk_score = db.Column(db.Integer)
    reasons_json = db.Column(db.Text)
    user = db.relationship("User")
    file = db.relationship("File")

    @property
    def reasons(self):
        return json.loads(self.reasons_json) if self.reasons_json else []


class Incident(db.Model):
    __tablename__ = "incident"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"))
    level = db.Column(db.String(10))  # warn | block
    risk_score = db.Column(db.Integer)
    reasons_json = db.Column(db.Text)
    status = db.Column(db.String(20), default="open")  # open | resolved | false_positive
    user = db.relationship("User")
    file = db.relationship("File")
    event = db.relationship("Event")

    @property
    def reasons(self):
        return json.loads(self.reasons_json) if self.reasons_json else []


class AccessRequest(db.Model):
    """Just-In-Time (JIT) Break-Glass clearance elevation and temporary access request."""
    __tablename__ = "access_request"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), index=True, nullable=False)
    current_clearance = db.Column(db.Integer, default=1)
    requested_clearance = db.Column(db.Integer, default=2)
    justification = db.Column(db.Text, nullable=False)
    duration_hours = db.Column(db.Integer, default=2)
    status = db.Column(db.String(20), default="pending")  # pending | approved | rejected | expired
    created_at = db.Column(db.DateTime, default=utcnow)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.String(64))
    expires_at = db.Column(db.DateTime)

    user = db.relationship("User")
    file = db.relationship("File")

    @property
    def is_active(self):
        if self.status != "approved":
            return False
        if self.expires_at and self.expires_at < utcnow():
            return False
        return True


class Audit(db.Model):
    """Hash-chained audit log: each row commits to the previous one."""
    __tablename__ = "audit"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow)
    actor = db.Column(db.String(64))
    action = db.Column(db.String(40))
    detail = db.Column(db.Text)
    prev_hash = db.Column(db.String(64))
    hash = db.Column(db.String(64))


def _digest(prev, ts, actor, action, detail):
    raw = json.dumps([prev, ts.isoformat(), actor, action, detail], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def audit(actor, action, detail=""):
    last = Audit.query.order_by(Audit.id.desc()).first()
    prev = last.hash if last else "0" * 64
    ts = utcnow()
    row = Audit(
        ts=ts,
        actor=str(actor),
        action=action,
        detail=detail,
        prev_hash=prev,
        hash=_digest(prev, ts, str(actor), action, detail),
    )
    db.session.add(row)


def verify_audit_chain():
    """Return (ok, first_bad_id). Detects edited or deleted rows."""
    prev = "0" * 64
    for row in Audit.query.order_by(Audit.id).all():
        if row.prev_hash != prev or row.hash != _digest(prev, row.ts, row.actor, row.action, row.detail):
            return False, row.id
        prev = row.hash
    return True, None
