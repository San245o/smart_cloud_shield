import hashlib
import secrets
from datetime import timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from scs.models import Otp, User, audit, db, utcnow
from scs.routes.helpers import device_id, log_event, send_otp, touch_device

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("files.files"))
    if request.method == "POST":
        f = request.form
        username, pw = f.get("username", "").strip(), f.get("password", "")
        if not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
            flash("Username must be 3-32 letters, digits or underscores.", "danger")
        elif len(pw) < 8 or pw.isalpha() or pw.isdigit():
            flash("Password needs 8+ characters with letters and numbers.", "danger")
        elif "@" not in f.get("email", ""):
            flash("Enter a valid email address.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("That username is taken.", "danger")
        else:
            role = "guest" if f.get("role") == "guest" else "employee"
            u = User(
                username=username,
                email=f["email"].strip(),
                role=role,
                department=f.get("department", "general").strip().lower()[:40] or "general",
                clearance=1,
                password_hash=generate_password_hash(pw),
            )
            db.session.add(u)
            audit(username, "register", f"role={role}")
            db.session.commit()
            flash("Account created. Log in below.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("files.files"))
    if request.method == "POST":
        u = User.query.filter_by(username=request.form.get("username", "").strip()).first()
        pw = request.form.get("password", "")
        if u and u.locked_until and u.locked_until > utcnow():
            flash("Too many failed attempts. Try again in a few minutes.", "danger")
        elif u and check_password_hash(u.password_hash, pw):
            u.failed_logins = 0
            db.session.commit()
            session.clear()
            session["pending_uid"] = u.id
            send_otp(u)
            return redirect(url_for("otp"))
        else:
            if u:
                u.failed_logins += 1
                if u.failed_logins >= 5:
                    u.locked_until = utcnow() + timedelta(minutes=15)
                    u.failed_logins = 0
                log_event(u.id, "login_fail", "failed")
                audit(u.username, "login_fail", "")
                db.session.commit()
            flash("Invalid username or password.", "danger")
    return render_template("login.html")


@auth_bp.route("/otp", methods=["GET", "POST"])
def otp():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    u = db.session.get(User, uid)
    if request.method == "POST":
        rec = Otp.query.filter_by(user_id=uid, used=False).order_by(Otp.id.desc()).first()
        code = request.form.get("code", "").strip()
        if not rec or rec.expires_at < utcnow() or rec.attempts >= 3:
            flash("Code expired or too many attempts. Log in again.", "danger")
            session.clear()
            return redirect(url_for("login"))
        rec.attempts += 1
        ok = secrets.compare_digest(
            rec.code_hash, hashlib.sha256(f"{uid}:{code}".encode()).hexdigest()
        )
        if ok:
            rec.used = True
            session.clear()
            session.permanent = True
            login_user(u)
            touch_device(u)
            log_event(u.id, "login", "ok")
            db.session.commit()
            if u.role == "admin":
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("files.files"))
        db.session.commit()
        flash("Wrong code.", "danger")
    demo_code = session.get("demo_otp") if current_app.config.get("SHOW_OTP") else None
    return render_template("otp.html", user=u, demo_code=demo_code)


@auth_bp.route("/logout")
@login_required
def logout():
    audit(current_user.username, "logout")
    db.session.commit()
    logout_user()
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("login"))
