import base64
import hashlib
import io
import json
import uuid
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from scs.models import AccessRequest, Event, File, Incident, audit, db, utcnow
from scs.routes.helpers import current_hour, device_id, log_event
from scs.services import access, crypto, dlp, risk, storage

files_bp = Blueprint("files", __name__)


@files_bp.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("files.files"))
    return render_template("landing.html")


@files_bp.route("/landing")
def landing():
    return render_template("landing.html")


@files_bp.route("/files")
@login_required
def files():
    rows = File.query.order_by(File.id.desc()).all()
    active_grants = {}
    pending_requests = set()
    if current_user.is_authenticated:
        try:
            for g in AccessRequest.query.filter_by(user_id=current_user.id, status="approved").filter(AccessRequest.expires_at > utcnow()).all():
                active_grants[g.file_id] = g
            for p in AccessRequest.query.filter_by(user_id=current_user.id, status="pending").all():
                pending_requests.add(p.file_id)
        except Exception:
            pass

    return render_template(
        "files.html",
        files=rows,
        can_upload=access.can(current_user, "upload"),
        check=lambda f: access.can_download(current_user, f)[0],
        file_clearance=access.file_required_clearance,
        clearance_info=access.get_clearance_info,
        active_grants=active_grants,
        pending_requests=pending_requests,
    )


@files_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    if not access.can(current_user, "upload"):
        abort(403)
    up = request.files.get("file")
    if not up or not up.filename:
        flash("Choose a file first.", "danger")
        return redirect(url_for("files"))
    name = secure_filename(up.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in dlp.ALLOWED_EXT:
        flash(
            f"File type .{ext} is not allowed. Allowed: {', '.join(sorted(dlp.ALLOWED_EXT))}",
            "danger",
        )
        return redirect(url_for("files"))
    data = up.read()
    result = dlp.scan_file(data, name)

    # Clearance Level Selection and DLP Escalation
    raw_clr = request.form.get("min_clearance", "1")
    try:
        user_chosen_clr = max(0, min(3, int(raw_clr)))
    except (ValueError, TypeError):
        user_chosen_clr = 1

    # DLP scanning determines base sensitivity and minimum required clearance
    dlp_clr = access.REQUIRED_CLEARANCE.get(result["level"], 1)
    effective_clearance = max(user_chosen_clr, dlp_clr)

    # Secure Deduplication (Report Section 2.7 & 6.6)
    content_hash = hashlib.sha256(data).hexdigest()
    existing = File.query.filter_by(content_hash=content_hash).first()
    store = storage.get_storage(current_app.config.get("BASE_DIR"))

    if existing:
        stored = existing.stored_name
        wrapped = existing.wrapped_dek
        is_dedup = True
    else:
        blob, wrapped = crypto.encrypt(data)
        stored = uuid.uuid4().hex
        store.put(stored, blob)
        is_dedup = False

    f = File(
        owner_id=current_user.id,
        original_name=name,
        stored_name=stored,
        content_hash=content_hash,
        is_deduplicated=is_dedup,
        size=len(data),
        department=current_user.department,
        sensitivity=result["level"],
        sensitivity_score=result["score"],
        min_clearance=effective_clearance,
        dlp_json=json.dumps(result["counts"]),
        wrapped_dek=wrapped,
    )
    db.session.add(f)
    db.session.flush()
    log_event(current_user.id, "upload", "ok", file=f, nbytes=len(data))

    clr_meta = access.get_clearance_info(effective_clearance)
    if is_dedup:
        audit(current_user.username, "upload_deduplicated", f"file={f.id} hash={content_hash[:12]} stored={stored}")
        flash(
            f"Uploaded successfully. Secure deduplication detected identical block. Enforced clearance: {clr_meta['code']} - {clr_meta['name']}.",
            "info",
        )
    else:
        audit(current_user.username, "upload", f"file={f.id} level={f.sensitivity} clearance={effective_clearance}")
        if dlp_clr > user_chosen_clr:
            flash(
                f"Uploaded and encrypted. DLP scanner detected sensitive patterns and escalated clearance to {clr_meta['code']} - {clr_meta['name']} ({result['level'].replace('_', ' ').capitalize()}).",
                "warning",
            )
        else:
            flash(
                f"Uploaded and encrypted. Enforced clearance level: {clr_meta['code']} - {clr_meta['name']}.",
                "success",
            )
    db.session.commit()
    return redirect(url_for("files"))


@files_bp.route("/request-elevation/<int:fid>", methods=["POST"])
@login_required
def request_elevation(fid):
    f = db.session.get(File, fid) or abort(404)
    if current_user.status == "restricted":
        flash("Your account is restricted by the security system. Contact an admin.", "danger")
        return redirect(url_for("files"))

    req_clr = access.file_required_clearance(f)
    if access.can_download(current_user, f)[0]:
        flash("You already possess authorization to access this file.", "info")
        return redirect(url_for("files"))

    # Check if a pending request already exists
    existing = AccessRequest.query.filter_by(
        user_id=current_user.id, file_id=f.id, status="pending"
    ).first()
    if existing:
        flash(f"An elevation request for '{f.original_name}' is already pending administrator review.", "warning")
        return redirect(url_for("files"))

    justification = (request.form.get("justification") or "").strip()
    if not justification or len(justification) < 5:
        flash("Please provide a valid business justification (minimum 5 characters).", "danger")
        return redirect(url_for("files"))

    try:
        hours = max(1, min(72, int(request.form.get("duration_hours", 2))))
    except (ValueError, TypeError):
        hours = 2

    req_obj = AccessRequest(
        user_id=current_user.id,
        file_id=f.id,
        current_clearance=current_user.clearance,
        requested_clearance=req_clr,
        justification=justification[:500],
        duration_hours=hours,
        status="pending",
    )
    db.session.add(req_obj)
    db.session.commit()

    audit(current_user.username, "request_clearance_elevation", f"file={f.id} name={f.original_name} hours={hours}")
    log_event(
        current_user.id,
        "elevation_request",
        "ok",
        file=f,
        reasons=[{"points": 0, "text": f"Requested L{req_clr} elevation: {justification[:60]}"}],
    )
    db.session.commit()

    # Dispatch alert email to administrator
    try:
        from scs.services import mailer
        mailer.send_access_request_alert(req_obj)
    except Exception as e:
        current_app.logger.warning(f"Could not dispatch elevation request alert email: {e}")

    flash(f"Elevation request submitted for '{f.original_name}'. An administrator has been alerted.", "success")
    return redirect(url_for("files"))


@files_bp.route("/download/<int:fid>")
@login_required
def download(fid):
    f = db.session.get(File, fid) or abort(404)
    user = current_user
    mode = request.args.get("mode")

    # Quarantine Lockdown Check (Report Fig 6.1 Step 8)
    if f.is_quarantined:
        log_event(user.id, "download", "denied", file=f, reasons=[{"points": 0, "text": "File is quarantined by security policy"}])
        audit(user.username, "download_blocked_quarantine", f"file={f.id}")
        db.session.commit()
        flash(f"Security Alert: '{f.original_name}' has been QUARANTINED by administrators. All downloads are blocked.", "danger")
        return redirect(url_for("files"))

    # Handle Redacted / Safe Copy Download
    if mode == "redacted":
        if user.status == "restricted":
            flash("Account restricted by the security system. Contact an admin.", "danger")
            return redirect(url_for("files"))
        if not access.can(user, "download"):
            flash(f"Role '{user.role}' may not download files.", "danger")
            return redirect(url_for("files"))

        store = storage.get_storage(current_app.config.get("BASE_DIR"))
        plain = crypto.decrypt(store.get(f.stored_name), f.wrapped_dek)
        text = plain.decode("utf-8", errors="ignore")
        redacted_text = dlp.redact_text(text)
        out_bytes = redacted_text.encode("utf-8")

        log_event(user.id, "download", "allowed", file=f, nbytes=len(out_bytes), score=10,
                  reasons=[{"points": 10, "text": "Redacted copy (all sensitive PII scrubbed)"}])
        audit(user.username, "download_redacted", f"file={f.id}")
        db.session.commit()
        flash("Downloaded safe copy with all sensitive PII, cards, and keys redacted.", "info")
        return send_file(io.BytesIO(out_bytes), as_attachment=True, download_name=f"redacted_{f.original_name}")

    # Standard Raw Download Flow
    # 1. Access Check (RBAC + ABAC)
    ok, why = access.can_download(user, f)
    if not ok:
        log_event(user.id, "download", "denied", file=f, reasons=[{"points": 0, "text": why}])
        audit(user.username, "download_denied", f"file={f.id}: {why}")
        db.session.commit()
        flash(why, "danger")
        return redirect(url_for("files"))

    # 2. Risk Evaluation
    r = risk.assess(user, f, device_id(), current_hour())
    outcome = {"allow": "allowed", "warn": "warned", "block": "blocked"}[r["level"]]
    ev = log_event(
        user.id,
        "download",
        outcome,
        file=f,
        nbytes=f.size,
        score=r["score"],
        reasons=r["reasons"],
    )
    audit(user.username, f"download_{outcome}", f"file={f.id} risk={r['score']}")

    if r["level"] != "allow":
        inc = Incident(
            user_id=user.id,
            event_id=ev.id,
            file_id=f.id,
            level=r["level"],
            risk_score=r["score"],
            reasons_json=json.dumps(r["reasons"]),
        )
        db.session.add(inc)
        db.session.flush()
        try:
            from scs.services import mailer
            mailer.send_security_alert_email(inc)
        except Exception as e:
            current_app.logger.warning(f"Could not dispatch incident email: {e}")

    # 3. Dynamic Enforcement
    if r["level"] == "block":
        recent = Event.query.filter(
            Event.user_id == user.id,
            Event.outcome == "blocked",
            Event.ts >= utcnow() - timedelta(hours=1),
        ).count()
        if recent >= 3 and user.role != "admin":
            user.status = "restricted"
            audit("system", "auto_restrict", f"user={user.username} after {recent} blocks")
            try:
                from scs.services import mailer
                mailer.send_account_restriction_alert(
                    user,
                    reason=f"Automated zero-trust lockout: {recent} blocked exfiltration attempts within 1 hour.",
                )
            except Exception as e:
                current_app.logger.warning(f"Could not dispatch restriction email: {e}")
        db.session.commit()
        flash("Download blocked for security review. An administrator has been alerted via email.", "danger")
        return redirect(url_for("files"))

    db.session.commit()
    if r["level"] == "warn":
        flash(
            "Unusual activity detected. This download was allowed but has been logged for review.",
            "warning",
        )

    store = storage.get_storage(current_app.config.get("BASE_DIR"))
    plain = crypto.decrypt(store.get(f.stored_name), f.wrapped_dek)
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=f.original_name)


@files_bp.route("/preview/<int:fid>")
@login_required
def preview(fid):
    """In-browser zero-exfiltration preview with anti-leak dynamic watermark."""
    f = db.session.get(File, fid) or abort(404)
    user = current_user

    if f.is_quarantined:
        flash(f"Access Denied: '{f.original_name}' is quarantined by administrators.", "danger")
        return redirect(url_for("files"))

    ok, why = access.can_download(user, f)
    is_redacted = False

    if not ok:
        if user.status != "restricted" and user.role != "guest" and f.sensitivity in ("confidential", "highly_confidential"):
            is_redacted = True
        else:
            flash(f"Access Denied: {why}", "danger")
            return redirect(url_for("files"))

    store = storage.get_storage(current_app.config.get("BASE_DIR"))
    plain = crypto.decrypt(store.get(f.stored_name), f.wrapped_dek)

    ext = f.original_name.rsplit(".", 1)[-1].lower() if "." in f.original_name else ""
    is_image = ext in ("png", "jpg", "jpeg", "bmp", "tiff")

    content_display = ""
    image_src = None

    if is_image:
        image_b64 = base64.b64encode(plain).decode("utf-8")
        mime = "image/jpeg" if ext == "jpg" else f"image/{ext}"
        image_src = f"data:{mime};base64,{image_b64}"
    else:
        text = plain.decode("utf-8", errors="ignore")
        if is_redacted:
            text = dlp.redact_text(text)
        content_display = text

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    watermark_text = f"SmartCloud Shield • {user.username.upper()} ({user.department.upper()}) • IP: {ip} • {utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    audit(user.username, "preview_file", f"file={f.id} redacted={is_redacted}")
    db.session.commit()

    return render_template(
        "preview.html",
        file=f,
        is_redacted=is_redacted,
        content_display=content_display,
        image_src=image_src,
        watermark_text=watermark_text,
    )


@files_bp.route("/delete/<int:fid>", methods=["POST"])
@login_required
def delete(fid):
    f = db.session.get(File, fid) or abort(404)
    if f.owner_id != current_user.id and current_user.role != "admin":
        abort(403)

    # Reference-counted storage cleanup for deduplication
    other_refs = File.query.filter(File.stored_name == f.stored_name, File.id != f.id).count()
    if other_refs == 0:
        store = storage.get_storage(current_app.config.get("BASE_DIR"))
        store.delete(f.stored_name)

    audit(current_user.username, "delete", f"file={f.id} shared_refs={other_refs}")
    Event.query.filter_by(file_id=f.id).update({"file_id": None})
    Incident.query.filter_by(file_id=f.id).update({"file_id": None})
    db.session.delete(f)
    db.session.commit()
    flash("File deleted.", "success")
    return redirect(url_for("files"))
