import hashlib
import time
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from scs.models import (
    AccessRequest,
    Audit,
    Device,
    Event,
    File,
    Incident,
    User,
    audit,
    db,
    utcnow,
    verify_audit_chain,
)
from scs import csrf
from scs.routes.helpers import admin_required
from scs.services import ai_agent, crypto, mailer, storage
from scs.services.ai_agent import get_gemini_api_key
from scs.services.mailer import is_smtp_configured

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
@admin_required
def dashboard():
    pending_requests = (
        AccessRequest.query.filter_by(status="pending")
        .order_by(AccessRequest.id.desc())
        .all()
    )
    recent_grants = (
        AccessRequest.query.filter(AccessRequest.status.in_(("approved", "rejected")))
        .order_by(AccessRequest.id.desc())
        .limit(6)
        .all()
    )
    return render_template(
        "admin.html",
        pending_requests=pending_requests,
        recent_grants=recent_grants,
        utcnow=utcnow(),
    )


@admin_bp.route("/admin/access-requests/<int:rid>/approve", methods=["POST"])
@admin_required
def approve_access_request(rid):
    req_obj = db.session.get(AccessRequest, rid) or abort(404)
    if req_obj.status != "pending":
        flash("This elevation request has already been reviewed.", "warning")
        return redirect(url_for("admin.dashboard"))

    now = utcnow()
    req_obj.status = "approved"
    req_obj.reviewed_at = now
    req_obj.reviewed_by = current_user.username
    req_obj.expires_at = now + timedelta(hours=req_obj.duration_hours)
    db.session.commit()

    file_name = req_obj.file.original_name if req_obj.file else f"File #{req_obj.file_id}"
    user_name = req_obj.user.username if req_obj.user else f"User #{req_obj.user_id}"

    audit(
        current_user.username,
        "approve_access_request",
        f"user={user_name} file={file_name} hours={req_obj.duration_hours} expires={req_obj.expires_at.strftime('%Y-%m-%d %H:%M')}",
    )
    db.session.commit()

    # Dispatch notification to user
    try:
        mailer.send_access_decision_notification(req_obj, approved=True)
    except Exception as e:
        current_app.logger.warning(f"Could not dispatch decision notification email: {e}")

    flash(
        f"Approved temporary clearance for {user_name} on '{file_name}' (valid for {req_obj.duration_hours} hours).",
        "success",
    )
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/admin/access-requests/<int:rid>/reject", methods=["POST"])
@admin_required
def reject_access_request(rid):
    req_obj = db.session.get(AccessRequest, rid) or abort(404)
    if req_obj.status != "pending":
        flash("This elevation request has already been reviewed.", "warning")
        return redirect(url_for("admin.dashboard"))

    req_obj.status = "rejected"
    req_obj.reviewed_at = utcnow()
    req_obj.reviewed_by = current_user.username
    db.session.commit()

    file_name = req_obj.file.original_name if req_obj.file else f"File #{req_obj.file_id}"
    user_name = req_obj.user.username if req_obj.user else f"User #{req_obj.user_id}"

    audit(
        current_user.username,
        "reject_access_request",
        f"user={user_name} file={file_name}",
    )
    db.session.commit()

    try:
        mailer.send_access_decision_notification(req_obj, approved=False)
    except Exception as e:
        current_app.logger.warning(f"Could not dispatch decision notification email: {e}")

    flash(
        f"Rejected clearance elevation request from {user_name} for '{file_name}'.",
        "danger",
    )
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/api/stats")
@admin_required
def api_stats():
    since = utcnow() - timedelta(hours=24)
    counts = {
        k: Event.query.filter(
            Event.ts >= since, Event.action == "download", Event.outcome == k
        ).count()
        for k in ("allowed", "warned", "blocked", "denied")
    }
    recent = (
        Event.query.filter(Event.action == "download")
        .order_by(Event.id.desc())
        .limit(40)
        .all()
    )
    feed = [
        {
            "id": e.id,
            "ts": e.ts.strftime("%H:%M:%S"),
            "user": e.user.username if e.user else "?",
            "file": e.file.original_name if e.file else "(deleted)",
            "outcome": e.outcome,
            "score": e.risk_score,
            "reasons": e.reasons,
        }
        for e in recent
    ]
    return jsonify(
        {
            "counts": counts,
            "feed": feed,
            "open_incidents": Incident.query.filter_by(status="open").count(),
            "pending_access_requests": AccessRequest.query.filter_by(status="pending").count(),
            "users": User.query.count(),
            "files": File.query.count(),
            "smtp_configured": is_smtp_configured(),
            "has_gemini": bool(get_gemini_api_key()),
        }
    )


@admin_bp.route("/admin/incidents")
@admin_required
def incidents():
    rows = Incident.query.order_by(Incident.id.desc()).limit(100).all()
    return render_template("incidents.html", rows=rows)


@admin_bp.route("/admin/incidents/<int:iid>", methods=["POST"])
@admin_required
def resolve_incident(iid):
    inc = db.session.get(Incident, iid) or abort(404)
    action = request.form.get("as")

    if action == "lock_user":
        if inc.user:
            inc.user.status = "restricted"
            inc.status = "resolved"
            audit(current_user.username, "restrict_user", f"user={inc.user.username} via incident={iid}")
            try:
                mailer.send_account_restriction_alert(
                    inc.user,
                    reason=f"Account restricted by administrator ({current_user.username}) during triage of Incident #{iid}."
                )
            except Exception as e:
                current_app.logger.warning(f"Could not dispatch account restriction alert: {e}")
            flash(f"Account for {inc.user.username} has been locked/restricted. Alert email dispatched.", "danger")
    elif action == "trust_device":
        dev_id = inc.event.device_id if inc.event else None
        if inc.user and dev_id:
            dev = Device.query.filter_by(user_id=inc.user_id, device_id=dev_id).first()
            if dev:
                dev.trusted = True
            inc.status = "false_positive"
            audit(current_user.username, "trust_device", f"device={dev_id} user={inc.user.username}")
            flash(f"Device '{dev_id}' marked as trusted. Incident marked as false alarm.", "success")
    elif action == "quarantine_file":
        if inc.file:
            inc.file.is_quarantined = True
            audit(current_user.username, "quarantine_file", f"file={inc.file.id} name={inc.file.original_name} via incident={iid}")
            flash(f"File '{inc.file.original_name}' has been QUARANTINED. All downloads are now blocked.", "warning")
    elif action == "unquarantine_file":
        if inc.file:
            inc.file.is_quarantined = False
            audit(current_user.username, "unquarantine_file", f"file={inc.file.id} name={inc.file.original_name} via incident={iid}")
            flash(f"File '{inc.file.original_name}' released from quarantine.", "success")
    elif action == "false_positive":
        inc.status = "false_positive"
        audit(current_user.username, "incident_false_positive", f"incident={iid}")
        flash(f"Incident #{iid} marked as false alarm.", "info")
    else:
        inc.status = "resolved"
        audit(current_user.username, "incident_resolved", f"incident={iid}")
        flash(f"Incident #{iid} marked as resolved.", "success")

    db.session.commit()
    return redirect(url_for("incidents"))


@admin_bp.route("/admin/file/<int:fid>/quarantine", methods=["POST"])
@admin_required
def toggle_quarantine(fid):
    f = db.session.get(File, fid) or abort(404)
    f.is_quarantined = not f.is_quarantined
    state = "QUARANTINED" if f.is_quarantined else "RELEASED"
    audit(current_user.username, f"file_{state.lower()}", f"file={f.id} name={f.original_name}")
    db.session.commit()
    flash(f"File '{f.original_name}' is now {state}.", "warning" if f.is_quarantined else "success")
    return redirect(request.referrer or url_for("files"))


@admin_bp.route("/admin/integrity", methods=["GET", "POST"])
@admin_required
def integrity_check():
    """Verifies storage blobs and cryptographic checksums (Report Section 6.6)."""
    store = storage.get_storage(current_app.config.get("BASE_DIR"))
    all_files = File.query.all()
    results = []
    tampered_count = 0
    ok_count = 0

    for f in all_files:
        status = "ok"
        detail = "Cryptographic integrity verified (SHA-256 match & decryptable)"
        try:
            cipher = store.get(f.stored_name)
            if not cipher:
                status = "missing"
                detail = "Storage blob missing from cloud disk/bucket"
                tampered_count += 1
            else:
                plain = crypto.decrypt(cipher, f.wrapped_dek)
                if f.content_hash:
                    actual_hash = hashlib.sha256(plain).hexdigest()
                    if actual_hash != f.content_hash:
                        status = "tampered"
                        detail = f"Content hash mismatch! Expected {f.content_hash[:8]}..., got {actual_hash[:8]}..."
                        tampered_count += 1
                    else:
                        ok_count += 1
                else:
                    ok_count += 1
        except Exception as e:
            status = "corrupted"
            detail = f"Decryption failure / ciphertext corrupted ({str(e)})"
            tampered_count += 1

        results.append({
            "id": f.id,
            "name": f.original_name,
            "status": status,
            "detail": detail,
            "is_quarantined": f.is_quarantined,
            "is_deduplicated": f.is_deduplicated,
        })

    audit(current_user.username, "integrity_verification", f"total={len(all_files)} ok={ok_count} issues={tampered_count}")
    db.session.commit()

    if request.method == "POST":
        if tampered_count == 0:
            flash(f"Integrity check passed! All {ok_count} stored cloud files verified against cryptographic checksums.", "success")
        else:
            flash(f"Integrity check completed with warnings: {tampered_count} file(s) flagged for potential tampering or corruption.", "danger")
        return redirect(url_for("admin.integrity_check"))

    return render_template(
        "integrity.html",
        results=results,
        total=len(all_files),
        ok_count=ok_count,
        tampered_count=tampered_count,
    )


@admin_bp.route("/admin/users")
@admin_required
def users():
    return render_template("users.html", rows=User.query.order_by(User.id).all())


@admin_bp.route("/admin/users/<int:uid>", methods=["POST"])
@admin_required
def update_user(uid):
    u = db.session.get(User, uid) or abort(404)
    f = request.form
    if f.get("restore"):
        u.status = "active"
    if f.get("clearance", "").isdigit():
        u.clearance = max(0, min(3, int(f["clearance"])))
    if f.get("department"):
        u.department = f["department"].strip().lower()[:40]
    if f.get("role") in ("admin", "employee", "guest"):
        u.role = f["role"]
    audit(current_user.username, "update_user", f"user={u.username}")
    db.session.commit()
    flash(f"Updated {u.username}.", "success")
    return redirect(url_for("users"))


@admin_bp.route("/admin/audit")
@admin_required
def audit_view():
    ok, bad = verify_audit_chain()
    rows = Audit.query.order_by(Audit.id.desc()).limit(100).all()
    return render_template("audit.html", rows=rows, ok=ok, bad=bad)


@admin_bp.route("/admin/ai-insights")
@admin_required
def ai_insights():
    """Interactive GenAI Log & Security Threat Intelligence Hub."""
    return render_template(
        "ai_insights.html",
        has_gemini=bool(get_gemini_api_key()),
        model_name=ai_agent.get_gemini_model(),
        smtp_configured=is_smtp_configured(),
    )


@admin_bp.route("/api/admin/ai-summary", methods=["GET", "POST"])
@csrf.exempt
@admin_required
def api_ai_summary():
    """Generates an executive threat summary across recent logs."""
    hours = 24
    if request.is_json and request.json:
        hours = int(request.json.get("hours", 24))
    elif request.args.get("hours"):
        hours = int(request.args.get("hours", 24))

    since = utcnow() - timedelta(hours=hours)
    events = Event.query.filter(Event.ts >= since).order_by(Event.id.desc()).all()
    incidents = Incident.query.filter(Incident.ts >= since).order_by(Incident.id.desc()).all()
    audit_rows = Audit.query.filter(Audit.ts >= since).order_by(Audit.id.desc()).all()

    counts = {
        k: sum(1 for e in events if e.action == "download" and e.outcome == k)
        for k in ("allowed", "warned", "blocked", "denied")
    }
    open_incidents_count = sum(1 for i in incidents if i.status == "open")

    res = ai_agent.summarize_security_logs(
        events=events,
        incidents=incidents,
        audit_rows=audit_rows,
        counts=counts,
        open_incidents_count=open_incidents_count,
        hours=hours,
    )
    return jsonify({"success": True, **res})


@admin_bp.route("/api/admin/ai-incident/<int:iid>", methods=["GET", "POST"])
@csrf.exempt
@admin_required
def api_ai_incident(iid):
    """Forensic AI deep dive on a specific incident."""
    inc = db.session.get(Incident, iid) or abort(404)
    res = ai_agent.analyze_single_incident(inc)
    return jsonify({"success": True, **res})


@admin_bp.route("/admin/email-test", methods=["POST"])
@admin_required
def email_test():
    """Sends a test email to verify SMTP configuration and returns status."""
    target = (request.form.get("email") or "").strip()
    if not target:
        if request.is_json and request.json:
            target = (request.json.get("email") or "").strip()
    if not target:
        target = current_user.email

    if not target or "@" not in target:
        return jsonify({"success": False, "error": "Invalid recipient email address."}), 400

    res = mailer.send_test_email(target)
    if res.get("success"):
        transport = "Simulated Dev Console" if res.get("simulated") else "Live SMTP Server"
        audit(current_user.username, "email_test", f"to={target} transport={transport}")
        db.session.commit()
        return jsonify({
            "success": True,
            "simulated": res.get("simulated", False),
            "message": f"Test email dispatched successfully to {target} ({transport})!",
        })
    else:
        return jsonify({
            "success": False,
            "error": res.get("error") or "Unknown error delivering email",
        }), 500


@admin_bp.route("/api/admin/simulated-emails")
@admin_required
def api_simulated_emails():
    """Returns recent in-memory simulated emails for preview."""
    return jsonify({
        "emails": mailer.get_simulated_outbox(),
        "smtp_configured": is_smtp_configured(),
    })


@admin_bp.route("/api/admin/crypto-benchmark", methods=["GET", "POST"])
@admin_required
def api_crypto_benchmark():
    """Live cryptographic performance evaluation and KEK/DEK architecture details."""
    payload_kb = 100
    if request.is_json and request.json:
        payload_kb = int(request.json.get("payload_kb", 100))
    elif request.args.get("payload_kb"):
        payload_kb = int(request.args.get("payload_kb", 100))
    payload_kb = max(1, min(payload_kb, 5000))

    info = crypto.get_crypto_info()
    metrics = crypto.benchmark_crypto(payload_kb)
    return jsonify({
        "success": True,
        "info": info,
        "metrics": metrics,
    })


@admin_bp.route("/api/admin/crypto-sandbox", methods=["POST"])
@csrf.exempt
@admin_required
def api_crypto_sandbox():
    """Interactive encryption and decryption test sandbox for administrators."""
    data = request.get_json(silent=True) or request.form
    action = data.get("action", "encrypt")
    payload = (data.get("payload") or "").strip()

    if not payload:
        return jsonify({"success": False, "error": "Payload cannot be empty."}), 400

    if action == "encrypt":
        t0 = time.perf_counter()
        token = crypto.encrypt_string(payload)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
        audit(current_user.username, "crypto_sandbox_encrypt", f"len={len(payload)}")
        db.session.commit()
        return jsonify({
            "success": True,
            "action": "encrypt",
            "token": token,
            "elapsed_ms": elapsed_ms,
            "architecture": "Envelope AES-128-CBC + HMAC-SHA256",
        })
    elif action == "decrypt":
        try:
            t0 = time.perf_counter()
            decrypted = crypto.decrypt_string(payload)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
            audit(current_user.username, "crypto_sandbox_decrypt", "status=verified")
            db.session.commit()
            return jsonify({
                "success": True,
                "action": "decrypt",
                "decrypted": decrypted,
                "elapsed_ms": elapsed_ms,
                "integrity_verified": True,
            })
        except Exception as exc:
            return jsonify({
                "success": False,
                "error": f"Decryption failed: {str(exc)}. Possible tampering or wrong key.",
            }), 400
    else:
        return jsonify({"success": False, "error": f"Unknown action: {action}"}), 400


