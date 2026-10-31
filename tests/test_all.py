import io
import os
import tempfile

os.environ["DISABLE_SQLALCHEMY_CEXT"] = "1"
os.environ["DEMO_MODE"] = "1"
os.environ["BLOB_DIR"] = tempfile.mkdtemp()

import pytest

import crypto
import dlp
import risk
from app import create_app
from scs.models import Audit, Device, Event, File, Incident, User, db, verify_audit_chain
from seed import aadhaar
from werkzeug.security import generate_password_hash

PW = "Pass@12345"


# ------------------------------------------------------------------ DLP
def test_checksums():
    assert dlp.luhn_valid("4111111111111111") and not dlp.luhn_valid("4111111111111112")
    good = aadhaar("23456789012").replace(" ", "")
    assert dlp.verhoeff_valid(good)
    assert not dlp.verhoeff_valid(good[:-1] + str((int(good[-1]) + 1) % 10))


def test_random_numbers_are_not_flagged():
    c = dlp.scan_text("order 234567890123 ref 4111111111111112 id 999999999998")
    assert c["aadhaar"] == 0 and c["credit_card"] == 0


def test_real_patterns_are_flagged():
    text = f"{aadhaar('23456789012')} card 4111 1111 1111 1111 PAN ABCPD1234E a@b.com"
    c = dlp.scan_text(text)
    assert c["aadhaar"] == 1 and c["credit_card"] == 1 and c["pan"] == 1 and c["email"] == 1


def test_card_is_not_double_counted_as_aadhaar():
    assert dlp.scan_text("card 4111 1111 1111 1111")["aadhaar"] == 0


def test_classification_levels():
    assert dlp.scan_file(b"hello world", "a.txt")["level"] == "public"
    assert dlp.scan_file(b"-----BEGIN RSA PRIVATE KEY-----", "k.txt")["level"] == "highly_confidential"


def test_counts_only_never_raw_values():
    r = dlp.scan_file(b"card 4111 1111 1111 1111", "a.txt")
    assert "4111" not in str(r)


# --------------------------------------------------------------- crypto
def test_encrypt_roundtrip_and_tamper():
    blob, wrapped = crypto.encrypt(b"secret data")
    assert b"secret" not in blob
    assert crypto.decrypt(blob, wrapped) == b"secret data"
    with pytest.raises(Exception):
        crypto.decrypt(blob[:-5] + b"AAAAA", wrapped)


# ------------------------------------------------------------ app fixtures
@pytest.fixture()
def app():
    a = create_app("sqlite://")
    a.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    with a.app_context():
        db.drop_all(); db.create_all()
        for n, role, dept, clr in [("admin", "admin", "it", 3), ("alice", "employee", "finance", 3),
                                   ("bob", "employee", "hr", 2), ("dave", "employee", "general", 1),
                                   ("gus", "guest", "general", 0)]:
            u = User(username=n, email=f"{n}@x.io", role=role, department=dept, clearance=clr,
                     password_hash=generate_password_hash(PW))
            db.session.add(u)
        db.session.commit()
    return a


def login(app, user, device="dev-" , hour=11):
    c = app.test_client()
    h = {"X-Demo-Device": device + user, "X-Demo-Hour": str(hour)}
    c.post("/login", data={"username": user, "password": PW}, headers=h)
    with app.app_context():
        uid = User.query.filter_by(username=user).first().id
    c.post("/otp", data={"code": app.config["DEBUG_OTPS"][uid]}, headers=h)
    return c, h


def upload(c, h, name, text):
    return c.post("/upload", data={"file": (io.BytesIO(text.encode()), name)},
                  headers=h, content_type="multipart/form-data")


# ------------------------------------------------------------------ auth
def test_wrong_password_and_lockout(app):
    c = app.test_client()
    for _ in range(5):
        r = c.post("/login", data={"username": "alice", "password": "bad"})
        assert b"Invalid username or password" in r.data
    r = c.post("/login", data={"username": "alice", "password": PW})
    assert b"Too many failed attempts" in r.data


def test_wrong_otp_rejected(app):
    c = app.test_client()
    c.post("/login", data={"username": "alice", "password": PW})
    c.post("/otp", data={"code": "000000"})
    assert c.get("/files").status_code == 302          # still not logged in


def test_pages_require_login(app):
    c = app.test_client()
    assert c.get("/files").status_code == 302
    assert c.get("/admin").status_code == 302


def test_employee_cannot_open_admin(app):
    c, h = login(app, "alice")
    assert c.get("/admin", headers=h).status_code == 403


# ------------------------------------------------------- upload / download
def test_upload_encrypts_and_classifies(app):
    c, h = login(app, "alice")
    upload(c, h, "pay.csv", "salary table\n" + aadhaar("23456789012") + "\n" + aadhaar("23456789013")
           + "\n" + aadhaar("23456789014") + "\n" + aadhaar("23456789015") + "\n")
    with app.app_context():
        f = File.query.first()
        assert f.sensitivity in ("confidential", "highly_confidential")
        raw = open(os.path.join(os.environ["BLOB_DIR"], f.stored_name), "rb").read()
        assert b"salary" not in raw                      # stored encrypted


def test_bad_extension_rejected(app):
    c, h = login(app, "alice")
    upload(c, h, "evil.exe", "x")
    with app.app_context():
        assert File.query.count() == 0


def test_download_roundtrip_and_abac(app):
    c, h = login(app, "alice")
    upload(c, h, "notes.txt", "plain meeting notes")
    r = c.get("/download/1", headers=h)
    assert r.status_code == 200 and r.data == b"plain meeting notes"
    gc, gh = login(app, "gus")                         # guest: no download role
    assert gc.get("/download/1", headers=gh).status_code == 302
    with app.app_context():
        assert Event.query.filter_by(user_id=User.query.filter_by(username="gus").first().id,
                                     outcome="denied").count() == 1


def test_department_wall(app):
    c, h = login(app, "alice")                         # finance uploads a confidential file
    upload(c, h, "payroll.csv", "payroll salary confidential " + " ".join(
        aadhaar("2345678901" + str(i)) for i in range(5)))
    bc, bh = login(app, "bob")                         # HR, clearance 2
    r = bc.get("/download/1", headers=bh)
    assert r.status_code == 302
    with app.app_context():
        assert Event.query.filter_by(outcome="denied").count() >= 1


# ------------------------------------------------------------ risk engine
SENSITIVE = "payroll salary confidential " + " ".join(aadhaar("2345678901" + str(i)) for i in range(5))


def test_normal_download_allowed_attack_blocked(app):
    c, h = login(app, "alice", device="home-")
    upload(c, h, "payroll.csv", SENSITIVE)
    assert c.get("/download/1", headers=h).status_code == 200
    # same account from a brand-new device at 2 AM
    ac, ah = login(app, "alice", device="attacker-", hour=2)
    r = ac.get("/download/1", headers=ah)
    assert r.status_code == 302
    with app.app_context():
        e = Event.query.filter_by(outcome="blocked").first()
        assert e and e.risk_score >= risk.BLOCK_AT and len(e.reasons) >= 3
        assert Incident.query.filter_by(level="block").count() == 1


def test_three_blocks_restrict_account(app):
    c, h = login(app, "alice", device="home-")
    upload(c, h, "payroll.csv", SENSITIVE)
    ac, ah = login(app, "alice", device="attacker-", hour=2)
    for _ in range(4):
        ac.get("/download/1", headers=ah)
    with app.app_context():
        assert User.query.filter_by(username="alice").first().status == "restricted"


def test_risk_levels():
    assert risk.level_for(30) == "allow" and risk.level_for(31) == "warn" and risk.level_for(71) == "block"


# ------------------------------------------------------------------ audit
def test_audit_chain_detects_tampering(app):
    c, h = login(app, "alice")
    upload(c, h, "n.txt", "hello")
    with app.app_context():
        assert verify_audit_chain()[0] is True
        row = Audit.query.filter_by(action="upload").first()
        row.detail = "file=999 level=public"           # attacker edits history
        db.session.commit()
        ok, bad = verify_audit_chain()
        assert ok is False and bad == row.id


# ----------------------------------------------------------- new features
def test_dlp_redaction():
    text = f"card 4111 1111 1111 1111 aadhaar {aadhaar('23456789012')} PAN ABCPD1234E"
    redacted = dlp.redact_text(text)
    assert "4111 1111 1111 1111" not in redacted
    assert "****-****-****-1111" in redacted
    assert "23456789012" not in redacted
    assert "ABCPD****E" in redacted


def test_download_redacted_safe_copy(app):
    c, h = login(app, "alice")
    upload(c, h, "secrets.csv", SENSITIVE + " card 4111 1111 1111 1111")
    # Low-clearance or restricted user can still download safe redacted copy
    bc, bh = login(app, "bob")  # HR employee trying to access finance confidential file
    # Normal raw download is denied by department wall
    assert bc.get("/download/1", headers=bh).status_code == 302
    # Redacted download succeeds with PII masked
    r = bc.get("/download/1?mode=redacted", headers=bh)
    assert r.status_code == 200
    assert b"4111 1111 1111 1111" not in r.data
    assert b"****-****-****-1111" in r.data
    assert b"2345678901" not in r.data


def test_admin_incident_remediation(app):
    # Alice triggers a blocked incident
    c, h = login(app, "alice", device="newdev-", hour=2)
    upload(c, h, "pay.csv", SENSITIVE)
    c.get("/download/1", headers=h)  # blocked

    # Admin reviews incidents
    ac, ah = login(app, "admin")
    with app.app_context():
        inc = Incident.query.first()
        assert inc is not None
        inc_id = inc.id

    # Admin executes Trust Device action
    r = ac.post(f"/admin/incidents/{inc_id}", data={"as": "trust_device"}, headers=ah)
    assert r.status_code == 302
    with app.app_context():
        dev = Device.query.filter_by(device_id="newdev-alice").first()
        assert dev and dev.trusted is True
        assert db.session.get(Incident, inc_id).status == "false_positive"


def test_image_ocr_and_upload(app):
    from PIL import Image

    # 1. Verify image extensions are accepted in DLP
    assert {"png", "jpg", "jpeg"}.issubset(dlp.ALLOWED_EXT)

    # 2. Create in-memory test image
    img = Image.new("RGB", (120, 40), color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    data = bio.getvalue()

    # 3. Test text extraction does not crash on image
    text = dlp.extract_text(data, "test.png")
    assert isinstance(text, str)

    # 4. Upload image file through the app
    c, h = login(app, "alice")
    r = c.post("/upload", data={"file": (io.BytesIO(data), "receipt.png")},
               headers=h, content_type="multipart/form-data")
    assert r.status_code == 302
    with app.app_context():
        uploaded = File.query.filter_by(original_name="receipt.png").first()
        assert uploaded is not None


def test_deduplication_and_ref_counting(app):
    from scs.services import storage
    c1, h1 = login(app, "alice")
    c2, h2 = login(app, "bob")

    content = "Confidential report shared between departments: 12345."
    # Alice uploads
    r1 = upload(c1, h1, "report_v1.txt", content)
    assert r1.status_code == 302

    # Bob uploads identical file
    r2 = upload(c2, h2, "report_copy.txt", content)
    assert r2.status_code == 302

    with app.app_context():
        f1 = File.query.filter_by(original_name="report_v1.txt").first()
        f2 = File.query.filter_by(original_name="report_copy.txt").first()
        assert f1 is not None and f2 is not None
        assert f1.content_hash == f2.content_hash
        assert f1.stored_name == f2.stored_name  # Reused storage pointer!
        assert not f1.is_deduplicated
        assert f2.is_deduplicated  # Flagged as deduplicated block!

        store = storage.get_storage(app.config.get("BASE_DIR"))
        assert store.get(f1.stored_name) is not None

    # Bob deletes his copy; f1 still references it so blob must remain
    c2.post(f"/delete/{f2.id}", headers=h2)
    with app.app_context():
        assert File.query.filter_by(id=f2.id).first() is None
        f1_check = File.query.filter_by(id=f1.id).first()
        assert f1_check is not None
        store = storage.get_storage(app.config.get("BASE_DIR"))
        # Stored blob is still intact for Alice!
        assert store.get(f1_check.stored_name) is not None


def test_quarantine_blocks_download_and_preview(app):
    c, h = login(app, "alice")
    upload(c, h, "suspect.txt", "Some sensitive financial material.")

    with app.app_context():
        f = File.query.filter_by(original_name="suspect.txt").first()
        fid = f.id

    # Admin quarantines the file
    ac, ah = login(app, "admin")
    r_quar = ac.post(f"/admin/file/{fid}/quarantine", headers=ah, follow_redirects=True)
    assert r_quar.status_code == 200

    with app.app_context():
        f = db.session.get(File, fid)
        assert f.is_quarantined is True

    # Alice tries to download or preview -> denied!
    dl_resp = c.get(f"/download/{fid}", headers=h, follow_redirects=True)
    assert b"QUARANTINED" in dl_resp.data

    redact_resp = c.get(f"/download/{fid}?mode=redacted", headers=h, follow_redirects=True)
    assert b"QUARANTINED" in redact_resp.data

    prev_resp = c.get(f"/preview/{fid}", headers=h, follow_redirects=True)
    assert b"is quarantined by administrators" in prev_resp.data

    # Admin unquarantines the file
    ac.post(f"/admin/file/{fid}/quarantine", headers=ah, follow_redirects=True)
    with app.app_context():
        f = db.session.get(File, fid)
        assert f.is_quarantined is False

    dl_resp_ok = c.get(f"/download/{fid}", headers=h)
    assert dl_resp_ok.status_code == 200


def test_watermarked_preview(app):
    c, h = login(app, "alice")
    upload(c, h, "watermark_test.txt", "Internal audit details.")

    with app.app_context():
        f = File.query.filter_by(original_name="watermark_test.txt").first()
        fid = f.id

    r = c.get(f"/preview/{fid}", headers=h)
    assert r.status_code == 200
    assert b"Secure In-Browser Preview" in r.data
    assert b"Internal audit details." in r.data
    assert b"ALICE" in r.data
    assert b"FINANCE" in r.data
    assert b"watermark-overlay" in r.data


def test_storage_integrity_verification(app):
    c, h = login(app, "alice")
    upload(c, h, "int_test.txt", "Integrity check test blob 98765.")

    ac, ah = login(app, "admin")
    r = ac.get("/admin/integrity", headers=ah)
    assert r.status_code == 200
    assert b"Storage Block Verification Table" in r.data
    assert b"int_test.txt" in r.data
    assert b"Verified OK" in r.data


# ----------------------------------------------------------- Email & GenAI
def test_mailer_otp_and_security_alerts(app):
    from scs.services import mailer

    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        mailer.clear_simulated_outbox()

        # 1. Test OTP email
        otp_res = mailer.send_otp_email(u, "123456", ip="192.168.1.50", device_id="test-device-uuid")
        assert otp_res["success"] is True
        assert otp_res.get("simulated") is True

        outbox = mailer.get_simulated_outbox()
        assert len(outbox) == 1
        assert "123456" in outbox[0]["text"]
        assert "123456" in outbox[0]["html"]
        assert outbox[0]["to"] == u.email

        # 2. Test Incident security alert email
        ev = Event(user_id=u.id, action="download", outcome="blocked", risk_score=85)
        db.session.add(ev)
        db.session.flush()

        inc = Incident(user_id=u.id, event_id=ev.id, level="block", risk_score=85,
                       reasons_json='[{"points": 30, "text": "Highly confidential exfiltration"}]')
        db.session.add(inc)
        db.session.flush()

        alert_res = mailer.send_security_alert_email(inc, recipient_email="security-lead@company.local")
        assert alert_res["success"] is True
        
        outbox = mailer.get_simulated_outbox()
        assert len(outbox) == 2
        assert "SECURITY ALERT" in outbox[0]["subject"]
        assert "85" in outbox[0]["text"]
        assert "alice" in outbox[0]["text"]

        # 3. Test Account restriction alert
        restrict_res = mailer.send_account_restriction_alert(u, "Suspicious download rate", admin_email="admin@test.local")
        assert restrict_res["success"] is True


def test_admin_email_endpoints(app):
    ac, ah = login(app, "admin")
    
    # 1. Test sending a test email via endpoint
    r = ac.post("/admin/email-test", data={"email": "test-admin@corp.local"}, headers=ah)
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert "dispatched successfully" in data["message"]

    # 2. Test invalid email rejection
    r_bad = ac.post("/admin/email-test", data={"email": "not-an-email"}, headers=ah)
    assert r_bad.status_code == 400
    assert r_bad.get_json()["success"] is False

    # 3. Test simulated outbox API
    r_outbox = ac.get("/api/admin/simulated-emails", headers=ah)
    assert r_outbox.status_code == 200
    out_data = r_outbox.get_json()
    assert "emails" in out_data
    assert len(out_data["emails"]) > 0


def test_ai_threat_summary_and_fallback(app):
    from scs.services import ai_agent

    with app.app_context():
        events = Event.query.all()
        incidents = Incident.query.all()
        audits = Audit.query.all()
        counts = {"allowed": 5, "warned": 2, "blocked": 1, "denied": 1}

        # 1. Direct service summary execution
        summary = ai_agent.summarize_security_logs(events, incidents, audits, counts, len(incidents), hours=24)
        assert summary["source"] in ("local", "gemini")
        assert "Executive Threat Intelligence Report" in summary["content"]
        assert summary["posture"]["score"] > 0
        assert "grade" in summary["posture"]

    # 2. Test admin API endpoint
    ac, ah = login(app, "admin")
    r = ac.post("/api/admin/ai-summary", json={"hours": 24}, headers=ah)
    assert r.status_code == 200
    res = r.get_json()
    assert res["success"] is True
    assert "posture" in res
    assert "content" in res


def test_ai_incident_deep_dive(app):
    from scs.services import ai_agent

    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        inc = Incident(user_id=u.id, level="block", risk_score=80,
                       reasons_json='[{"points": 30, "text": "Confidential financial data"}, {"points": 15, "text": "Unverified device"}]')
        db.session.add(inc)
        db.session.commit()
        iid = inc.id

        # 1. Service direct analysis
        analysis_data = ai_agent.analyze_single_incident(inc)
        assert analysis_data["source"] in ("local", "gemini")
        assert f"Incident Breakdown — #{iid}" in analysis_data["analysis"]
        assert "alice" in analysis_data["analysis"]

    # 2. Endpoint analysis call
    ac, ah = login(app, "admin")
    r = ac.post(f"/api/admin/ai-incident/{iid}", headers=ah)
    assert r.status_code == 200
    res = r.get_json()
    assert res["success"] is True
    assert "analysis" in res


def test_ai_insights_view_and_gemini_integration(app, monkeypatch):
    from scs.services import ai_agent

    # 1. Verify access control: employee blocked, admin allowed
    ec, eh = login(app, "alice")
    assert ec.get("/admin/ai-insights", headers=eh).status_code == 403

    ac, ah = login(app, "admin")
    r_admin = ac.get("/admin/ai-insights", headers=ah)
    assert r_admin.status_code == 200
    assert b"AI Threat Intelligence" in r_admin.data

    # 2. Mock Gemini API call to test live GenAI integration path
    def mock_call_gemini(prompt, system_instruction=None):
        return "### 🛡️ Mocked Executive Gemini Threat Report\n* Security posture is resilient.\n* No active breaches detected."

    monkeypatch.setattr(ai_agent, "_call_gemini_api", mock_call_gemini)

    with app.app_context():
        res = ai_agent.summarize_security_logs([], [], [], {"allowed": 1, "warned": 0, "blocked": 0, "denied": 0}, 0)
        assert res["source"] == "gemini"
        assert "Mocked Executive Gemini Threat Report" in res["content"]


def test_landing_page_renders(app):
    c = app.test_client()

    # 1. Unauthenticated root / renders landing page
    r = c.get("/")
    assert r.status_code == 200
    assert b"Smart Cloud Shield" in r.data
    assert b"Zero-Trust &amp; GenAI" in r.data or b"Zero-Trust & GenAI" in r.data
    assert b"Envelope Encryption" in r.data
    assert b"Interactive Demo" in r.data or b"Test the 4-Pillar" in r.data
    assert b"hero.jpg" in r.data

    # 2. /landing renders landing page
    r_land = c.get("/landing")
    assert r_land.status_code == 200
    assert b"Zero-Trust Cloud DLP" in r_land.data

    # 3. Authenticated user redirects to their workspace from /
    ac, ah = login(app, "admin")
    r_auth = ac.get("/")
    assert r_auth.status_code == 302
    assert "/admin" in r_auth.headers.get("Location", "")


def test_crypto_features_and_admin_sandbox(app):
    # 1. String-level envelope encryption & decryption
    plain = "Super-Secret-Data-12345"
    token = crypto.encrypt_string(plain)
    assert token != plain
    recovered = crypto.decrypt_string(token)
    assert recovered == plain

    # 2. Benchmark evaluation
    bench = crypto.benchmark_crypto(10)
    assert bench["integrity_verified"] is True
    assert bench["tamper_detected_and_blocked"] is True
    assert bench["encryption_ms"] >= 0
    assert bench["decryption_ms"] >= 0

    # 3. Admin benchmark endpoint
    ac, _ = login(app, "admin")
    r_bench = ac.get("/api/admin/crypto-benchmark?payload_kb=10")
    assert r_bench.status_code == 200
    data = r_bench.get_json()
    assert data["success"] is True
    assert "info" in data and "metrics" in data
    assert data["info"]["cipher"] == "AES-128-CBC"

    # 4. Admin crypto sandbox encrypt & decrypt endpoints
    r_enc = ac.post("/api/admin/crypto-sandbox", json={"action": "encrypt", "payload": "Test Secret 999"})
    assert r_enc.status_code == 200
    d_enc = r_enc.get_json()
    assert d_enc["success"] is True
    assert "token" in d_enc

    r_dec = ac.post("/api/admin/crypto-sandbox", json={"action": "decrypt", "payload": d_enc["token"]})
    assert r_dec.status_code == 200
    d_dec = r_dec.get_json()
    assert d_dec["success"] is True
    assert d_dec["decrypted"] == "Test Secret 999"

    # 5. Tampered token fails decryption
    tampered_token = d_enc["token"][:-2] + "AA"
    r_bad = ac.post("/api/admin/crypto-sandbox", json={"action": "decrypt", "payload": tampered_token})
    assert r_bad.status_code == 400


def test_clearance_levels_and_elevation_workflow(app):
    """Verifies clearance option enforcement, DLP escalation, and JIT elevation approval workflow."""
    from scs.models import AccessRequest, File, User
    from scs.services import access

    # Login as admin and alice
    ac, ah = login(app, "admin")
    dc, dh = login(app, "dave")  # Dave has clearance 1, general dept

    # 1. Admin uploads file enforcing clearance level 2 (Confidential)
    r_up = ac.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"Confidential financial forecast notes."), "forecast_q4.txt"),
            "min_clearance": "2",
        },
        content_type="multipart/form-data",
        headers=ah,
    )
    assert r_up.status_code == 302

    with app.app_context():
        f = File.query.filter_by(original_name="forecast_q4.txt").first()
        assert f is not None
        assert f.min_clearance >= 2
        fid = f.id

        # 2. Dave (clearance 1) cannot download raw file due to clearance requirement
        dave = User.query.filter_by(username="dave").first()
        ok, reason = access.can_download(dave, f)
        assert ok is False
        assert "Clearance L1" in reason or "below" in reason

    # Dave tries to download via client -> gets redirected with flash
    r_down = dc.get(f"/download/{fid}", headers=dh, follow_redirects=True)
    assert b"Clearance L1" in r_down.data or b"below" in r_down.data

    # 3. Dave submits Clearance Elevation Request with business justification
    r_req = dc.post(
        f"/request-elevation/{fid}",
        data={
            "justification": "Required for scheduled cross-departmental operations audit.",
            "duration_hours": "2",
        },
        headers=dh,
        follow_redirects=True,
    )
    assert r_req.status_code == 200
    assert b"Elevation request submitted" in r_req.data

    with app.app_context():
        req_obj = AccessRequest.query.filter_by(file_id=fid, user_id=dave.id, status="pending").first()
        assert req_obj is not None
        assert req_obj.requested_clearance >= 2
        assert req_obj.duration_hours == 2
        rid = req_obj.id

    # 4. Admin inspects dashboard and sees the pending elevation request with Yes / No decision
    r_dash = ac.get("/admin", headers=ah)
    assert r_dash.status_code == 200
    assert b"Clearance Elevation Requests" in r_dash.data
    assert b"forecast_q4.txt" in r_dash.data
    assert b"Yes (Approve)" in r_dash.data
    assert b"No (Reject)" in r_dash.data

    # 5. Admin clicks Approve (Yes)
    r_app = ac.post(f"/admin/access-requests/{rid}/approve", headers=ah, follow_redirects=True)
    assert r_app.status_code == 200
    assert b"Approved temporary clearance" in r_app.data

    with app.app_context():
        req_app = db.session.get(AccessRequest, rid)
        assert req_app.status == "approved"
        assert req_app.reviewed_by == "admin"
        assert req_app.is_active is True

        # Now access.can_download should allow Dave!
        f = db.session.get(File, fid)
        dave = User.query.filter_by(username="dave").first()
        ok_after, reason_after = access.can_download(dave, f)
        assert ok_after is True
        assert "Temporary clearance elevation active" in reason_after

    # 6. Dave can now download the file
    r_down_ok = dc.get(f"/download/{fid}", headers=dh)
    assert r_down_ok.status_code == 200
    assert b"Confidential financial forecast notes." in r_down_ok.data

    # 7. Test Admin rejecting an elevation request
    with app.app_context():
        req_reject = AccessRequest(
            user_id=dave.id,
            file_id=fid,
            current_clearance=1,
            requested_clearance=3,
            justification="Unauthorized exploratory access",
            duration_hours=1,
            status="pending",
        )
        db.session.add(req_reject)
        db.session.commit()
        rej_id = req_reject.id

    r_rej = ac.post(f"/admin/access-requests/{rej_id}/reject", headers=ah, follow_redirects=True)
    assert r_rej.status_code == 200
    assert b"Rejected clearance elevation request" in r_rej.data

    with app.app_context():
        assert db.session.get(AccessRequest, rej_id).status == "rejected"




