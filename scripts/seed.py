"""Reset the database and create demo users + sample files.
DEMO PASSWORDS ONLY. Change or delete these accounts before any real use."""
import json
import os
import shutil
import uuid
from datetime import timedelta
from pathlib import Path
import sys

# Ensure root workspace directory is in sys.path when running script directly
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from werkzeug.security import generate_password_hash

from scs import create_app
from scs.config import Config
from scs.models import Device, File, User, audit, db, utcnow
from scs.services import crypto, dlp, ml, storage

PASSWORD = "Pass@12345"


def aadhaar(base11: str) -> str:
    n = base11 + dlp.verhoeff_check_digit(base11)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def sample_files():
    cards = [
        "4111 1111 1111 1111",
        "5500 0000 0000 0004",
        "3714 4963 5398 431",
        "6011 0000 0000 0004",
    ]
    payroll = "name,pan,aadhaar,salary,email,phone\n"
    for i in range(8):
        payroll += (
            f"Employee{i},ABCPD{1000+i}E,{aadhaar('23456789' + f'{i:03d}')},"
            f"{50000+i*1000},emp{i}@corp.example,9{8765432100+i}\n"
        )
    payroll += "CONFIDENTIAL payroll data - do not distribute\n"
    customers = "id,card,email\n" + "\n".join(
        f"{i},{cards[i % 4]},c{i}@mail.example" for i in range(6)
    ) + "\n"
    infra = (
        "# internal use only\nAPI_KEY=sk-abcdefghijklmnopqrstuvwx1234\nAWS=AKIAIOSFODNN7EXAMPLE\n"
        "password: S3cretPass!\n-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n"
    )
    return {
        "payroll_2026.csv": ("finance", "alice", payroll),
        "customer_cards.csv": ("finance", "alice", customers),
        "server_credentials.txt": ("engineering", "carol", infra),
        "team_contacts.csv": (
            "hr",
            "bob",
            "name,email,phone\nA,a@corp.example,9876543210\nB,b@corp.example,9876543211\nC,c@corp.example,9876543212\nD,d@corp.example,9876543213\nE,e@corp.example,9876543214\n",
        ),
        "meeting_notes.txt": (
            "hr",
            "bob",
            "Weekly sync notes. Agenda: hiring plan, office move.\n",
        ),
        "public_brochure.txt": (
            "general",
            "dave",
            "Welcome to our company. Visit our website for more information.\n",
        ),
    }


def run():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        shutil.rmtree(Config.INSTANCE_DIR / "blobs", ignore_errors=True)
        store = storage.get_storage(Config.BASE_DIR)
        users = {}
        for name, role, dept, clr in [
            ("admin", "admin", "it", 3),
            ("alice", "employee", "finance", 3),
            ("bob", "employee", "hr", 2),
            ("carol", "employee", "engineering", 3),
            ("dave", "employee", "general", 1),
            ("guest1", "guest", "general", 0),
        ]:
            email_map = {
                "admin": os.environ.get("ADMIN_ALERT_EMAIL") or os.environ.get("MAIL_USER") or "sankeerthbanagar2@gmail.com",
                "alice": os.environ.get("ALICE_EMAIL") or "raghavendranr28781@gmail.com",
                "bob": os.environ.get("BOB_EMAIL") or "raghavendranr1218@gmail.com",
            }
            user_email = email_map.get(name, f"{name}@corp.example")
            u = User(
                username=name,
                email=user_email,
                role=role,
                department=dept,
                clearance=clr,
                password_hash=generate_password_hash(PASSWORD),
            )
            db.session.add(u)
            db.session.flush()
            users[name] = u
            # seeded users already have a trusted, long-known laptop
            db.session.add(
                Device(
                    user_id=u.id,
                    device_id=f"{name}-laptop",
                    trusted=True,
                    first_seen=utcnow() - timedelta(days=30),
                )
            )

        import hashlib
        for fname, (dept, owner, text) in sample_files().items():
            data = text.encode()
            res = dlp.scan_file(data, fname)
            chash = hashlib.sha256(data).hexdigest()
            blob, wrapped = crypto.encrypt(data)
            stored = uuid.uuid4().hex
            store.put(stored, blob)
            db.session.add(
                File(
                    owner_id=users[owner].id,
                    original_name=fname,
                    stored_name=stored,
                    content_hash=chash,
                    is_deduplicated=False,
                    size=len(data),
                    department=dept,
                    sensitivity=res["level"],
                    sensitivity_score=res["score"],
                    dlp_json=json.dumps(res["counts"]),
                    wrapped_dek=wrapped,
                )
            )
            print(f"  {fname:26s} -> {res['level']:20s} score={res['score']}")

        # Add one deduplicated file to demonstrate cloud storage deduplication (Report Section 2.7 & 6.6)
        payroll_orig = sample_files()["payroll_2026.csv"][2].encode()
        payroll_hash = hashlib.sha256(payroll_orig).hexdigest()
        orig_file = File.query.filter_by(content_hash=payroll_hash).first()
        if orig_file:
            db.session.add(
                File(
                    owner_id=users["alice"].id,
                    original_name="payroll_2026_backup.csv",
                    stored_name=orig_file.stored_name,
                    content_hash=payroll_hash,
                    is_deduplicated=True,
                    size=len(payroll_orig),
                    department="finance",
                    sensitivity=orig_file.sensitivity,
                    sensitivity_score=orig_file.sensitivity_score,
                    dlp_json=orig_file.dlp_json,
                    wrapped_dek=orig_file.wrapped_dek,
                )
            )
            print(f"  {'payroll_2026_backup.csv':26s} -> {orig_file.sensitivity:20s} score={orig_file.sensitivity_score} (DEDUPLICATED)")

        audit("system", "seed", "demo data created")
        db.session.commit()
        ml.train()

    print(f"\nSeeded. Users: admin, alice, bob, carol, dave, guest1  Password: {PASSWORD}")


if __name__ == "__main__":
    run()
