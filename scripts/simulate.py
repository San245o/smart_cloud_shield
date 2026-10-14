"""Attack demo. Runs normal users and attackers through the REAL app and prints
what the security system decided. Run `python seed.py` first (it resets data).
Then start the app and open the admin dashboard to see the same events.
"""
import os
import sys
from pathlib import Path

# Ensure workspace root is in sys.path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

os.environ["DEMO_MODE"] = "1"  # lets this script fake the device and the hour

from scs import create_app
from scs.models import Event, File, User

PASSWORD = "Pass@12345"


def login(app, client, user, device, hour):
    h = {"X-Demo-Device": device, "X-Demo-Hour": str(hour)}
    client.post("/login", data={"username": user, "password": PASSWORD}, headers=h)
    with app.app_context():
        uid = User.query.filter_by(username=user).first().id
    r = client.post("/otp", data={"code": app.config["DEBUG_OTPS"][uid]}, headers=h)
    assert r.status_code in (302, 303), "login failed"
    return h


def run(app, title, user, device, hour, plan):
    print(f"\n=== {title} ===")
    print(f"user={user} device={device} hour={hour:02d}:00 attempts={len(plan)}")
    c = app.test_client()
    h = login(app, c, user, device, hour)
    with app.app_context():
        last = (Event.query.order_by(Event.id.desc()).first() or Event(id=0)).id
        ids = {f.original_name: f.id for f in File.query.all()}
    for name in plan:
        c.get(f"/download/{ids[name]}", headers=h)
    with app.app_context():
        evs = (
            Event.query.filter(Event.id > last, Event.action == "download")
            .order_by(Event.id)
            .all()
        )
        delivered = sum(1 for e in evs if e.outcome in ("allowed", "warned"))
        for n, e in enumerate(evs, 1):
            top = max(e.reasons, key=lambda r: r["points"])["text"] if e.reasons else ""
            score = "-" if e.risk_score is None else e.risk_score
            if n <= 3 or e.outcome != evs[n - 2].outcome:  # print first rows and every change
                print(f"  #{n:<2} {e.file.original_name:22s} {e.outcome:8s} risk={score!s:>3}  {top}")
        first_stop = next(
            (i for i, e in enumerate(evs, 1) if e.outcome in ("blocked", "denied")), None
        )
        print(
            f"  -> delivered {delivered} of {len(evs)} attempts"
            + (f"; first stop at attempt #{first_stop}" if first_stop else "; never stopped")
        )


def main():
    app = create_app()
    app.config["WTF_CSRF_ENABLED"] = False
    run(
        app,
        "1. Normal day: HR employee, usual laptop",
        "bob",
        "bob-laptop",
        11,
        ["team_contacts.csv", "meeting_notes.txt"],
    )
    run(
        app,
        "2. Legit busy day: 12 quick downloads of low-risk files (should NOT be blocked)",
        "bob",
        "bob-laptop",
        15,
        ["team_contacts.csv", "meeting_notes.txt", "public_brochure.txt"] * 4,
    )
    run(
        app,
        "3. Insider: finance employee bulk-downloads confidential files on her usual laptop",
        "alice",
        "alice-laptop",
        14,
        ["payroll_2026.csv", "customer_cards.csv"] * 12,
    )
    run(
        app,
        "4. Compromised account: stolen password used from a new device at 2 AM",
        "carol",
        "attacker-laptop",
        2,
        ["server_credentials.txt"] * 4,
    )
    print(
        "\nNow run `python app.py`, log in as admin (Pass@12345) and open the Dashboard and Incidents pages."
    )


if __name__ == "__main__":
    main()
