"""Explainable risk score for a download request.

Risk = file sensitivity (30) + volume (20) + context (25) + behaviour anomaly (25)
Every point added also produces a human-readable reason.
"""
from datetime import timedelta

from scs.models import Device, Event, utcnow
from scs.services import ml

SENS_POINTS = {
    "public": 0,
    "internal": 8,
    "confidential": 18,
    "highly_confidential": 30,
}
SENS_LABEL = {
    "public": "public",
    "internal": "internal",
    "confidential": "confidential",
    "highly_confidential": "highly confidential",
}
WARN_AT, BLOCK_AT = 31, 71  # 0-30 allow | 31-70 warn | 71-100 block
NEW_DEVICE_HOURS = 24


def level_for(score: int) -> str:
    return "block" if score >= BLOCK_AT else "warn" if score >= WARN_AT else "allow"


def recent_activity(user_id: int, file, now):
    since = now - timedelta(hours=1)
    evs = (
        Event.query.filter(
            Event.user_id == user_id,
            Event.action == "download",
            Event.ts >= since,
            Event.outcome != "denied",
        ).all()
    )
    files = {e.file_id for e in evs} | {file.id}
    sens = sum(
        1 for e in evs if e.file and e.file.sensitivity in ("confidential", "highly_confidential")
    )
    if file.sensitivity in ("confidential", "highly_confidential"):
        sens += 1
    mb = (sum(e.nbytes or 0 for e in evs) + (file.size or 0)) / 1e6
    return len(evs) + 1, len(files), sens, mb


def is_new_device(user_id: int, device_id: str, now) -> bool:
    d = Device.query.filter_by(user_id=user_id, device_id=device_id).first()
    if d is None:
        return True
    return (not d.trusted) and (now - d.first_seen) < timedelta(hours=NEW_DEVICE_HOURS)


def assess(user, file, device_id: str, hour: int, now=None) -> dict:
    now = now or utcnow()
    reasons, score = [], 0

    pts = SENS_POINTS.get(file.sensitivity, 30)
    if pts:
        score += pts
        reasons.append({"points": pts, "text": f"File is {SENS_LABEL[file.sensitivity]}"})

    n, distinct, sens, mb = recent_activity(user.id, file, now)
    vol = min(20, max(0, n - 3) * 2)
    if vol:
        score += vol
        reasons.append({"points": vol, "text": f"{n} downloads in the last hour"})

    newdev = is_new_device(user.id, device_id, now)
    if newdev:
        score += 15
        reasons.append({"points": 15, "text": "Request from a new or unverified device"})
    odd = hour < 6 or hour >= 22
    if odd:
        score += 10
        reasons.append({"points": 10, "text": f"Unusual hour ({hour:02d}:00)"})

    p = ml.anomaly_percentile([n, distinct, sens, mb, hour, int(newdev)])
    ml_pts = round(25 * min(1.0, max(0.0, (p - 0.90) / 0.10)))
    if ml_pts:
        score += ml_pts
        reasons.append(
            {
                "points": ml_pts,
                "text": f"Behaviour more unusual than {p:.0%} of normal activity (Isolation Forest)",
            }
        )

    score = min(100, score)
    return {
        "score": score,
        "level": level_for(score),
        "reasons": reasons,
        "features": dict(
            zip(ml.FEATURES, [n, distinct, sens, round(mb, 2), hour, int(newdev)])
        ),
    }
