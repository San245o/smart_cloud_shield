"""RBAC (role) + ABAC (department, clearance) checks with JIT elevation support. Deny by default."""
from typing import Any, Dict, Optional, Tuple

REQUIRED_CLEARANCE = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "highly_confidential": 3,
}

CLEARANCE_TIERS: Dict[int, Dict[str, Any]] = {
    0: {
        "level": 0,
        "code": "L0",
        "name": "Public",
        "badge_class": "badge-l0",
        "color": "#10b981",
        "description": "Public unrestricted access",
    },
    1: {
        "level": 1,
        "code": "L1",
        "name": "Internal",
        "badge_class": "badge-l1",
        "color": "#0284c7",
        "description": "Standard internal employee access",
    },
    2: {
        "level": 2,
        "code": "L2",
        "name": "Confidential",
        "badge_class": "badge-l2",
        "color": "#f59e0b",
        "description": "Confidential departmental & managerial records",
    },
    3: {
        "level": 3,
        "code": "L3",
        "name": "Top Secret",
        "badge_class": "badge-l3",
        "color": "#ef4444",
        "description": "Top Secret enterprise intellectual property & PII",
    },
}

ROLE_PERMS = {
    "admin": {"upload", "download", "delete", "dashboard"},
    "employee": {"upload", "download"},
    "guest": set(),
}


def get_clearance_info(level: int) -> Dict[str, Any]:
    """Returns metadata for a numerical clearance level."""
    return CLEARANCE_TIERS.get(level, CLEARANCE_TIERS[1])


def file_required_clearance(f) -> int:
    """Calculates the minimum required clearance level for a file."""
    min_clr = getattr(f, "min_clearance", None)
    sens_clr = REQUIRED_CLEARANCE.get(f.sensitivity, 1)
    if min_clr is not None:
        return max(min_clr, sens_clr)
    return sens_clr


def get_active_grant(user_id: int, file_id: int):
    """Returns an active unexpired AccessRequest grant for the user and file, if one exists."""
    from scs.models import AccessRequest, utcnow
    try:
        return AccessRequest.query.filter_by(
            user_id=user_id,
            file_id=file_id,
            status="approved",
        ).filter(AccessRequest.expires_at > utcnow()).first()
    except Exception:
        return None


def has_pending_request(user_id: int, file_id: int) -> bool:
    """Checks if user has an unresolved pending elevation request for the file."""
    from scs.models import AccessRequest
    try:
        return bool(AccessRequest.query.filter_by(
            user_id=user_id,
            file_id=file_id,
            status="pending",
        ).first())
    except Exception:
        return False


def can(user, perm: str) -> bool:
    return perm in ROLE_PERMS.get(user.role, set())


def can_download(user, f) -> Tuple[bool, str]:
    """Return (allowed, reason). This answers 'MAY this user?'.
    The risk engine then answers 'does it look SAFE right now?'."""
    if user.status == "restricted":
        return False, "Account restricted by the security system. Contact an admin."
    if not can(user, "download"):
        return False, f"Role '{user.role}' may not download files."
    if user.role == "admin":
        return True, "admin"

    # Check for active JIT clearance elevation grant
    grant = get_active_grant(user.id, f.id)
    if grant:
        from scs.models import utcnow
        remaining_min = max(1, int((grant.expires_at - utcnow()).total_seconds() / 60))
        return True, f"Temporary clearance elevation active (approved by {grant.reviewed_by}, {remaining_min}m remaining)."

    need = file_required_clearance(f)
    if user.clearance < need:
        req_name = CLEARANCE_TIERS.get(need, {}).get("name", f"Level {need}")
        curr_name = CLEARANCE_TIERS.get(user.clearance, {}).get("name", f"Level {user.clearance}")
        return False, f"Clearance L{user.clearance} ({curr_name}) is below the L{need} ({req_name}) required for this file."

    if need >= 2 and f.department != user.department:
        return False, f"{f.sensitivity.replace('_', ' ').capitalize()} files are limited to the {f.department} department."

    return True, "ok"
