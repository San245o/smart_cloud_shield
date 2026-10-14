"""RBAC (role) + ABAC (department, clearance) checks. Deny by default."""

REQUIRED_CLEARANCE = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "highly_confidential": 3,
}

ROLE_PERMS = {
    "admin": {"upload", "download", "delete", "dashboard"},
    "employee": {"upload", "download"},
    "guest": set(),
}


def can(user, perm: str) -> bool:
    return perm in ROLE_PERMS.get(user.role, set())


def can_download(user, f) -> tuple[bool, str]:
    """Return (allowed, reason). This answers 'MAY this user?'.
    The risk engine then answers 'does it look SAFE right now?'."""
    if user.status == "restricted":
        return False, "Account restricted by the security system. Contact an admin."
    if not can(user, "download"):
        return False, f"Role '{user.role}' may not download files."
    if user.role == "admin":
        return True, "admin"
    need = REQUIRED_CLEARANCE.get(f.sensitivity, 3)
    if user.clearance < need:
        return False, f"Clearance {user.clearance} is below the {need} required for {f.sensitivity} files."
    if need >= 2 and f.department != user.department:
        return False, f"{f.sensitivity} files are limited to the {f.department} department."
    return True, "ok"
