"""Local control commands (no LLM). Shared by any adapter."""

from __future__ import annotations

import re
from typing import Any

from .security import audit_log, kill_switch_active, set_kill_switch

_KILL = frozenset({"/kill", "!kill", "/pause", "!pause"})
_RESUME = frozenset({"/unkill", "!unkill", "/resume", "!resume"})
_STATUS = frozenset({"/status", "!status"})
_LOCK = frozenset({"/lock", "!lock", "/logout", "!logout"})
_AUTH_BARE = frozenset({"/auth", "!auth"})
_AUTH_RE = re.compile(r"^[/!]auth\s+(\S+)\s*$", re.I)


def _norm(text: str) -> str:
    return (text or "").lower().strip()


def owner_control_reply(
    text: str,
    user_id: int,
    *,
    security: Any,
    allowlist_size: int,
    model: str | None = None,
) -> str | None:
    """Owner-only kill / resume / status. Returns reply or None if not a match."""
    low = _norm(text)
    if low in _KILL:
        set_kill_switch(True, getattr(security, "_kill_path", None))
        audit_log(
            "kill_on",
            user_id=user_id,
            path=getattr(security, "_audit_path", None),
        )
        return "Kill switch ON. Agent paused for everyone."
    if low in _RESUME:
        set_kill_switch(False, getattr(security, "_kill_path", None))
        audit_log(
            "kill_off",
            user_id=user_id,
            path=getattr(security, "_audit_path", None),
        )
        return "Kill switch OFF. Agent live."
    if low in _STATUS:
        pin_ok = bool(security and security.sessions.pin_configured())
        return (
            f"kill={kill_switch_active(getattr(security, '_kill_path', None))} "
            f"pin_configured={pin_ok} allowlist={allowlist_size} model={model or '-'}"
        )
    return None


def session_control_reply(text: str, user_id: int, *, security: Any) -> str | None:
    """Lock / auth for any allowlisted user."""
    low = _norm(text)
    audit_p = getattr(security, "_audit_path", None) if security else None
    if low in _LOCK:
        if security:
            security.sessions.lock(user_id)
        audit_log("session_lock", user_id=user_id, path=audit_p)
        return "Session locked. Use `/auth <pin>` to unlock."

    m = _AUTH_RE.match((text or "").strip())
    if m and security:
        ok, msg = security.sessions.try_auth(user_id, m.group(1))
        audit_log("auth_attempt", user_id=user_id, detail={"ok": ok}, path=audit_p)
        return msg
    if low in _AUTH_BARE:
        return "Usage: `/auth <pin>`"
    return None
