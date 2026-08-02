"""
Agentic DM security controls (control plane vs data plane).

Layers (in order for check_message):
1. Kill switch (global halt)
2. Optional session PIN for non-owners
3. Per-user rate limits
4. Input size + injection heuristics
5. Secret redaction helpers for outputs
6. Append-only audit log

Identity allowlisting is separate (see allowlist.py). Callers enforce it first.
Message body is always untrusted data plane.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("agentic_dm_gateway.security")

_AUDIT_USER_ID: ContextVar[int] = ContextVar("agentic_dm_audit_user_id", default=0)


def set_audit_user_id(user_id: int) -> None:
    _AUDIT_USER_ID.set(int(user_id))


def get_audit_user_id() -> int:
    return int(_AUDIT_USER_ID.get() or 0)


def _data_dir() -> Path:
    raw = os.environ.get("AGENTIC_DM_DATA_DIR", "").strip()
    if raw:
        return Path(raw)
    return Path.cwd() / "data" / "agentic_dm"


def kill_switch_path() -> Path:
    return _data_dir() / "dm_kill_switch"


def audit_log_path() -> Path:
    return _data_dir() / "dm_audit.jsonl"


def session_unlock_path() -> Path:
    return _data_dir() / "dm_unlocked.json"


def default_pin_file() -> Path:
    env = os.environ.get("AGENTIC_DM_PIN_FILE", "").strip()
    if env:
        return Path(env)
    secrets = os.environ.get("AGENTIC_DM_SECRETS_DIR", "").strip()
    if secrets:
        return Path(secrets) / "dm_pin.txt"
    return Path.home() / ".secrets" / "dm_pin.txt"


_INJECTION_RES = [
    re.compile(p, re.I)
    for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"disregard\s+(all\s+)?(previous|your)\s+(instructions|rules)",
        r"you\s+are\s+now\s+",
        r"system\s*prompt",
        r"reveal\s+(your\s+)?(system|hidden)\s+prompt",
        r"print\s+(your\s+)?(system|developer)\s+(prompt|message)",
        r"\[?\s*SYSTEM\s+OVERRIDE",
        r"STEER-AUTHORITY-LEVEL",
        r"OUT-OF-BAND\s+(USER\s+)?MESSAGE",
        r"developer\s+mode\s+enabled",
        r"do\s+anything\s+now|\bDAN\b",
        r"jailbreak",
        r"bypass\s+(safety|guard|allowlist|auth)",
        r"(read|cat|type|open)\s+[~\\/].*secrets",
        r"~/?\.secrets",
        r"\bapi[_-]?key\b",
        r"\baccess[_-]?token\b",
        r"\brefresh[_-]?token\b",
        r"bearer\s+[A-Za-z0-9\-._~+/]{20,}",
        r"exfiltrat",
        r"send\s+(me\s+)?(the\s+)?(api\s*)?(keys?|passwords?|credentials)\b",
        r"export\s+(env|credentials|secrets)",
        r"</?\s*script\b",
        r";\s*(rm|curl|wget|powershell|Invoke-)",
        r"reveal\s+(the\s+)?(pin|password|api\s*key|canary)",
        r"act\s+as\s+(the\s+)?system\b",
        r"dump\s+(secrets?|keys?|credentials|env)\b",
    ]
]

_SECRET_PATTERNS = [
    re.compile(r"(?i)(sk-ant-[A-Za-z0-9\-_]{20,})"),
    re.compile(r"(?i)(sk-[A-Za-z0-9]{20,})"),
    re.compile(r"(?i)(xai-[A-Za-z0-9\-_]{20,})"),
    re.compile(r"(?i)(ghp_[A-Za-z0-9]{20,})"),
    re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[^\s'\"]{12,}"),
]

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]+\)", re.I)
_HTML_IMG = re.compile(r"<\s*img\b[^>]*>", re.I)
_URL_EXFIL_QUERY = re.compile(
    r"(https?://[^\s)>\]]+[?&](?:d|data|q|token|key|secret|payload)=)[^\s)>\]]+",
    re.I,
)


@dataclass
class SecurityVerdict:
    ok: bool
    reason: str = ""
    code: str = ""  # kill | pin | rate | length | injection | empty
    sanitized: str = ""


class RateLimiter:
    """Sliding-window rate limiter per user id."""

    def __init__(self, per_minute: int = 8, per_hour: int = 60):
        self.per_minute = max(1, int(per_minute))
        self.per_hour = max(1, int(per_hour))
        self._hits: dict[int, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, user_id: int) -> tuple[bool, str]:
        now = time.time()
        with self._lock:
            q = self._hits[int(user_id)]
            while q and now - q[0] > 3600:
                q.popleft()
            hour_count = len(q)
            min_count = sum(1 for t in q if now - t <= 60)
            if min_count >= self.per_minute:
                return False, f"Rate limit: {self.per_minute}/min. Wait a bit."
            if hour_count >= self.per_hour:
                return False, f"Rate limit: {self.per_hour}/hour. Cool down."
            q.append(now)
            return True, ""


def _const_eq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    out = 0
    for x, y in zip(a.encode(), b.encode(), strict=True):
        out |= x ^ y
    return out == 0


class SessionAuth:
    """Optional PIN gate for non-owner friends. Owners always unlocked."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        owners: set[int] | None = None,
        pin_file: Path | None = None,
        unlock_file: Path | None = None,
        ttl_hours: float = 72.0,
        pin_env: str = "AGENTIC_DM_PIN",
        pin_required_env: str = "AGENTIC_DM_PIN_REQUIRED",
    ):
        self.enabled = enabled
        self.owners = set(owners or set())
        self.pin_file = pin_file or default_pin_file()
        self.unlock_file = unlock_file or session_unlock_path()
        self.ttl_sec = max(3600.0, float(ttl_hours) * 3600.0)
        self.pin_env = pin_env
        self.pin_required_env = pin_required_env
        self._lock = threading.Lock()
        self._unlocked: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        if not self.unlock_file.exists():
            return
        try:
            data = json.loads(self.unlock_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._unlocked = {str(k): float(v) for k, v in data.items()}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            self._unlocked = {}

    def _save(self) -> None:
        self.unlock_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.unlock_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._unlocked, indent=2), encoding="utf-8")
        tmp.replace(self.unlock_file)

    def _pin_hash(self) -> str | None:
        raw = os.environ.get(self.pin_env, "").strip()
        if not raw and self.pin_file is not None and Path(self.pin_file).exists():
            try:
                raw = (
                    Path(self.pin_file).read_text(encoding="utf-8").strip().splitlines()[0].strip()
                )
            except OSError:
                raw = ""
        if not raw:
            return None
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def pin_configured(self) -> bool:
        return self._pin_hash() is not None

    def is_owner(self, user_id: int) -> bool:
        return int(user_id) in self.owners

    def _require_pin_strict(self) -> bool:
        return os.environ.get(self.pin_required_env, "0").strip().lower() in {
            "1",
            "true",
            "yes",
        }

    def is_unlocked(self, user_id: int) -> bool:
        if not self.enabled:
            return True
        if self.is_owner(user_id):
            return True
        if not self.pin_configured():
            # No PIN on disk: open for allowlisted friends unless strict required.
            return not self._require_pin_strict()
        key = str(int(user_id))
        with self._lock:
            exp = self._unlocked.get(key)
            if not exp:
                return False
            if time.time() > exp:
                self._unlocked.pop(key, None)
                self._save()
                return False
            return True

    def try_auth(self, user_id: int, pin: str) -> tuple[bool, str]:
        if self.is_owner(user_id):
            return True, "Owner account - always unlocked."
        expected = self._pin_hash()
        if not expected:
            return False, (
                "No PIN configured. Set AGENTIC_DM_PIN or write dm_pin.txt under "
                "AGENTIC_DM_SECRETS_DIR / ~/.secrets/."
            )
        got = hashlib.sha256(pin.strip().encode("utf-8")).hexdigest()
        if not _const_eq(got, expected):
            return False, "Bad PIN."
        with self._lock:
            self._unlocked[str(int(user_id))] = time.time() + self.ttl_sec
            self._save()
        hours = int(self.ttl_sec // 3600)
        return True, f"Unlocked for ~{hours}h."

    def lock(self, user_id: int) -> None:
        with self._lock:
            self._unlocked.pop(str(int(user_id)), None)
            self._save()


def kill_switch_active(path: Path | None = None) -> bool:
    if os.environ.get("AGENTIC_DM_KILLED", "").strip().lower() in {"1", "true", "yes"}:
        return True
    p = path or kill_switch_path()
    return p.exists()


def set_kill_switch(active: bool, path: Path | None = None) -> None:
    p = path or kill_switch_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if active:
        p.write_text(f"killed_at={time.time()}\n", encoding="utf-8")
    elif p.exists():
        p.unlink()


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def sanitize_agent_output(text: str) -> str:
    """Redact secrets and strip common exfil channels before send."""
    if not text:
        return text
    out = redact_secrets(text)
    out = _MD_IMAGE.sub("[image removed]", out)
    out = _HTML_IMG.sub("[image removed]", out)
    out = _URL_EXFIL_QUERY.sub(r"\1[REDACTED]", out)
    return out


def sanitize_input(text: str, max_chars: int = 2000) -> SecurityVerdict:
    raw = (text or "").strip()
    if not raw:
        return SecurityVerdict(False, "Empty message.", "empty")
    if len(raw) > max_chars:
        return SecurityVerdict(
            False,
            f"Message too long ({len(raw)} > {max_chars}). Split it up.",
            "length",
        )
    for pat in _INJECTION_RES:
        if pat.search(raw):
            return SecurityVerdict(
                False,
                "Blocked: looks like prompt injection / secret fishing. Rephrase.",
                "injection",
                sanitized=raw[:200],
            )
    cleaned = "".join(ch for ch in raw if ch in "\n\t" or ord(ch) >= 32)
    cleaned = cleaned.strip()
    if not cleaned:
        return SecurityVerdict(False, "Empty after sanitize.", "empty")
    return SecurityVerdict(True, sanitized=cleaned)


def audit_log(
    event: str,
    *,
    user_id: int,
    detail: dict | None = None,
    path: Path | None = None,
    tool_names: list | None = None,
    blocked_code: str | None = None,
) -> None:
    p = path or audit_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    detail_out = dict(detail or {})
    if tool_names is not None:
        detail_out.setdefault("tool_names", list(tool_names))
    if blocked_code is not None:
        detail_out.setdefault("blocked_code", blocked_code)
    row: dict = {
        "ts": time.time(),
        "event": event,
        "user_id": int(user_id),
        "detail": detail_out,
    }
    if tool_names is not None:
        row["tool_names"] = list(tool_names)
    if blocked_code is not None:
        row["blocked_code"] = blocked_code
    try:
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except OSError as e:
        log.warning(
            "audit_log write failed event=%s user_id=%s (%s)",
            event,
            user_id,
            e,
        )


class SecurityGateway:
    """Single entry for DM pre-checks after identity allowlist."""

    def __init__(
        self,
        *,
        owners: set[int] | None = None,
        per_minute: int = 8,
        per_hour: int = 60,
        max_input_chars: int = 2000,
        pin_enabled: bool = True,
        pin_ttl_hours: float = 72.0,
        block_injection: bool = True,
        pin_file: Path | None = None,
        unlock_file: Path | None = None,
        kill_path: Path | None = None,
        audit_path: Path | None = None,
    ):
        self.owners = set(owners or set())
        self.rate = RateLimiter(per_minute=per_minute, per_hour=per_hour)
        self.max_input_chars = max_input_chars
        self.block_injection = block_injection
        self._kill_path = kill_path
        self._audit_path = audit_path
        self.sessions = SessionAuth(
            enabled=pin_enabled,
            owners=self.owners,
            pin_file=pin_file,
            unlock_file=unlock_file,
            ttl_hours=pin_ttl_hours,
        )

    @classmethod
    def from_config(
        cls,
        owners: set[int] | None,
        config: dict | None = None,
        **path_overrides: Path | None,
    ) -> SecurityGateway:
        cfg = dict(config or {})
        return cls(
            owners=owners,
            per_minute=int(cfg.get("rate_limit_per_minute", 8)),
            per_hour=int(cfg.get("rate_limit_per_hour", 60)),
            max_input_chars=int(cfg.get("max_input_chars", 2000)),
            pin_enabled=bool(cfg.get("pin_enabled", True)),
            pin_ttl_hours=float(cfg.get("pin_ttl_hours", 72)),
            block_injection=bool(cfg.get("block_injection", True)),
            pin_file=path_overrides.get("pin_file"),
            unlock_file=path_overrides.get("unlock_file"),
            kill_path=path_overrides.get("kill_path"),
            audit_path=path_overrides.get("audit_path"),
        )

    def check_message(self, user_id: int, text: str) -> SecurityVerdict:
        uid = int(user_id)
        kill_p = self._kill_path
        audit_p = self._audit_path

        if kill_switch_active(kill_p):
            audit_log("blocked_kill", user_id=uid, blocked_code="kill", path=audit_p)
            return SecurityVerdict(False, "Agent is paused (kill switch).", "kill")

        low = (text or "").strip().lower()
        if low.startswith("/auth ") or low.startswith("!auth "):
            if len(text) > 200:
                return SecurityVerdict(False, "Auth line too long.", "length")
            return SecurityVerdict(True, sanitized=text.strip())

        if not self.sessions.is_unlocked(uid):
            audit_log("blocked_pin", user_id=uid, blocked_code="pin", path=audit_p)
            return SecurityVerdict(
                False,
                "Session locked. Send `/auth <pin>` first.",
                "pin",
            )

        ok, reason = self.rate.allow(uid)
        if not ok:
            audit_log(
                "blocked_rate",
                user_id=uid,
                detail={"reason": reason},
                blocked_code="rate",
                path=audit_p,
            )
            return SecurityVerdict(False, reason, "rate")

        verdict = sanitize_input(text, max_chars=self.max_input_chars)
        if not verdict.ok:
            if verdict.code == "injection" and not self.block_injection:
                return SecurityVerdict(True, sanitized=verdict.sanitized or text.strip())
            code = verdict.code or "input"
            audit_log(
                "blocked_" + code,
                user_id=uid,
                detail={"reason": (verdict.reason or "")[:200]},
                blocked_code=code,
                path=audit_p,
            )
            return verdict

        return SecurityVerdict(True, sanitized=verdict.sanitized)
