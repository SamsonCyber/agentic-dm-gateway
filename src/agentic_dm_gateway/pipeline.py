"""Protocol-agnostic precheck for one inbound DM turn.

Call after you know the message is a DM (not a guild channel).
Does not call an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .allowlist import resolve_identity
from .commands import owner_control_reply, session_control_reply
from .security import SecurityGateway, audit_log


@dataclass
class PrecheckResult:
    """Outcome of security precheck before agent run."""

    consumed: bool
    """True if the adapter should stop (deny, control cmd, or block)."""

    run_agent: bool
    """True only when the message may reach the LLM."""

    user_id: int
    stage: str = ""
    reply_text: str | None = None
    sanitized_text: str = ""
    is_owner: bool = False


class InboundSecurityPipeline:
    """Allowlist → owner/session commands → SecurityGateway.check_message."""

    def __init__(self, config: dict[str, Any] | None = None, **path_kw: Any):
        self.config = dict(config or {})
        self.allowlist, self.owners = resolve_identity(self.config)
        self.security = SecurityGateway.from_config(self.owners, self.config, **path_kw)
        self._audit = bool(self.config.get("audit_log", True))

    def precheck(self, user_id: int, text: str, *, is_bot: bool = False) -> PrecheckResult:
        if not self.config.get("enabled", True):
            return PrecheckResult(True, False, int(user_id), stage="disabled")

        if is_bot:
            return PrecheckResult(True, False, int(user_id), stage="bot")

        uid = int(user_id)
        is_owner = uid in self.owners
        content = (text or "").strip()

        if uid not in self.allowlist:
            if self._audit:
                audit_log(
                    "denied_allowlist",
                    user_id=uid,
                    path=getattr(self.security, "_audit_path", None),
                )
            deny = self.config.get("deny_message")
            reply = None
            if deny is True:
                reply = "Not authorized."
            elif isinstance(deny, str) and deny:
                reply = deny
            # deny_message False → silent drop
            return PrecheckResult(
                True,
                False,
                uid,
                stage="allowlist",
                reply_text=reply,
                is_owner=is_owner,
            )

        if not content:
            return PrecheckResult(True, False, uid, stage="empty", is_owner=is_owner)

        if is_owner:
            reply = owner_control_reply(
                content,
                uid,
                security=self.security,
                allowlist_size=len(self.allowlist),
                model=self.config.get("model"),
            )
            if reply is not None:
                return PrecheckResult(
                    True,
                    False,
                    uid,
                    stage="owner_cmd",
                    reply_text=reply,
                    is_owner=True,
                )

        reply = session_control_reply(content, uid, security=self.security)
        if reply is not None:
            return PrecheckResult(
                True,
                False,
                uid,
                stage="session_cmd",
                reply_text=reply,
                is_owner=is_owner,
            )

        verdict = self.security.check_message(uid, content)
        if not verdict.ok:
            return PrecheckResult(
                True,
                False,
                uid,
                stage=verdict.code or "blocked",
                reply_text=(verdict.reason or "Blocked.")[:1500],
                is_owner=is_owner,
            )

        if self._audit:
            audit_log(
                "turn_allowed",
                user_id=uid,
                detail={"chars": len(verdict.sanitized or content)},
                path=getattr(self.security, "_audit_path", None),
            )

        return PrecheckResult(
            False,
            True,
            uid,
            stage="ok",
            sanitized_text=verdict.sanitized or content,
            is_owner=is_owner,
        )
