"""Agentic DM gateway — protocol-agnostic security controls for LLM chat over DMs."""

from .allowlist import load_allowlist_file, parse_ids, resolve_allowlist, resolve_identity
from .commands import owner_control_reply, session_control_reply
from .pipeline import InboundSecurityPipeline, PrecheckResult
from .security import (
    RateLimiter,
    SecurityGateway,
    SecurityVerdict,
    SessionAuth,
    audit_log,
    kill_switch_active,
    redact_secrets,
    sanitize_agent_output,
    sanitize_input,
    set_kill_switch,
)

__version__ = "0.1.0"

__all__ = [
    "InboundSecurityPipeline",
    "PrecheckResult",
    "RateLimiter",
    "SecurityGateway",
    "SecurityVerdict",
    "SessionAuth",
    "audit_log",
    "kill_switch_active",
    "load_allowlist_file",
    "owner_control_reply",
    "parse_ids",
    "redact_secrets",
    "resolve_allowlist",
    "resolve_identity",
    "sanitize_agent_output",
    "sanitize_input",
    "session_control_reply",
    "set_kill_switch",
    "__version__",
]
