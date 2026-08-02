"""Identity allowlist for agentic DM chat.

Sources (merged):
1. config allowed_user_ids / owner_ids
2. AGENTIC_DM_ALLOWLIST env (comma-separated snowflakes)
3. allowlist file (AGENTIC_DM_ALLOWLIST_FILE or ~/.secrets/dm_allowlist.txt)
4. AGENTIC_DM_OWNER_ID / DISCORD_OWNER_ID env
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


def default_allowlist_file() -> Path:
    env = os.environ.get("AGENTIC_DM_ALLOWLIST_FILE", "").strip()
    if env:
        return Path(env)
    secrets = os.environ.get("AGENTIC_DM_SECRETS_DIR", "").strip()
    if secrets:
        return Path(secrets) / "dm_allowlist.txt"
    return Path.home() / ".secrets" / "dm_allowlist.txt"


def parse_ids(raw: str | None) -> set[int]:
    out: set[int] = set()
    if not raw:
        return out
    for part in raw.replace("\n", ",").split(","):
        part = part.strip()
        if not part or part.startswith("#"):
            continue
        part = part.split("#", 1)[0].strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            continue
    return out


def load_allowlist_file(path: Path | None = None) -> set[int]:
    path = path or default_allowlist_file()
    if not path.exists():
        return set()
    try:
        return parse_ids(path.read_text(encoding="utf-8"))
    except OSError:
        return set()


def resolve_allowlist(
    config_ids: Iterable[int] | None = None,
    *,
    env_var: str = "AGENTIC_DM_ALLOWLIST",
    allowlist_file: Path | None = None,
    include_owner_env: bool = True,
) -> set[int]:
    ids: set[int] = set()
    if config_ids:
        for i in config_ids:
            try:
                ids.add(int(i))
            except (TypeError, ValueError):
                continue
    ids |= parse_ids(os.environ.get(env_var, ""))
    ids |= load_allowlist_file(allowlist_file)
    if include_owner_env:
        ids |= parse_ids(os.environ.get("AGENTIC_DM_OWNER_ID", ""))
        ids |= parse_ids(os.environ.get("DISCORD_OWNER_ID", ""))
    return ids


def resolve_identity(config: dict | None = None) -> tuple[set[int], set[int]]:
    """Return (allowlist, owners). Owners are always on the allowlist."""
    cfg = dict(config or {})
    owners = set()
    for x in cfg.get("owner_ids") or []:
        try:
            owners.add(int(x))
        except (TypeError, ValueError):
            continue
    owners |= parse_ids(os.environ.get("AGENTIC_DM_OWNER_ID", ""))
    owners |= parse_ids(os.environ.get("DISCORD_OWNER_ID", ""))

    allowlist = resolve_allowlist(
        cfg.get("allowed_user_ids") or [],
        include_owner_env=True,
    )
    allowlist |= owners
    return allowlist, owners
