# Agentic DM Gateway

**Security control plane for LLM agents over private DMs.**

Allowlist · optional PIN sessions · kill switch · rate limits · injection heuristics · secret redaction · append-only audit log.

No market logic. No scanners. No trading. Extracted from the design used by FinBot/Raven’s agentic Discord DM path, rewritten as a small dependency-free library.

```
DM message
  → bot/self ignore
  → DM-only (adapter)
  → allowlist (identity)
  → /kill /unkill /status (owners)
  → /auth /lock (session PIN)
  → kill switch · rate · length · injection
  → your agent (you plug this in)
  → redact secrets + strip image-beacon exfil on the way out
  → audit JSONL
```

Control plane = **who** (user id on allowlist).  
Data plane = **message body** (always untrusted).

## Install

```bash
pip install -e .
# optional Discord adapter
pip install -e ".[discord]"
```

## Quick use (no Discord)

```python
from agentic_dm_gateway.pipeline import InboundSecurityPipeline

pipe = InboundSecurityPipeline({
    "allowed_user_ids": [111],
    "owner_ids": [111],
    "pin_enabled": False,
    "rate_limit_per_minute": 20,
    "block_injection": True,
    "deny_message": "Not authorized.",
})

pre = pipe.precheck(111, "Summarize this paper abstract: ...")
if pre.run_agent:
    answer = my_llm(pre.sanitized_text)  # your code
elif pre.reply_text:
    send(pre.reply_text)
```

See `examples/minimal_precheck.py`.

## Discord adapter

```python
from agentic_dm_gateway.discord_adapter import register_dm_gateway

def agent(user_id: int, text: str, *, is_owner: bool = False) -> str:
    return call_your_model(text)

register_dm_gateway(bot, config, agent=agent)
```

Full example: `examples/discord_echo_bot.py`.

## Config keys

| Key | Default | Meaning |
|-----|---------|---------|
| `allowed_user_ids` | `[]` | Discord snowflakes (or any int ids) |
| `owner_ids` | `[]` | Skip PIN; can `/kill` |
| `pin_enabled` | `True` | Session PIN for non-owners |
| `pin_ttl_hours` | `72` | Unlock lifetime |
| `rate_limit_per_minute` | `8` | Sliding window |
| `rate_limit_per_hour` | `60` | Sliding window |
| `max_input_chars` | `2000` | Input cap |
| `block_injection` | `True` | Heuristic block list |
| `deny_message` | `False` | `False` silent, `True` generic, or custom string |
| `audit_log` | `True` | Write `dm_audit.jsonl` |
| `enabled` | `True` | Master switch |

### Env

| Env | Purpose |
|-----|---------|
| `AGENTIC_DM_ALLOWLIST` | Comma-separated user ids |
| `AGENTIC_DM_OWNER_ID` | Owner id(s) |
| `AGENTIC_DM_PIN` | Session PIN plaintext |
| `AGENTIC_DM_PIN_REQUIRED` | `1` = require PIN even if file missing |
| `AGENTIC_DM_KILLED` | `1` = kill switch on |
| `AGENTIC_DM_DATA_DIR` | State dir (kill file, audit, unlocks) |
| `AGENTIC_DM_SECRETS_DIR` | Where to find `dm_pin.txt` / `dm_allowlist.txt` |

## Owner / session commands

| Command | Who | Effect |
|---------|-----|--------|
| `/kill` `/pause` | owner | Global pause |
| `/unkill` `/resume` | owner | Clear pause |
| `/status` | owner | Kill/pin/allowlist snapshot |
| `/auth <pin>` | allowlisted | Unlock session |
| `/lock` | allowlisted | Clear unlock |

## Design notes

- **Fail closed on identity:** unknown users never reach the model.
- **PIN is optional:** owners always unlocked; friends need PIN when configured.
- **Injection list is heuristic**, not a full classifier. Pair with a real judge if stakes are high.
- **Redaction** is best-effort regex on outputs (API keys, JWTs, markdown image beacons).
- State files live under `AGENTIC_DM_DATA_DIR` (default `./data/agentic_dm`).

## Origin

Patterns distilled from an in-production agentic Discord DM bot (FinBot/Raven): allowlist + PIN + kill switch + rate limits + injection blocks + audit. This package is the **portable security kit only**.

## License

MIT. See [LICENSE](LICENSE).
