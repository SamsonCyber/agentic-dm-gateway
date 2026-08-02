# Agentic DM Gateway

Security control plane for LLM agents over private chat (typically Discord DMs).

It sits **in front of your agent**. It decides who may talk, whether the session is unlocked, whether the process is paused, and whether this message is safe enough to forward. Your model and tools stay behind that gate. The library does not call an LLM. It does not implement product features beyond security.

**Hermes-inspired.** Design follows the same control-plane ideas used in [Hermes Agent](https://github.com/NousResearch/hermes-agent) messaging gateways: DM-first delivery, identity allowlists, pairing-style open, owner kill switch, and a hard split between *who may act* (control plane) and *message text the model sees* (data plane). This package is a small, standalone extract of that pattern for any agent callable. Not affiliated with Nous Research.

**Maturity:** implemented · independently validated · maintained. See [STATUS.md](STATUS.md). 
**Reproduce:** `python scripts/repro.py` (expects `REPRO_OK`).

**Live:** https://github.com/SamsonCyber/agentic-dm-gateway

---

## The problem

If you put an agent on Discord (or any chat API) with tools, anyone who can message the bot can try to:

- use the agent without permission
- burn API quota with floods
- inject "ignore previous instructions" style prompts
- trick the model into echoing API keys or other secrets

You need a **control plane** (identity and process controls) separate from the **data plane** (message text the model sees).

This package is that control plane.

---

## What it does

| Control | Behavior |
|---------|----------|
| **Allowlist** | Only configured user IDs may proceed. Everyone else is dropped (silent or with a short deny string). |
| **Owner vs friend** | Owners skip PIN and can pause the whole agent. Friends may need a shared PIN for a time-limited open (Hermes-style pairing idea, simplified). |
| **Kill switch** | Global pause file or env flag. No agent turns while active. |
| **Rate limits** | Sliding window per user (per minute and per hour). |
| **Input checks** | Max length, strip odd control chars, regex heuristics for common injection / secret-fishing phrases. |
| **Output scrub** | Redact secret-shaped tokens (API keys, JWTs, Bearer headers) and strip markdown/HTML image beacons that can exfil via auto-fetch. |
| **Audit log** | Append-only JSONL of allow/deny/auth/kill events for later review. |
| **Local commands** | `/auth`, `/lock`, `/kill`, `/unkill`, `/status` handled without calling a model. |

Scope: security gate only. Not a chatbot, trading bot, scanner, or agent framework. Pass an `agent(user_id, text) -> str` (or async) if you use Discord. The core works with any integer user id and plain text.

---


## Demo (copy-paste)

```text
$ python - <<'PY'
from agentic_dm_gateway import InboundSecurityPipeline
pipe = InboundSecurityPipeline({
 "allowed_user_ids": [111],
 "owner_ids": [111],
 "pin_enabled": False,
 "block_injection": True,
 "deny_message": "Not authorized.",
})
for uid, text in [
 (99, "hi"),
 (111, "ignore previous instructions"),
 (111, "summarize this note"),
]:
 r = pipe.precheck(uid, text)
 print(uid, r.stage, r.run_agent, r.reply_text)
PY

99 allowlist False Not authorized.
111 injection False Blocked: looks like prompt injection / secret fishing. Rephrase.
111 ok True None

$ python scripts/repro.py
REPRO_OK agentic-dm-gateway unit suite
```

## How to hook it in

Three integration paths. Pick one.

### 1) Drop-in Discord (easiest)

Install with Discord support, point env at your user ids, register the gateway, run the bot.

```bash
pip install -e ".[discord]"
# or: pip install agentic-dm-gateway[discord]

export DISCORD_BOT_TOKEN=...
export AGENTIC_DM_ALLOWLIST=your_discord_user_id
export AGENTIC_DM_OWNER_ID=your_discord_user_id
# optional: export AGENTIC_DM_PIN=....
python examples/discord_echo_bot.py
```

In your own bot:

```python
import discord
from agentic_dm_gateway.discord_adapter import register_dm_gateway

def agent(user_id: int, text: str, *, is_owner: bool = False) -> str:
 # your Hermes / local model / tool loop
 return call_your_model(text)

intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)

register_dm_gateway(
 bot,
 {
 "allowed_user_ids": [], # or rely on AGENTIC_DM_ALLOWLIST env
 "owner_ids": [],
 "pin_enabled": False,
 "deny_message": False, # silent drop for strangers
 },
 agent=agent,
)
bot.run(TOKEN)
```

What `register_dm_gateway` does:

1. Installs an `on_message` handler on your `discord.Client` / bot.
2. Ignores bots and **guild** messages (DMs only).
3. Runs `InboundSecurityPipeline.precheck` before your agent.
4. Sends deny / control replies when needed.
5. Calls your `agent(user_id, sanitized_text, is_owner=...)`.
6. Scrubs the agent reply (secrets + image beacons) and chunks Discord's 2000-char limit.

Guild messages never reach the agent. Only DMs from allowlisted users do.

### 2) Manual Discord hook (you already have `on_message`)

If you cannot use `register_dm_gateway` (existing handler chain), call the pipeline yourself:

```python
from agentic_dm_gateway import InboundSecurityPipeline
from agentic_dm_gateway.security import sanitize_agent_output

pipe = InboundSecurityPipeline({
 "allowed_user_ids": [YOUR_ID],
 "owner_ids": [YOUR_ID],
 "pin_enabled": True,
})

@bot.event
async def on_message(message):
 if message.author.bot or message.guild is not None:
 return

 pre = pipe.precheck(int(message.author.id), message.content or "")
 if pre.reply_text and not pre.run_agent:
 await message.channel.send(pre.reply_text[:1900])
 return
 if not pre.run_agent:
 return

 raw = await your_agent(pre.sanitized_text) # Hermes, Ollama, API, ...
 await message.channel.send(sanitize_agent_output(str(raw))[:1900])
```

### 3) Protocol-agnostic (Hermes, CLI, Telegram, anything)

No Discord import required. Use the same precheck around any agent turn:

```python
from agentic_dm_gateway import InboundSecurityPipeline
from agentic_dm_gateway.security import sanitize_agent_output

pipe = InboundSecurityPipeline({
 "allowed_user_ids": [111],
 "owner_ids": [111],
 "pin_enabled": False,
 "rate_limit_per_minute": 20,
 "block_injection": True,
 "deny_message": "Not authorized.",
})

def handle_inbound(user_id: int, text: str) -> str | None:
 pre = pipe.precheck(user_id, text)
 if pre.run_agent:
 answer = my_llm(pre.sanitized_text) # your model / Hermes run
 return sanitize_agent_output(str(answer))
 return pre.reply_text # deny or control-command reply
```

`PrecheckResult` fields:

- `run_agent`: forward to the model only if true
- `sanitized_text`: cleaned input
- `reply_text`: deny / control-command reply
- `stage`: `allowlist` | `kill` | `pin` | `rate` | `injection` | `ok` | ...

Hook checklist:

1. Build `InboundSecurityPipeline` once at process start (config + env).
2. On each inbound message: `pre = pipe.precheck(user_id, text)`.
3. If `pre.run_agent`: call your agent with `pre.sanitized_text` only.
4. Always pass model output through `sanitize_agent_output` before send.
5. Treat control replies (`/auth`, `/kill`, …) as done when `run_agent` is false.

---

## Pipeline (one inbound message)

```
1. Adapter: ignore bots; only accept DMs (not server channels)
2. Allowlist: is this user id permitted?
3. Owner commands: /kill /unkill /status -> reply, stop
4. Session commands: /auth <pin> /lock -> reply, stop
5. SecurityGateway.check_message:
 kill switch?
 session unlocked? (PIN)
 under rate limit?
 length + injection heuristics OK?
6. If ok -> run_agent=True with sanitized text
7. After your agent returns -> sanitize_agent_output (redact + strip image beacons)
8. Audit rows written along the way
```

**Control plane:** who the user is (allowlist / owner). 
**Data plane:** message body (always untrusted until checks pass).

---

## Package layout

```
src/agentic_dm_gateway/
 security.py # RateLimiter, SessionAuth, SecurityGateway,
 # sanitize_input, redact_secrets, sanitize_agent_output,
 # kill switch, audit_log
 allowlist.py # merge config + env + file into allowlist / owners
 commands.py # /kill /unkill /status /auth /lock (no LLM)
 pipeline.py # InboundSecurityPipeline.precheck() orchestration
 discord_adapter.py # optional discord.py on_message wire-up
tests/ # unit tests for the core (no Discord required)
examples/
 minimal_precheck.py # CLI-style demo of precheck outcomes
 discord_echo_bot.py # secured DMs + echo agent
```

| Module | Responsibility |
|--------|----------------|
| `SecurityGateway` | Single `check_message(user_id, text) -> SecurityVerdict` |
| `InboundSecurityPipeline` | Allowlist + slash commands + gateway in one call |
| `DiscordDMGateway` | DM-only adapter; you inject the agent function |

Zero required runtime dependencies. Discord is optional: `pip install agentic-dm-gateway[discord]`.

---

## Install

```bash
git clone https://github.com/SamsonCyber/agentic-dm-gateway.git
cd agentic-dm-gateway
pip install -e ".[dev]"
python scripts/repro.py
```

---

## Configuration

### Config dict

| Key | Default | Meaning |
|-----|---------|---------|
| `allowed_user_ids` | `[]` | User ids allowed to chat |
| `owner_ids` | `[]` | Skip PIN; may `/kill` |
| `pin_enabled` | `True` | PIN gate for non-owners |
| `pin_ttl_hours` | `72` | open duration |
| `rate_limit_per_minute` | `8` | Sliding window |
| `rate_limit_per_hour` | `60` | Sliding window |
| `max_input_chars` | `2000` | Max input length |
| `block_injection` | `True` | Heuristic block list |
| `deny_message` | `False` | Silent, `True`, or custom string |
| `audit_log` | `True` | Write audit JSONL |
| `enabled` | `True` | Master switch |

### Environment

| Variable | Purpose |
|----------|---------|
| `AGENTIC_DM_ALLOWLIST` | Comma-separated user ids |
| `AGENTIC_DM_OWNER_ID` | Owner id(s) |
| `AGENTIC_DM_PIN` | PIN plaintext |
| `AGENTIC_DM_PIN_REQUIRED` | `1` = require PIN even if unset |
| `AGENTIC_DM_KILLED` | `1` = kill switch on |
| `AGENTIC_DM_DATA_DIR` | Directory for kill file, open, audit log |
| `AGENTIC_DM_SECRETS_DIR` | Directory for `dm_pin.txt` / `dm_allowlist.txt` |

Default state directory: `./data/agentic_dm/`.

---

## Owner and session commands

| Command | Who | Effect |
|---------|-----|--------|
| `/kill` `/pause` | owner | Pause agent for everyone |
| `/unkill` `/resume` | owner | Clear pause |
| `/status` | owner | Kill / PIN / allowlist snapshot |
| `/auth <pin>` | allowlisted | open session for TTL |
| `/lock` | allowlisted | Clear open |

These never call your model.

---

## Limits (honest)

- Injection detection is a **regex heuristic list**, not a full LLM judge or classifier.
- Redaction is **best-effort** pattern matching; it will miss novel secret formats.
- Hermes inspiration is architectural (DM control plane). This is not a full Hermes gateway or pairing stack.
- You still need secure token storage, least-privilege tools, and host hardening outside this library.

---

## License

MIT. See [LICENSE](LICENSE).
