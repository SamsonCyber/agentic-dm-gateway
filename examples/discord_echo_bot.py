"""
Example Discord bot: secured DMs, echo agent (no market tools).

  pip install -e ".[discord]"
  set DISCORD_BOT_TOKEN=...
  set AGENTIC_DM_ALLOWLIST=your_discord_user_id
  set AGENTIC_DM_OWNER_ID=your_discord_user_id
  python examples/discord_echo_bot.py
"""

from __future__ import annotations

import os

import discord

from agentic_dm_gateway.discord_adapter import register_dm_gateway

TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("Set DISCORD_BOT_TOKEN")

config = {
    "enabled": True,
    "allowed_user_ids": [],  # filled from env allowlist
    "owner_ids": [],
    "pin_enabled": False,
    "rate_limit_per_minute": 20,
    "rate_limit_per_hour": 200,
    "deny_message": False,  # silent drop for strangers
    "audit_log": True,
}


def echo_agent(user_id: int, text: str, *, is_owner: bool = False) -> str:
    role = "owner" if is_owner else "friend"
    return f"[{role}] secured echo: {text[:500]}"


intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)

register_dm_gateway(bot, config, agent=echo_agent)

if __name__ == "__main__":
    bot.run(TOKEN)
