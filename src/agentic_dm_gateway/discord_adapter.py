"""
Optional Discord adapter (requires: pip install agentic-dm-gateway[discord]).

Wires InboundSecurityPipeline to discord.py DMs only.
You supply the agent callable; this package never imports market logic.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .pipeline import InboundSecurityPipeline
from .security import redact_secrets, sanitize_agent_output

log = logging.getLogger("agentic_dm_gateway.discord")

# agent(user_id, text, *, is_owner) -> str  (sync or async)
AgentFn = Callable[..., Any]


class DiscordDMGateway:
    """Register on a discord.Client / commands.Bot."""

    def __init__(
        self,
        bot: Any,
        config: dict[str, Any] | None = None,
        *,
        agent: AgentFn | None = None,
        path_overrides: dict[str, Any] | None = None,
    ):
        self.bot = bot
        self.config = dict(config or {})
        self.agent = agent
        self.pipeline = InboundSecurityPipeline(self.config, **(path_overrides or {}))
        self._locks: dict[int, asyncio.Lock] = {}

    def _lock_for(self, user_id: int) -> asyncio.Lock:
        if user_id not in self._locks:
            self._locks[user_id] = asyncio.Lock()
        return self._locks[user_id]

    def is_dm(self, message: Any) -> bool:
        import discord

        if message.guild is not None:
            return False
        ch = message.channel
        try:
            return isinstance(ch, discord.DMChannel) or getattr(
                ch, "type", None
            ) == discord.ChannelType.private
        except Exception:
            return True

    async def handle_message(self, message: Any) -> bool:
        """
        Process one Discord message. Returns True if consumed (including silent deny).
        """
        import discord

        if not self.config.get("enabled", True) or message.author.bot:
            return False
        if not self.is_dm(message):
            return False

        pre = self.pipeline.precheck(
            int(message.author.id),
            message.content or "",
            is_bot=bool(message.author.bot),
        )

        if pre.reply_text and not pre.run_agent:
            try:
                await message.channel.send(pre.reply_text[:1900])
            except discord.HTTPException:
                pass
            return True

        if not pre.run_agent:
            return True

        if self.agent is None:
            try:
                await message.channel.send(
                    "Agent not configured. Pass agent= to DiscordDMGateway."
                )
            except discord.HTTPException:
                pass
            return True

        lock = self._lock_for(pre.user_id)
        if lock.locked():
            try:
                await message.channel.send("Still working on your last ask.")
            except discord.HTTPException:
                pass
            return True

        async with lock:
            await self._run_agent(message, pre.sanitized_text, pre.is_owner)
        return True

    async def _run_agent(self, message: Any, text: str, is_owner: bool) -> None:
        import discord

        try:
            result = self.agent(
                int(message.author.id),
                text,
                is_owner=is_owner,
            )
            if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
                result = await result
            out = sanitize_agent_output(str(result or ""))
        except Exception as e:
            out = f"Agent error: {redact_secrets(str(e))[:500]}"
            log.exception("agent failed")

        # Discord 2000 char soft chunks
        chunk = 1900
        for i in range(0, max(len(out), 1), chunk):
            part = out[i : i + chunk] or "(empty)"
            try:
                await message.channel.send(part)
            except discord.HTTPException:
                break


def register_dm_gateway(
    bot: Any,
    config: dict[str, Any] | None = None,
    *,
    agent: AgentFn | None = None,
    path_overrides: dict[str, Any] | None = None,
) -> DiscordDMGateway:
    """Attach on_message handler. Returns gateway for tests."""
    gw = DiscordDMGateway(bot, config, agent=agent, path_overrides=path_overrides)

    @bot.event
    async def on_message(message):  # type: ignore[no-untyped-def]
        await gw.handle_message(message)

    return gw
