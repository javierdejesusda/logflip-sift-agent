"""Anthropic-backed model client: a real LLM drives the read-only tool surface.

This is the autonomous-reasoning path. Claude chooses which tools to call given
the system prompt and the accumulated tool results; the orchestrator's guards
(max-iterations, verdict guard, session log) bound it regardless of what the
model decides. The Anthropic client is injectable so the translation logic is
unit-testable without an API key.
"""

from __future__ import annotations

import json
from typing import Any

from sift_agent.clients import AgentState, ToolCall, Turn
from sift_agent.prompts import DEFAULT_SYSTEM_PROMPT, initial_task
from sift_agent.tools import ANTHROPIC_TOOLS


class AnthropicModelClient:
    """Drives the triage loop with a Claude model via the tool-use API."""

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-6",
        system: str | None = None,
        max_tokens: int = 1024,
        client: Any | None = None,
    ) -> None:
        """Build the client.

        Args:
            model: Claude model id.
            system: System prompt; defaults to the senior-analyst prompt.
            max_tokens: Max output tokens per turn.
            client: An object exposing messages.create(...); when None, a real
                anthropic.Anthropic() is constructed lazily (needs an API key).
        """
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        # Typed as Any: this is the external SDK boundary. The Anthropic message
        # and content-block shapes are accessed structurally below.
        self._client: Any = client
        self._model = model
        self._system = system or DEFAULT_SYSTEM_PROMPT
        self._max_tokens = max_tokens
        self._messages: list[dict[str, Any]] = []
        self._pending_tool_ids: list[str] = []
        self._consumed = 0
        self._started = False

    def decide(self, state: AgentState) -> Turn:
        """Send the running transcript to Claude and parse the next Turn."""
        if not self._started:
            self._messages.append(
                {"role": "user", "content": initial_task(state.image_path)}
            )
            self._started = True
        elif self._pending_tool_ids:
            new_obs = state.observations[self._consumed :]
            content = [
                {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(obs["result"], default=str),
                }
                for tool_id, obs in zip(self._pending_tool_ids, new_obs, strict=True)
            ]
            self._messages.append({"role": "user", "content": content})
            self._consumed = len(state.observations)
            self._pending_tool_ids = []

        response = self._client.messages.create(
            model=self._model,
            system=self._system,
            max_tokens=self._max_tokens,
            tools=ANTHROPIC_TOOLS,
            messages=self._messages,
        )
        self._messages.append({"role": "assistant", "content": response.content})

        tool_calls: list[ToolCall] = []
        texts: list[str] = []
        ids: list[str] = []
        # response.content is a union of block types; tool_use blocks carry
        # .name/.input/.id and text blocks carry .text.
        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(ToolCall(block.name, dict(block.input)))
                ids.append(block.id)
            elif block.type == "text":
                texts.append(block.text)
        self._pending_tool_ids = ids

        usage = {
            "input": getattr(response.usage, "input_tokens", 0),
            "output": getattr(response.usage, "output_tokens", 0),
        }
        reasoning = " ".join(texts).strip() or None
        if tool_calls:
            return Turn(tool_calls=tool_calls, reasoning=reasoning, usage=usage)
        return Turn(final_text=reasoning or "Triage complete.", reasoning=reasoning, usage=usage)
