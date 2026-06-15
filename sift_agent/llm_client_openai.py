"""OpenAI-backed model client: a real LLM drives the read-only tool surface.

This mirrors sift_agent.llm_client.AnthropicModelClient for the OpenAI Chat
Completions tool-calling API, so the orchestrator stays model-agnostic: both
clients satisfy the ModelClient protocol (decide(state) -> Turn) and are bounded
by the same guards (max-iterations, verdict guard, session log). The verdict in a
finding still comes only from the engine's signed leaf, never from model prose.

The OpenAI client is injectable so the translation logic is unit-testable without
an API key.
"""

from __future__ import annotations

import json
from typing import Any

from sift_agent.clients import AgentState, ToolCall, Turn
from sift_agent.prompts import DEFAULT_SYSTEM_PROMPT, initial_task
from sift_agent.tools import OPENAI_TOOLS


class OpenAIModelClient:
    """Drives the triage loop with an OpenAI model via the tool-calling API."""

    def __init__(
        self,
        *,
        model: str = "gpt-4o",
        system: str | None = None,
        max_tokens: int = 1024,
        client: Any | None = None,
    ) -> None:
        """Build the client.

        Args:
            model: OpenAI model id (must support tool calling).
            system: System prompt; defaults to the senior-analyst prompt.
            max_tokens: Max output tokens per turn.
            client: An object exposing chat.completions.create(...); when None, a
                real openai.OpenAI() is constructed lazily (needs an API key).
        """
        if client is None:
            import openai

            client = openai.OpenAI()
        # Typed as Any: this is the external SDK boundary. The OpenAI message and
        # tool-call shapes are accessed structurally below.
        self._client: Any = client
        self._model = model
        self._system = system or DEFAULT_SYSTEM_PROMPT
        self._max_tokens = max_tokens
        self._messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system}
        ]
        self._pending_tool_ids: list[str] = []
        self._consumed = 0
        self._started = False

    def decide(self, state: AgentState) -> Turn:
        """Send the running transcript to OpenAI and parse the next Turn."""
        if not self._started:
            self._messages.append(
                {"role": "user", "content": initial_task(state.image_path)}
            )
            self._started = True
        elif self._pending_tool_ids:
            new_obs = state.observations[self._consumed :]
            for tool_id, obs in zip(self._pending_tool_ids, new_obs, strict=True):
                self._messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps(obs["result"], default=str),
                    }
                )
            self._consumed = len(state.observations)
            self._pending_tool_ids = []

        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            tools=OPENAI_TOOLS,
            messages=self._messages,
        )
        message = response.choices[0].message

        tool_calls: list[ToolCall] = []
        assistant_tool_calls: list[dict[str, Any]] = []
        # message.tool_calls carry .id and .function.name/.function.arguments
        # (a JSON string, unlike Anthropic's already-parsed .input dict).
        for raw in message.tool_calls or []:
            args = json.loads(raw.function.arguments or "{}")
            tool_calls.append(ToolCall(raw.function.name, args))
            assistant_tool_calls.append(
                {
                    "id": raw.id,
                    "type": "function",
                    "function": {
                        "name": raw.function.name,
                        "arguments": raw.function.arguments,
                    },
                }
            )

        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": message.content,
        }
        if assistant_tool_calls:
            assistant_message["tool_calls"] = assistant_tool_calls
        self._messages.append(assistant_message)
        self._pending_tool_ids = [tc["id"] for tc in assistant_tool_calls]

        usage = {
            "input": getattr(response.usage, "prompt_tokens", 0),
            "output": getattr(response.usage, "completion_tokens", 0),
        }
        reasoning = (message.content or "").strip() or None
        if tool_calls:
            return Turn(tool_calls=tool_calls, reasoning=reasoning, usage=usage)
        return Turn(final_text=reasoning or "Triage complete.", reasoning=reasoning, usage=usage)
