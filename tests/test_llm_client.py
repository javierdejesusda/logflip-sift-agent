"""Tests for the Anthropic LLM client translation logic (sift_agent.llm_client).

Strict TDD. The Anthropic client is driven through an injected fake so the
tool-use parsing and tool-spec contract are verified without an API key.
"""

from __future__ import annotations

from sift_agent.clients import AgentState
from sift_agent.llm_client import AnthropicModelClient
from sift_agent.tools import ANTHROPIC_TOOLS, TOOL_REGISTRY


class _Block:
    def __init__(self, **kw) -> None:
        self.__dict__.update(kw)


class _Usage:
    def __init__(self, i: int, o: int) -> None:
        self.input_tokens = i
        self.output_tokens = o


class _Resp:
    def __init__(self, content, usage) -> None:
        self.content = content
        self.usage = usage


class _Messages:
    def __init__(self, resp) -> None:
        self._resp = resp
        self.calls: list[dict] = []

    def create(self, **kw):
        self.calls.append(kw)
        return self._resp


class _FakeClient:
    def __init__(self, resp) -> None:
        self.messages = _Messages(resp)


class TestAnthropicToolSpecs:
    def test_specs_match_registry(self) -> None:
        names = {t["name"] for t in ANTHROPIC_TOOLS}
        assert names == set(TOOL_REGISTRY)

    def test_each_spec_is_well_formed(self) -> None:
        for spec in ANTHROPIC_TOOLS:
            schema = spec["input_schema"]
            assert schema["type"] == "object"
            assert "required" in schema
            assert "properties" in schema


class TestDecideParsing:
    def test_tool_use_block_becomes_tool_call(self) -> None:
        resp = _Resp(
            [
                _Block(type="text", text="Let me scan the image first."),
                _Block(type="tool_use", name="scan_image", input={"image_path": "x"}, id="t1"),
            ],
            _Usage(10, 5),
        )
        client = AnthropicModelClient(client=_FakeClient(resp))
        turn = client.decide(AgentState(image_path="x"))
        assert turn.tool_calls[0].name == "scan_image"
        assert turn.tool_calls[0].args == {"image_path": "x"}
        assert turn.reasoning == "Let me scan the image first."
        assert turn.usage == {"input": 10, "output": 5}
        assert turn.final_text is None

    def test_text_only_response_becomes_final(self) -> None:
        resp = _Resp([_Block(type="text", text="All records are clean.")], _Usage(3, 2))
        client = AnthropicModelClient(client=_FakeClient(resp))
        turn = client.decide(AgentState(image_path="x"))
        assert turn.final_text == "All records are clean."
        assert not turn.tool_calls
