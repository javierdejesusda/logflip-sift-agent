"""Tests for the OpenAI LLM client translation logic (sift_agent.llm_client_openai).

Strict TDD. The OpenAI client is driven through an injected fake so the
chat.completions tool-call parsing and the tool-spec conversion are verified
without an API key. It mirrors the Anthropic client's contract: decide(state)
returns a Turn whose verdict-bearing data still comes only from the engine.
"""

from __future__ import annotations

from sift_agent.clients import AgentState
from sift_agent.llm_client_openai import OpenAIModelClient
from sift_agent.tools import OPENAI_TOOLS, TOOL_REGISTRY


class _Fn:
    def __init__(self, name, arguments) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, id, name, arguments) -> None:
        self.id = id
        self.type = "function"
        self.function = _Fn(name, arguments)


class _Message:
    def __init__(self, content=None, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _Choice:
    def __init__(self, message) -> None:
        self.message = message


class _Usage:
    def __init__(self, prompt: int, completion: int) -> None:
        self.prompt_tokens = prompt
        self.completion_tokens = completion


class _Resp:
    def __init__(self, message, usage) -> None:
        self.choices = [_Choice(message)]
        self.usage = usage


class _Completions:
    def __init__(self, resp) -> None:
        self._resp = resp
        self.calls: list[dict] = []

    def create(self, **kw):
        self.calls.append(kw)
        return self._resp


class _Chat:
    def __init__(self, resp) -> None:
        self.completions = _Completions(resp)


class _FakeClient:
    def __init__(self, resp) -> None:
        self.chat = _Chat(resp)


class TestOpenAIToolSpecs:
    def test_specs_match_registry(self) -> None:
        names = {t["function"]["name"] for t in OPENAI_TOOLS}
        assert names == set(TOOL_REGISTRY)

    def test_each_spec_is_well_formed(self) -> None:
        for spec in OPENAI_TOOLS:
            assert spec["type"] == "function"
            params = spec["function"]["parameters"]
            assert params["type"] == "object"
            assert "required" in params
            assert "properties" in params


class TestDecideParsing:
    def test_tool_call_becomes_tool_call(self) -> None:
        resp = _Resp(
            _Message(
                content="Let me scan the image first.",
                tool_calls=[_ToolCall("call_1", "scan_image", '{"image_path": "x"}')],
            ),
            _Usage(10, 5),
        )
        client = OpenAIModelClient(client=_FakeClient(resp))
        turn = client.decide(AgentState(image_path="x"))
        assert turn.tool_calls[0].name == "scan_image"
        assert turn.tool_calls[0].args == {"image_path": "x"}
        assert turn.reasoning == "Let me scan the image first."
        assert turn.usage == {"input": 10, "output": 5}
        assert turn.final_text is None

    def test_text_only_response_becomes_final(self) -> None:
        resp = _Resp(_Message(content="All records are clean.", tool_calls=None), _Usage(3, 2))
        client = OpenAIModelClient(client=_FakeClient(resp))
        turn = client.decide(AgentState(image_path="x"))
        assert turn.final_text == "All records are clean."
        assert not turn.tool_calls

    def test_tool_call_arguments_are_parsed_from_json_string(self) -> None:
        resp = _Resp(
            _Message(
                content=None,
                tool_calls=[
                    _ToolCall("call_2", "detect_record", '{"image_path": "x", "mft_record": 5}')
                ],
            ),
            _Usage(7, 4),
        )
        client = OpenAIModelClient(client=_FakeClient(resp))
        turn = client.decide(AgentState(image_path="x"))
        assert turn.tool_calls[0].name == "detect_record"
        assert turn.tool_calls[0].args == {"image_path": "x", "mft_record": 5}
        assert turn.reasoning is None
