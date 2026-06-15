"""Tool registry shared by the MCP server and the agent loop.

The registry maps tool names to the read-only engine functions in
sift_mcp.engine. It is the same surface the MCP server exposes, so the bundled
agent runner and an external MCP client (for example Claude Code) drive an
identical set of read-only tools. There is no destructive tool in the registry.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sift_mcp import engine

TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    "scan_image": engine.scan_image,
    "detect_record": engine.detect_record,
    "inspect_mft": engine.inspect_mft,
    "inspect_usnjrnl": engine.inspect_usnjrnl,
    "verify_leaf": engine.verify_leaf,
    "verify_db": engine.verify_db,
}


# JSON-Schema tool specifications for the Anthropic tool-use API. The names are
# exactly the keys of TOOL_REGISTRY, so the LLM driver and the dispatch layer
# share one surface.
ANTHROPIC_TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_image",
        "description": (
            "Scan every candidate MFT record in an NTFS image for timestomping. "
            "Returns candidates with verdicts (clean, anomaly, provisional, "
            "confirmed) and a summary. Always call this first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to the NTFS image."},
                "include_mft_deltas": {
                    "type": "boolean",
                    "description": "Also surface journal-less SI-vs-FN anomalies (default true).",
                },
                "key_path": {
                    "type": "string",
                    "description": "Optional engagement key path; omit for the demo key.",
                },
            },
            "required": ["image_path"],
        },
    },
    {
        "name": "detect_record",
        "description": (
            "Reverse-replay the $LogFile for one MFT record and return the signed "
            "verdict, evidence record types, and reconstructed/tampered timestamps."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string"},
                "mft_record": {"type": "integer"},
                "usnjrnl_record": {
                    "type": "integer",
                    "description": "Optional $UsnJrnl $J record number for a direct cross-check.",
                },
                "key_path": {"type": "string"},
            },
            "required": ["image_path", "mft_record"],
        },
    },
    {
        "name": "inspect_mft",
        "description": (
            "Parse one MFT record and report its SI-vs-FN timestamp delta, an "
            "independent corroboration channel."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string"},
                "mft_record": {"type": "integer"},
            },
            "required": ["image_path", "mft_record"],
        },
    },
    {
        "name": "inspect_usnjrnl",
        "description": (
            "Query the $UsnJrnl change journal for records about a file reference, "
            "the independent channel used to corroborate a single-source anomaly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "image_path": {"type": "string"},
                "file_ref": {"type": "integer"},
                "usnjrnl_record": {"type": "integer"},
            },
            "required": ["image_path", "file_ref"],
        },
    },
    {
        "name": "verify_leaf",
        "description": "Re-verify a signed leaf's HMAC against the engagement key.",
        "input_schema": {
            "type": "object",
            "properties": {
                "leaf_json_path": {"type": "string"},
                "key_path": {"type": "string"},
            },
            "required": ["leaf_json_path", "key_path"],
        },
    },
    {
        "name": "verify_db",
        "description": "Verify a signed fingerprint DB's HMAC against the master key.",
        "input_schema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string"},
                "key_path": {"type": "string"},
            },
            "required": ["db_path", "key_path"],
        },
    },
]


def _to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert the canonical Anthropic tool specs to OpenAI function-tool schema.

    The two APIs carry the same JSON Schema; only the envelope differs. Anthropic
    uses {name, description, input_schema}; OpenAI nests the same fields under
    {"type": "function", "function": {name, description, parameters}}.

    Args:
        tools: Tool specs in the Anthropic tool-use shape.

    Returns:
        The equivalent specs in the OpenAI function-tool shape.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }
        for tool in tools
    ]


# The same read-only surface re-encoded for the OpenAI Chat Completions API, so
# both LLM drivers and the dispatch layer share one set of tool names.
OPENAI_TOOLS: list[dict[str, Any]] = _to_openai_tools(ANTHROPIC_TOOLS)


class ToolDispatchError(KeyError):
    """Raised when an unknown tool name is dispatched."""


def dispatch(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a read-only tool by name with keyword arguments.

    Args:
        name: Registered tool name.
        args: Keyword arguments for the tool.

    Returns:
        The tool's result dict.

    Raises:
        ToolDispatchError: If name is not a registered read-only tool.
    """
    if name not in TOOL_REGISTRY:
        raise ToolDispatchError(name)
    return TOOL_REGISTRY[name](**args)
