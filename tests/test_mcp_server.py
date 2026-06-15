"""Tests for the sift-mcp server tool surface (sift_mcp.server).

Strict TDD: asserts the server exposes ONLY read-only forensic tools and no
destructive (write/delete/exec/shell) tool. This is the architectural
spoliation guarantee, verified against the tools actually registered on the
FastMCP instance, not just an intention.
"""

from __future__ import annotations

from sift_mcp import server

_EXPECTED = {
    "scan_image",
    "detect_record",
    "inspect_mft",
    "inspect_usnjrnl",
    "verify_leaf",
    "verify_db",
}

_DESTRUCTIVE_HINTS = (
    "write",
    "delete",
    "remove",
    "exec",
    "shell",
    "cmd",
    "format",
    "stomp",
    "modify",
    "patch",
    "spawn",
)


def _registered_names(srv) -> set[str]:
    return {t.name for t in srv._tool_manager.list_tools()}


class TestServerToolSurface:
    """The registered MCP tool surface is read-only by construction."""

    def test_registers_exactly_the_readonly_tools(self) -> None:
        srv = server.build_server()
        assert _registered_names(srv) == _EXPECTED

    def test_no_destructive_tool_exposed(self) -> None:
        srv = server.build_server()
        for name in _registered_names(srv):
            low = name.lower()
            for hint in _DESTRUCTIVE_HINTS:
                assert hint not in low, f"destructive-looking tool exposed: {name}"

    def test_readonly_registry_matches_expected(self) -> None:
        from_registry = {fn.__name__ for fn in server.READONLY_TOOLS}
        assert from_registry == _EXPECTED
