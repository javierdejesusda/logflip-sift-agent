"""sift-mcp: a read-only MCP server exposing the logflip engine as typed tools.

The server registers exactly the read-only forensic tools in READONLY_TOOLS and
nothing else. There is no write, delete, execute, or shell tool anywhere in the
surface, so an LLM agent driving this server cannot modify or spoliate the
evidence it analyzes. That guarantee is architectural (the capability is absent),
not a prompt instruction the model could ignore.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from sift_mcp import engine

# The complete tool surface. Every entry is a read-only forensic function from
# sift_mcp.engine. Adding a destructive tool here would break the read-only
# guarantee and the test_mcp_server surface tests.
READONLY_TOOLS = (
    engine.scan_image,
    engine.detect_record,
    engine.inspect_mft,
    engine.inspect_usnjrnl,
    engine.verify_leaf,
    engine.verify_db,
)


def build_server(name: str = "sift-mcp") -> FastMCP:
    """Build the FastMCP server with the read-only tool surface registered.

    Args:
        name: Server name advertised to MCP clients.

    Returns:
        A FastMCP instance with exactly the READONLY_TOOLS registered.
    """
    server = FastMCP(name)
    for fn in READONLY_TOOLS:
        server.add_tool(fn)
    return server


def main() -> None:
    """Run the sift-mcp server over stdio (console-script entry point)."""
    build_server().run()


if __name__ == "__main__":
    main()
