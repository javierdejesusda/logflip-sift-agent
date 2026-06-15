"""Read-only MCP server exposing the logflip NTFS anti-forensics engine as typed tools.

The server exposes only read-only forensic functions (scan, detect, inspect,
verify). It deliberately exposes no shell, write, or delete tool, so an LLM
agent driving it cannot modify or spoliate evidence. This boundary is
architectural, not a prompt instruction: the destructive capability does not
exist in the tool surface at all.
"""

__version__ = "0.1.0"
