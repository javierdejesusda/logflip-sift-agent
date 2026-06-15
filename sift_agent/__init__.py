"""Autonomous, self-correcting incident-response agent over the sift-mcp tool surface.

The agent triages an NTFS image, reasons about each candidate, and self-corrects
when the deterministic engine returns an inconclusive or single-source verdict by
pivoting to an independent failure-mode channel. A verdict guard clamps every agent
claim to the engine's signed gate output, so the agent can never assert a
confirmation the engine did not cryptographically support.
"""

__version__ = "0.1.0"
