"""Verdict guard: clamp every reported finding to the engine's signed leaf.

The agent reasons in natural language, but a finding's structured verdict must
come from the deterministic engine, never from model text. guard_finding takes a
detect_record result (engine output) and returns the canonical finding, raising
VerdictGuardError if a caller tries to assert a confirmation the signed leaf does
not support. This is the prompt-to-architecture clamp that complements logflip's
own 4-gate never-false-confirm invariant.
"""

from __future__ import annotations

from typing import Any

_VALID_VERDICTS = {"clean", "anomaly", "provisional", "confirmed", "error"}

# Severity ordering used to detect an agent claim that exceeds the engine.
_RANK = {"error": -1, "clean": 0, "anomaly": 1, "provisional": 2, "confirmed": 3}


class VerdictGuardError(Exception):
    """Raised when a claimed verdict exceeds what the signed leaf supports."""


def _rank(verdict: str) -> int:
    """Return the severity rank of a verdict, or -2 if unknown."""
    return _RANK.get(verdict, -2)


def guard_finding(
    detect_result: dict[str, Any], *, claimed_verdict: str | None = None
) -> dict[str, Any]:
    """Return the canonical finding derived solely from the engine result.

    Args:
        detect_result: A detect_record engine output dict.
        claimed_verdict: Optional verdict the agent asserted in prose. If it
            ranks higher than the engine verdict (for example claims 'confirmed'
            when the leaf is only 'provisional'), VerdictGuardError is raised. A
            lower or equal claim is allowed; the engine verdict always wins.

    Returns:
        Canonical finding dict with verdict, evil_confirmed, tool_family,
        confidence, scope_bounded, and evidence_record_types copied verbatim from
        the engine result.

    Raises:
        VerdictGuardError: When the verdict is unknown, internally inconsistent,
            or the agent's claim over-states the engine verdict.
    """
    verdict = detect_result.get("verdict")
    evil_confirmed = bool(detect_result.get("evil_confirmed", False))

    if verdict not in _VALID_VERDICTS:
        raise VerdictGuardError(f"unknown engine verdict: {verdict!r}")
    if evil_confirmed and verdict != "confirmed":
        raise VerdictGuardError(
            f"inconsistent leaf: evil_confirmed=True but verdict is {verdict!r}"
        )
    if verdict == "confirmed" and not evil_confirmed:
        raise VerdictGuardError("verdict 'confirmed' without evil_confirmed in the signed leaf")
    if claimed_verdict is not None and _rank(claimed_verdict) > _rank(verdict):
        raise VerdictGuardError(
            f"agent claimed '{claimed_verdict}' but the engine verdict is '{verdict}'"
        )

    return {
        "mft_record": detect_result.get("mft_record"),
        "verdict": verdict,
        "evil_confirmed": evil_confirmed,
        "tool_family": detect_result.get("tool_family"),
        "confidence": detect_result.get("confidence"),
        "scope_bounded": detect_result.get("scope_bounded"),
        "evidence_record_types": detect_result.get("evidence_record_types", []),
    }
