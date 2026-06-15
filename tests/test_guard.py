"""Tests for the verdict guard (sift_agent.guard).

Strict TDD: the guard re-derives a finding from the engine's signed-leaf output
and refuses any agent claim that exceeds it. A hallucinated escalation is
structurally rejected here, on top of logflip's own 4-gate invariant.
"""

from __future__ import annotations

import pytest

from sift_agent.guard import VerdictGuardError, guard_finding


def _det(**over):
    base = {
        "mft_record": 5,
        "verdict": "provisional",
        "evil_confirmed": False,
        "tool_family": None,
        "confidence": 0.0,
        "scope_bounded": "scope string",
        "evidence_record_types": ["logfile_reverse_replay", "si_vs_fn_delta"],
    }
    base.update(over)
    return base


class TestVerdictGuard:
    def test_passes_through_engine_verdict(self) -> None:
        f = guard_finding(_det())
        assert f["verdict"] == "provisional"
        assert f["evil_confirmed"] is False
        assert f["evidence_record_types"]

    def test_rejects_agent_overclaim_confirmed(self) -> None:
        with pytest.raises(VerdictGuardError):
            guard_finding(_det(verdict="provisional", evil_confirmed=False), claimed_verdict="confirmed")

    def test_confirmed_requires_evil_confirmed_in_leaf(self) -> None:
        with pytest.raises(VerdictGuardError):
            guard_finding(_det(verdict="confirmed", evil_confirmed=False))

    def test_inconsistent_evil_confirmed_flag_rejected(self) -> None:
        with pytest.raises(VerdictGuardError):
            guard_finding(_det(verdict="provisional", evil_confirmed=True))

    def test_allows_confirmed_when_leaf_confirms(self) -> None:
        f = guard_finding(
            _det(verdict="confirmed", evil_confirmed=True, tool_family="SetMACE", confidence=0.95),
            claimed_verdict="confirmed",
        )
        assert f["verdict"] == "confirmed"
        assert f["evil_confirmed"] is True
        assert f["tool_family"] == "SetMACE"

    def test_conservative_claim_below_engine_is_allowed_engine_truth_wins(self) -> None:
        f = guard_finding(
            _det(verdict="confirmed", evil_confirmed=True, tool_family="X", confidence=0.9),
            claimed_verdict="provisional",
        )
        assert f["verdict"] == "confirmed"

    def test_unknown_verdict_rejected(self) -> None:
        with pytest.raises(VerdictGuardError):
            guard_finding(_det(verdict="totally_evil"))
