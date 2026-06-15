"""Tests for the structured JSONL session log (sift_agent.session_log).

Strict TDD. Asserts the audit-trail invariants the hackathon requires: a
monotonic timestamp sequence, contiguous sequence numbers, valid JSONL on disk,
and that every finding traces back to the specific tool execution (and leaf)
that produced it.
"""

from __future__ import annotations

import json

from logflip.lab.synthetic import (
    STOMP_A,
    USNJRNL_RECORD_NUM,
    build_image_with_journal_less_delta_record,
)

from sift_agent.clients import PolicyModelClient
from sift_agent.orchestrator import triage_image
from sift_agent.session_log import SessionLog


class _Clock:
    """Deterministic, strictly increasing ISO-8601 clock for tests."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"2026-06-14T00:{self.n // 60:02d}:{self.n % 60:02d}.000000Z"


def _img(tmp_path, data: bytes) -> str:
    p = tmp_path / "img.raw"
    p.write_bytes(data)
    return str(p)


class TestSessionLogUnit:
    """Direct unit checks on the log writer."""

    def test_seq_and_timestamps_monotonic(self, tmp_path) -> None:
        log = SessionLog(tmp_path / "s.jsonl", clock=_Clock())
        log.record_step(1, "thinking", {"input": 10, "output": 5})
        log.record_tool(1, "scan_image", {"image_path": "x"}, {"verdict": None, "candidates": []})
        log.record_meta(halted_reason="complete", iterations=1)
        seqs = [ln["seq"] for ln in log.lines]
        assert seqs == [1, 2, 3]
        timestamps = [ln["ts"] for ln in log.lines]
        assert timestamps == sorted(timestamps)

    def test_finding_links_to_producing_tool(self, tmp_path) -> None:
        log = SessionLog(tmp_path / "s.jsonl", clock=_Clock())
        tool_line = log.record_tool(
            1, "detect_record", {"image_path": "x", "mft_record": 5}, {"verdict": "provisional"}
        )
        log.record_findings([{"mft_record": 5, "verdict": "provisional", "evil_confirmed": False}])
        finding = next(ln for ln in log.lines if ln["event"] == "finding")
        assert finding["produced_by_seq"] == tool_line["seq"]
        assert finding["leaf_ref"]


class TestSessionLogEndToEnd:
    """A full triage run produces a traceable JSONL audit trail on disk."""

    def test_jsonl_is_valid_and_findings_are_traceable(self, tmp_path) -> None:
        image, _ = build_image_with_journal_less_delta_record()
        path = _img(tmp_path, image)
        log_path = tmp_path / "session.jsonl"
        log = SessionLog(log_path, clock=_Clock())

        triage_image(
            path,
            model_client=PolicyModelClient(),
            usnjrnl_record=USNJRNL_RECORD_NUM,
            session=log,
        )
        log.close()

        raw_lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        parsed = [json.loads(line) for line in raw_lines]
        assert len(parsed) == len(log.lines)

        seqs = [ln["seq"] for ln in parsed]
        assert seqs == list(range(1, len(parsed) + 1))
        timestamps = [ln["ts"] for ln in parsed]
        assert timestamps == sorted(timestamps)

        tool_seqs = {ln["seq"] for ln in parsed if ln["event"] == "tool"}
        finding_lines = [ln for ln in parsed if ln["event"] == "finding"]
        assert finding_lines, "expected at least one finding line"
        for finding in finding_lines:
            assert finding["produced_by_seq"] in tool_seqs, (
                f"finding for record {finding['mft_record']} does not trace to a tool execution"
            )
            # Journaled findings have a signed leaf; anomalies honestly have none.
            if finding["verdict"] in ("provisional", "confirmed"):
                assert finding["leaf_ref"]
            else:
                assert finding["leaf_ref"] is None

        # An anomaly's corroboration evidence is linked to the inspect tools that
        # produced it, separately from the scan that produced the verdict.
        anomaly = next((ln for ln in finding_lines if ln["verdict"] == "anomaly"), None)
        assert anomaly is not None, "expected an anomaly finding in this case"
        assert anomaly["corroborated_by_seq"], "anomaly must link its corroboration tools"
        for seq in anomaly["corroborated_by_seq"]:
            assert seq in tool_seqs

        # The provisional stomp finding is present and traceable.
        prov = next(
            (ln for ln in finding_lines if ln["mft_record"] == STOMP_A), None
        )
        assert prov is not None
        assert prov["verdict"] == "provisional"
