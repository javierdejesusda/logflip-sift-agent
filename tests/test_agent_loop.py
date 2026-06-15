"""Tests for the autonomous triage loop (sift_agent.orchestrator).

Strict TDD. Covers the deterministic analyst policy (happy path and the
self-correction-on-anomaly path) and the orchestrator's architectural guards
(max-iterations halt; model prose can never forge a confirmed verdict).
"""

from __future__ import annotations

from logflip.lab.synthetic import (
    ANOMALY_SLOT,
    STOMP_A,
    STOMP_B,
    USNJRNL_RECORD_NUM,
    build_image_with_journal_less_delta_record,
    build_multi_stomped_image,
)

from sift_agent.clients import AgentState, PolicyModelClient, ToolCall, Turn
from sift_agent.orchestrator import triage_image


def _img(tmp_path, data: bytes) -> str:
    p = tmp_path / "img.raw"
    p.write_bytes(data)
    return str(p)


class TestPolicyHappyPath:
    """The analyst policy scans first, then investigates each disagreeing record."""

    def test_scans_then_detects_two_provisional(self, tmp_path) -> None:
        path = _img(tmp_path, build_multi_stomped_image())
        report = triage_image(path, model_client=PolicyModelClient())

        assert report.halted_reason == "complete"
        verdicts = {f["mft_record"]: f["verdict"] for f in report.findings}
        assert verdicts.get(STOMP_A) == "provisional"
        assert verdicts.get(STOMP_B) == "provisional"

        tools_called = [o["tool"] for o in report.observations]
        assert tools_called[0] == "scan_image"
        assert tools_called.count("detect_record") >= 2
        for f in report.findings:
            assert f["evil_confirmed"] is False


class TestSelfCorrection:
    """A single-source anomaly triggers corroboration and is never escalated."""

    def test_anomaly_triggers_corroboration_and_stays_anomaly(self, tmp_path) -> None:
        image, _ = build_image_with_journal_less_delta_record()
        path = _img(tmp_path, image)
        report = triage_image(
            path, model_client=PolicyModelClient(), usnjrnl_record=USNJRNL_RECORD_NUM
        )

        tools_called = [o["tool"] for o in report.observations]
        assert "inspect_usnjrnl" in tools_called
        assert "inspect_mft" in tools_called

        anomaly = next(f for f in report.findings if f["mft_record"] == ANOMALY_SLOT)
        assert anomaly["verdict"] == "anomaly"
        assert anomaly["evil_confirmed"] is False
        assert "corroboration" in anomaly

        # The journaled stomps still resolve as provisional findings.
        verdicts = {f["mft_record"]: f["verdict"] for f in report.findings}
        assert verdicts.get(STOMP_A) == "provisional"


class TestArchitecturalGuards:
    """Guards that hold regardless of model behavior."""

    def test_max_iterations_halts_a_runaway_client(self, tmp_path) -> None:
        path = _img(tmp_path, build_multi_stomped_image())

        class _NeverFinishes:
            def decide(self, state: AgentState) -> Turn:
                return Turn(
                    tool_calls=[
                        ToolCall("inspect_mft", {"image_path": state.image_path, "mft_record": 5})
                    ],
                    reasoning="intentionally never concludes",
                )

        report = triage_image(path, model_client=_NeverFinishes(), max_iterations=3)
        assert report.halted_reason == "max_iterations"
        assert report.iterations == 3

    def test_model_prose_cannot_forge_a_confirmed_verdict(self, tmp_path) -> None:
        path = _img(tmp_path, build_multi_stomped_image())

        class _Overclaim:
            def __init__(self) -> None:
                self.step = 0

            def decide(self, state: AgentState) -> Turn:
                self.step += 1
                if self.step == 1:
                    return Turn(
                        tool_calls=[
                            ToolCall(
                                "detect_record",
                                {"image_path": state.image_path, "mft_record": STOMP_A, "key_path": None},
                            )
                        ]
                    )
                return Turn(final_text="CONFIRMED EVIL on every record!!!")

        report = triage_image(path, model_client=_Overclaim())
        finding = next(f for f in report.findings if f["mft_record"] == STOMP_A)
        assert finding["verdict"] == "provisional"
        assert finding["evil_confirmed"] is False
