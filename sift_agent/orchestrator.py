"""The autonomous triage loop with architectural guards.

triage_image drives a model client around the read-only tool surface. Regardless
of which client drives it, the loop enforces three guarantees that do not depend
on the model behaving:

- a hard max-iterations cap (anti-runaway),
- a verdict guard so a reported finding's structured verdict comes only from the
  engine's signed leaf, never from model prose,
- a structured session log of every step (when a session is supplied).

Findings are assembled from the engine tool outputs after the loop, so model
narration can never inflate a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from sift_agent.clients import AgentState, ModelClient
from sift_agent.guard import guard_finding
from sift_agent.tools import dispatch

DEFAULT_MAX_ITERATIONS = 24


@dataclass
class TriageReport:
    """Outcome of a triage run.

    Attributes:
        findings: Engine-derived findings (one per non-clean record).
        observations: Ordered list of every {tool, args, result} executed.
        iterations: Number of loop iterations consumed.
        halted_reason: "complete" when the model concluded, else "max_iterations".
        final_text: The model's closing narrative, if any.
    """

    findings: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    iterations: int
    halted_reason: str
    final_text: str | None


def _find_result(
    observations: list[dict[str, Any]], tool: str, arg_key: str, value: Any
) -> dict[str, Any] | None:
    """Return the result of the first observation matching tool and an arg value."""
    for o in observations:
        if o["tool"] == tool and o["args"].get(arg_key) == value:
            return cast("dict[str, Any]", o["result"])
    return None


def _assemble_findings(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build engine-derived findings from the observation trail.

    Provisional and confirmed findings come from detect_record outputs and pass
    through the verdict guard (with the signed leaf attached). Anomalies come from
    the scan classification, annotated with whatever corroboration the loop
    gathered; they are never escalated.

    Args:
        observations: The ordered tool-call observation trail.

    Returns:
        A list of finding dicts, one per non-clean record.
    """
    findings: dict[int, dict[str, Any]] = {}

    for o in observations:
        if o["tool"] != "detect_record":
            continue
        result = o["result"]
        if result.get("verdict") in ("provisional", "confirmed"):
            finding = guard_finding(result)
            finding["leaf"] = result.get("leaf")
            finding["source"] = "logfile_reverse_replay"
            findings[result["mft_record"]] = finding

    scan = next((o for o in observations if o["tool"] == "scan_image"), None)
    if scan is not None:
        for candidate in scan["result"].get("candidates", []):
            if candidate["verdict"] != "anomaly":
                continue
            record = candidate["mft_record"]
            if record in findings:
                continue
            usn = _find_result(observations, "inspect_usnjrnl", "file_ref", record)
            mft = _find_result(observations, "inspect_mft", "mft_record", record)
            findings[record] = {
                "mft_record": record,
                "verdict": "anomaly",
                "evil_confirmed": False,
                "tool_family": None,
                "source": "si_fn_delta",
                "corroboration": {
                    "usn_present": (usn or {}).get("present"),
                    "si_fn_delta_nonzero": (mft or {}).get("si_fn_delta_nonzero"),
                },
                "note": (
                    "single-source anomaly, no $LogFile coverage; requires manual "
                    "corroboration and is never auto-confirmed"
                ),
            }

    return list(findings.values())


def triage_image(
    image_path: str,
    *,
    model_client: ModelClient,
    key_path: str | None = None,
    usnjrnl_record: int | None = None,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    session: Any | None = None,
) -> TriageReport:
    """Run the autonomous triage loop over an NTFS image.

    Args:
        image_path: Path to the NTFS image (opened read-only by the tools).
        model_client: The client that decides each Turn.
        key_path: Optional engagement key path (demo key when None).
        usnjrnl_record: Optional $UsnJrnl $J record number for corroboration on
            images without $Extend auto-discovery.
        max_iterations: Hard cap on loop iterations (anti-runaway).
        session: Optional session log with record_step / record_tool /
            record_findings methods.

    Returns:
        A TriageReport with engine-derived findings and the full observation trail.
    """
    state = AgentState(
        image_path=image_path, key_path=key_path, usnjrnl_record=usnjrnl_record
    )
    final_text: str | None = None
    halted_reason = "max_iterations"
    iterations = 0

    for i in range(1, max_iterations + 1):
        iterations = i
        turn = model_client.decide(state)
        if session is not None:
            session.record_step(i, turn.reasoning, turn.usage)

        if turn.final_text is not None and not turn.tool_calls:
            final_text = turn.final_text
            halted_reason = "complete"
            break

        for tool_call in turn.tool_calls:
            result = dispatch(tool_call.name, tool_call.args)
            state.observations.append(
                {"tool": tool_call.name, "args": tool_call.args, "result": result}
            )
            if session is not None:
                session.record_tool(i, tool_call.name, tool_call.args, result)

    findings = _assemble_findings(state.observations)
    if session is not None:
        session.record_findings(findings)
        session.record_meta(
            halted_reason=halted_reason,
            iterations=iterations,
            finding_count=len(findings),
        )

    return TriageReport(
        findings=findings,
        observations=state.observations,
        iterations=iterations,
        halted_reason=halted_reason,
        final_text=final_text,
    )
