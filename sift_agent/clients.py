"""Model clients that drive the triage loop.

A model client decides the next action given the current AgentState. Three
implementations share one orchestrator:

- PolicyModelClient: a deterministic senior-analyst policy. It scans, investigates
  each disagreeing record, and self-corrects on a single-source anomaly by
  corroborating across independent channels before concluding. It needs no API
  key, so it is the reproducible demo path and the backbone of the loop tests.
- AnthropicModelClient (in llm_client.py): a real LLM driving the same tools for
  genuine autonomous reasoning.

The orchestrator's guarantees (max-iterations cap, verdict guard, structured
logging) hold no matter which client drives the loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    """A single tool invocation requested by a model client."""

    name: str
    args: dict[str, Any]


@dataclass
class Turn:
    """One decision from a model client: tool calls to run, or a final answer."""

    tool_calls: list[ToolCall] = field(default_factory=list)
    final_text: str | None = None
    reasoning: str | None = None
    usage: dict[str, int] = field(default_factory=dict)


@dataclass
class AgentState:
    """Accumulated state passed to a model client on each decision.

    Attributes:
        image_path: Path to the NTFS image under triage.
        key_path: Optional engagement key path (demo key when None).
        usnjrnl_record: Optional $UsnJrnl $J record number for images whose
            $Extend index does not support auto-discovery.
        observations: Ordered list of {tool, args, result} from prior tool calls.
    """

    image_path: str
    key_path: str | None = None
    usnjrnl_record: int | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)


class ModelClient(Protocol):
    """Decides the next Turn given the current AgentState."""

    def decide(self, state: AgentState) -> Turn: ...


def _has_detect(observations: list[dict[str, Any]], mft_record: int) -> bool:
    """Return True if detect_record has already run for mft_record."""
    return any(
        o["tool"] == "detect_record" and o["args"].get("mft_record") == mft_record
        for o in observations
    )


def _has_corroboration(observations: list[dict[str, Any]], mft_record: int) -> bool:
    """Return True if the $UsnJrnl corroboration step has run for mft_record."""
    return any(
        o["tool"] == "inspect_usnjrnl" and o["args"].get("file_ref") == mft_record
        for o in observations
    )


class PolicyModelClient:
    """Deterministic senior-analyst policy: scan, investigate, self-correct.

    The policy is derived purely from the observations so far, so it is stateless
    and reproducible. It self-corrects on a single-source anomaly by pivoting to
    the $UsnJrnl and MFT-delta channels, then accepts the engine's bounded verdict
    rather than over-claiming.
    """

    def decide(self, state: AgentState) -> Turn:
        """Return the next analyst action given the accumulated observations."""
        observations = state.observations
        scan_obs = next((o for o in observations if o["tool"] == "scan_image"), None)

        if scan_obs is None:
            return Turn(
                tool_calls=[
                    ToolCall(
                        "scan_image",
                        {"image_path": state.image_path, "key_path": state.key_path},
                    )
                ],
                reasoning=(
                    "Open the case: scan the $LogFile for every candidate record "
                    "whose in-image timestamps disagree with the journal."
                ),
            )

        candidates = [
            c
            for c in scan_obs["result"].get("candidates", [])
            if c["verdict"] in ("provisional", "confirmed", "anomaly")
        ]

        for candidate in candidates:
            record = candidate["mft_record"]
            verdict = candidate["verdict"]

            if verdict in ("provisional", "confirmed"):
                if not _has_detect(observations, record):
                    return Turn(
                        tool_calls=[
                            ToolCall(
                                "detect_record",
                                {
                                    "image_path": state.image_path,
                                    "mft_record": record,
                                    "key_path": state.key_path,
                                },
                            )
                        ],
                        reasoning=(
                            f"Record {record} disagrees with the journal. "
                            "Reverse-replay the $LogFile to recover the signed "
                            "verdict and its evidence chain."
                        ),
                    )
            elif verdict == "anomaly":
                if not _has_corroboration(observations, record):
                    return Turn(
                        tool_calls=[
                            ToolCall(
                                "inspect_usnjrnl",
                                {
                                    "image_path": state.image_path,
                                    "file_ref": record,
                                    "usnjrnl_record": state.usnjrnl_record,
                                },
                            ),
                            ToolCall(
                                "inspect_mft",
                                {"image_path": state.image_path, "mft_record": record},
                            ),
                        ],
                        reasoning=(
                            f"Record {record} is a single-source anomaly: an "
                            "SI-vs-FN delta with no $LogFile coverage, the shape of "
                            "a raw-disk edit that bypassed the journal. This does "
                            "not add up as a confirmable finding yet. Corroborate "
                            "via the $UsnJrnl and the MFT delta before concluding, "
                            "and do not over-claim."
                        ),
                    )

        return Turn(
            final_text=(
                "Triage complete: all candidates investigated. Findings derive "
                "from signed engine verdicts; anomalies without $LogFile coverage "
                "are reported as requiring manual corroboration, never confirmed."
            ),
            reasoning=(
                "Every non-clean candidate has been investigated or corroborated."
            ),
        )
