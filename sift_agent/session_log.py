"""Structured JSONL session execution log.

Every agent step is appended as one JSON line: model reasoning, each tool
execution (with a digest of its raw output), the assembled findings, and a
closing meta line. The log gives a judge an end-to-end, timestamped trace where
any finding links back via produced_by_seq to the exact tool execution that
produced it, and via leaf_ref to the signed evidence leaf.

The clock is injectable so tests can assert a deterministic, monotonic sequence;
production runs use UTC wall-clock time.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _digest(obj: Any) -> str:
    """Return a stable sha256 digest of a JSON-serializable object."""
    payload = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class SessionLog:
    """Append-only JSONL writer for an agent triage session."""

    def __init__(
        self, path: str | Path | None = None, *, clock: Callable[[], str] = _utc_now_iso
    ) -> None:
        """Open a session log.

        Args:
            path: Destination JSONL path. When None, lines are kept in memory only.
            clock: Callable returning an ISO-8601 timestamp string. Injectable for
                deterministic tests.
        """
        self._clock = clock
        self._seq = 0
        self._lines: list[dict[str, Any]] = []
        self._tool_index: dict[tuple[str, Any], int] = {}
        self._fh: TextIO | None = None
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("w", encoding="utf-8")

    def _emit(self, line: dict[str, Any]) -> dict[str, Any]:
        """Stamp a line with seq and ts, store it, and write it to disk."""
        self._seq += 1
        stamped = {"seq": self._seq, "ts": self._clock(), **line}
        self._lines.append(stamped)
        if self._fh is not None:
            self._fh.write(json.dumps(stamped, default=str) + "\n")
            self._fh.flush()
        return stamped

    def record_step(
        self, iteration: int, reasoning: str | None, usage: dict[str, int] | None = None
    ) -> dict[str, Any]:
        """Record a model reasoning step."""
        return self._emit(
            {
                "event": "reasoning",
                "iteration": iteration,
                "reasoning": reasoning,
                "tokens": usage or {},
            }
        )

    def record_tool(
        self, iteration: int, tool: str, args: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        """Record one tool execution and index it for finding traceability."""
        verdict = result.get("verdict") if isinstance(result, dict) else None
        line = self._emit(
            {
                "event": "tool",
                "iteration": iteration,
                "tool": tool,
                "args": args,
                "result_digest": _digest(result),
                "verdict": verdict,
            }
        )
        record = args.get("mft_record", args.get("file_ref"))
        self._tool_index[(tool, record)] = line["seq"]
        if tool == "scan_image":
            self._tool_index[("scan_image", None)] = line["seq"]
        return line

    def record_findings(self, findings: list[dict[str, Any]]) -> None:
        """Record each finding, linking it to the tool execution that produced it."""
        for finding in findings:
            record = finding.get("mft_record")
            journaled = finding.get("verdict") in ("provisional", "confirmed")
            corroborated_by: list[int] | None = None
            if journaled:
                produced_by = self._tool_index.get(("detect_record", record))
            else:
                # An anomaly's verdict comes from the scan; its corroboration
                # evidence comes from the independent inspect tools. Link both so
                # the trace honestly distinguishes the two, rather than implying
                # the scan alone produced the corroborated finding.
                produced_by = self._tool_index.get(("scan_image", None))
                corroborated_by = [
                    seq
                    for seq in (
                        self._tool_index.get(("inspect_usnjrnl", record)),
                        self._tool_index.get(("inspect_mft", record)),
                    )
                    if seq is not None
                ] or None
            # A leaf_ref is recorded only when a signed leaf actually exists.
            # Anomalies are never confirmed and produce no leaf, so leaf_ref is null.
            self._emit(
                {
                    "event": "finding",
                    "mft_record": record,
                    "verdict": finding.get("verdict"),
                    "evil_confirmed": finding.get("evil_confirmed"),
                    "source": finding.get("source"),
                    "produced_by_seq": produced_by,
                    "corroborated_by_seq": corroborated_by,
                    "leaf_ref": f"leaf_{record}.json" if journaled else None,
                }
            )

    def record_meta(self, **fields: Any) -> dict[str, Any]:
        """Record a closing meta line (halted reason, counts, and so on)."""
        return self._emit({"event": "meta", **fields})

    @property
    def lines(self) -> list[dict[str, Any]]:
        """Return a copy of all emitted lines."""
        return list(self._lines)

    def close(self) -> None:
        """Close the underlying file handle, if any."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None
