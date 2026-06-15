"""Read-only adapter functions wrapping the logflip engine for the MCP surface.

Each function takes plain inputs (paths, record numbers) and returns plain
JSON-serializable dicts. No function writes to, deletes, or executes against the
evidence: every logflip source is opened read-only and only parsing and
verification code runs. This module is the testable core that sift_mcp.server
exposes as MCP tools. Errors are returned as structured dicts rather than raised,
so the agent can reason about a failure instead of crashing on a traceback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from logflip.capture.ntfs import (
    extract_usnjrnl,
    extract_usnjrnl_from_extend,
    parse_boot_sector,
    read_mft_record,
)
from logflip.capture.sources import ImageFileSource
from logflip.cli import verify_leaf_ikm
from logflip.fingerprint.provider import (
    RealFingerprintDB,
    StubFingerprintDB,
    make_demo_key,
    verify_db_integrity,
)
from logflip.mft_parser import parse_mft_record, parse_si_fn_delta
from logflip.pipeline import DetectionError, run_detection, scan_detection
from logflip.usnjrnl import parse_usnjrnl


def _resolve_key(key_path: str | None) -> bytes | None:
    """Return the engagement key bytes, or None to use the demo key downstream.

    Args:
        key_path: Path to a raw 32-byte engagement key, or None.

    Returns:
        The key bytes when key_path is given, else None.
    """
    if key_path is None:
        return None
    return Path(key_path).read_bytes()


def _resolve_db(db_path: str | None, db_key: bytes) -> Any:
    """Return a fingerprint DB: a stub when db_path is None, else a signed DB.

    Args:
        db_path: Path to a signed RealFingerprintDB artifact, or None.
        db_key: Key used to build/verify the DB (engagement key or demo key).

    Returns:
        A StubFingerprintDB or a loaded RealFingerprintDB.
    """
    if db_path is None:
        return StubFingerprintDB(db_key)
    return RealFingerprintDB.load(Path(db_path).read_bytes(), db_key)


def scan_image(
    image_path: str,
    *,
    include_mft_deltas: bool = True,
    key_path: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Scan every candidate MFT record in an NTFS image for timestomping.

    The journal is not consumed at scan time: the engine's scan auto-discovers the
    $UsnJrnl via the $Extend index only and has no record-number override. Use
    detect_record or inspect_usnjrnl for an explicit $UsnJrnl cross-check.

    Args:
        image_path: Path to a raw NTFS image file (opened read-only).
        include_mft_deltas: Also surface journal-less SI-vs-FN anomalies.
        key_path: Optional engagement key path. Absent means the demo key,
            whose ceiling is a provisional verdict (never confirmed).
        db_path: Optional signed fingerprint DB path. Absent means the stub DB.

    Returns:
        Dict with image_path, candidates (one per record), and a summary of
        verdict counts. On a fatal stream error, returns an error field.
    """
    master_key = _resolve_key(key_path)
    db_key = master_key if master_key is not None else make_demo_key()
    src = ImageFileSource(image_path)
    try:
        db = _resolve_db(db_path, db_key)
        result = scan_detection(
            src, db, master_key=master_key, include_mft_deltas=include_mft_deltas
        )
    except (DetectionError, ValueError, OSError) as exc:
        return {
            "image_path": str(image_path),
            "error": f"{type(exc).__name__}: {exc}",
            "candidates": [],
            "summary": {},
        }

    counts = {"confirmed": 0, "provisional": 0, "anomaly": 0, "clean": 0, "skipped": 0}
    candidates: list[dict[str, Any]] = []
    for outcome in result.outcomes:
        if outcome.result is None:
            counts["skipped"] += 1
            candidates.append(
                {
                    "mft_record": outcome.mft_record,
                    "verdict": "skipped",
                    "error": outcome.error,
                    "tool_family": None,
                    "evil_confirmed": False,
                }
            )
            continue
        verdict = outcome.result.verdict
        counts[verdict] = counts.get(verdict, 0) + 1
        candidates.append(
            {
                "mft_record": outcome.mft_record,
                "verdict": verdict,
                "tool_family": outcome.result.leaf.get("tool_family"),
                "evil_confirmed": bool(outcome.result.leaf.get("evil_confirmed", False)),
            }
        )

    summary = {
        "candidates": len(result.outcomes),
        "findings": result.finding_count,
        "anomalies": result.anomaly_count,
        "skipped": result.skipped_count,
        **counts,
    }
    return {"image_path": str(image_path), "candidates": candidates, "summary": summary}


def detect_record(
    image_path: str,
    mft_record: int,
    *,
    usnjrnl_record: int | None = None,
    key_path: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Run the full detection pipeline on one MFT record.

    Args:
        image_path: Path to a raw NTFS image file (opened read-only).
        mft_record: Target MFT record number to investigate.
        usnjrnl_record: Optional $UsnJrnl $J record number for a direct
            cross-check; absent means auto-discovery via $Extend.
        key_path: Optional engagement key path (demo key when absent).
        db_path: Optional signed fingerprint DB path (stub when absent).

    Returns:
        Dict with the verdict, signed leaf, evidence record types, and the
        reconstructed and tampered timestamps. On error, verdict is "error".
    """
    master_key = _resolve_key(key_path)
    db_key = master_key if master_key is not None else make_demo_key()
    src = ImageFileSource(image_path)
    try:
        db = _resolve_db(db_path, db_key)
        result = run_detection(
            src,
            db,
            target_mft_record=mft_record,
            master_key=master_key,
            usnjrnl_record_num=usnjrnl_record,
        )
    except (DetectionError, ValueError, OSError) as exc:
        return {
            "image_path": str(image_path),
            "mft_record": mft_record,
            "verdict": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "evil_confirmed": False,
        }

    leaf = result.leaf
    evidence = leaf.get("evil_evidence", [])
    record_types = [str(e.get("record_type")) for e in evidence]
    inversion_complete: str | None = None
    walked_lsn_count: str | None = None
    for e in evidence:
        if str(e.get("record_type")) == "logfile_reverse_replay":
            inversion_complete = e.get("inversion_complete")
            walked_lsn_count = e.get("walked_lsn_count")

    return {
        "image_path": str(image_path),
        "mft_record": mft_record,
        "verdict": result.verdict,
        "evil_confirmed": bool(leaf.get("evil_confirmed", False)),
        "tool_family": leaf.get("tool_family"),
        "confidence": leaf.get("confidence"),
        "original_timestamp": leaf.get("original_timestamp"),
        "tampered_timestamp": leaf.get("tampered_timestamp"),
        "scope_bounded": leaf.get("scope_bounded"),
        "evidence_record_types": record_types,
        "inversion_complete": inversion_complete,
        "walked_lsn_count": walked_lsn_count,
        "leaf": leaf,
    }


def inspect_mft(image_path: str, mft_record: int) -> dict[str, Any]:
    """Parse one MFT record and report its SI-vs-FN timestamp delta.

    This is a corroboration channel: a nonzero SI-vs-FN delta is an independent
    failure-mode class the agent can use when the $LogFile path is inconclusive.

    Args:
        image_path: Path to a raw NTFS image file (opened read-only).
        mft_record: MFT record number to parse.

    Returns:
        Dict with si_fn_delta_nonzero and the SI/FN created timestamps, or an
        error field on a parse failure.
    """
    src = ImageFileSource(image_path)
    try:
        boot = parse_boot_sector(src)
        raw = read_mft_record(src, boot, mft_record)
        rec = parse_mft_record(raw, sector_size=boot.bytes_per_sector)
        delta = parse_si_fn_delta(rec)
    except Exception as exc:  # noqa: BLE001 - report any parse failure as structured error
        return {
            "image_path": str(image_path),
            "mft_record": mft_record,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "image_path": str(image_path),
        "mft_record": mft_record,
        "si_fn_delta_nonzero": bool(delta.si_fn_delta_nonzero),
        "si_created": getattr(delta, "si_created", None),
        "fn_created": getattr(delta, "fn_created", None),
    }


def inspect_usnjrnl(
    image_path: str, file_ref: int, *, usnjrnl_record: int | None = None
) -> dict[str, Any]:
    """Query the $UsnJrnl change journal for records about a file reference.

    This is the independent corroboration channel the agent pivots to when a
    record is a single-source anomaly. On a real image the $J stream is
    auto-discovered via the $Extend index; pass usnjrnl_record to read it from a
    known MFT record number when auto-discovery is unavailable.

    Args:
        image_path: Path to a raw NTFS image file (opened read-only).
        file_ref: MFT file reference number to filter on.
        usnjrnl_record: Optional MFT record number of the $UsnJrnl $J stream for
            a direct lookup; absent means auto-discovery via $Extend.

    Returns:
        Dict with present (whether any USN record was found) and the records,
        or present=False with an error field when the journal is unreadable.
    """
    src = ImageFileSource(image_path)
    try:
        boot = parse_boot_sector(src)
        if usnjrnl_record is not None:
            raw = extract_usnjrnl(src, boot, usnjrnl_record)
        else:
            raw = extract_usnjrnl_from_extend(src, boot)
        usn = parse_usnjrnl(raw, target_file_ref=file_ref)
    except Exception as exc:  # noqa: BLE001 - absent/corrupt journal is a normal outcome
        return {
            "image_path": str(image_path),
            "file_ref": file_ref,
            "present": False,
            "records": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
    records = [
        {"usn": r.usn, "timestamp": r.timestamp, "reason_flags": r.reason_flags}
        for r in usn.records
    ]
    return {
        "image_path": str(image_path),
        "file_ref": file_ref,
        "present": bool(records),
        "records": records,
    }


def verify_leaf(leaf_json_path: str, key_path: str) -> dict[str, Any]:
    """Re-verify a signed leaf's HMAC against the recovered engagement key.

    Args:
        leaf_json_path: Path to a signed leaf JSON file.
        key_path: Path to the raw 32-byte engagement key.

    Returns:
        Dict with pass (bool). The demo key is refused (pass=False with reason),
        matching logflip's signing-time refusal.
    """
    try:
        leaf = json.loads(Path(leaf_json_path).read_text(encoding="utf-8"))
        ikm = Path(key_path).read_bytes()
        return {"pass": bool(verify_leaf_ikm(leaf, ikm)), "refused": False}
    except ValueError as exc:
        # The engine raises ValueError specifically to refuse the demo key, which
        # is distinct from a signature mismatch (pass=False without a raise).
        return {
            "pass": False,
            "refused": "demo_key_prohibited" in str(exc),
            "error": str(exc),
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {"pass": False, "refused": False, "error": f"{type(exc).__name__}: {exc}"}


def verify_db(db_path: str, key_path: str) -> dict[str, Any]:
    """Verify a signed fingerprint DB's HMAC against the master key.

    Args:
        db_path: Path to a signed fingerprint DB JSON artifact.
        key_path: Path to the raw 32-byte master key.

    Returns:
        Dict with pass (bool), or pass=False with an error field on I/O failure.
    """
    try:
        raw = Path(db_path).read_bytes()
        key = Path(key_path).read_bytes()
        return {"pass": bool(verify_db_integrity(raw, key))}
    except OSError as exc:
        return {"pass": False, "error": f"{type(exc).__name__}: {exc}"}
