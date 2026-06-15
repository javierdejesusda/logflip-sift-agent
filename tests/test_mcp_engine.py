"""Tests for the read-only MCP engine adapter (sift_mcp.engine).

Strict TDD: written before sift_mcp/engine.py exists. Drives synthetic NTFS
images (logflip.lab) through the adapter and asserts the typed dict envelopes,
the never-false-confirm contract, and structured error handling (no tracebacks
escape to the agent).
"""

from __future__ import annotations

import json

from logflip.fingerprint.provider import make_demo_key
from logflip.lab.synthetic import (
    ANOMALY_SLOT,
    BENIGN,
    STOMP_A,
    STOMP_B,
    build_image_with_journal_less_delta_record,
    build_multi_stomped_image,
    build_pattern_matched_image,
    build_stomped_image,
)

from sift_mcp import engine

_PROD_KEY = b"\x11" * 32
_MATCH_PATTERN = b"TIMESTOMP_PATTERN"


def _img(tmp_path, data: bytes, name: str = "img.raw") -> str:
    """Write image bytes to a temp file and return its path string."""
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


class TestScanImage:
    """scan_image maps logflip scan outcomes to the typed candidate envelope."""

    def test_finds_two_provisional_one_clean_demo_key(self, tmp_path) -> None:
        path = _img(tmp_path, build_multi_stomped_image())
        out = engine.scan_image(path)
        by_record = {c["mft_record"]: c for c in out["candidates"]}
        assert by_record[STOMP_A]["verdict"] == "provisional"
        assert by_record[STOMP_B]["verdict"] == "provisional"
        assert by_record[BENIGN]["verdict"] == "clean"
        assert out["summary"]["findings"] == 2

    def test_demo_key_never_confirms(self, tmp_path) -> None:
        path = _img(tmp_path, build_multi_stomped_image())
        out = engine.scan_image(path)
        for c in out["candidates"]:
            assert c["evil_confirmed"] is False
            assert c["verdict"] != "confirmed"

    def test_include_mft_deltas_surfaces_anomaly(self, tmp_path) -> None:
        image, _ = build_image_with_journal_less_delta_record()
        path = _img(tmp_path, image)
        out = engine.scan_image(path, include_mft_deltas=True)
        by_record = {c["mft_record"]: c for c in out["candidates"]}
        assert ANOMALY_SLOT in by_record
        assert by_record[ANOMALY_SLOT]["verdict"] == "anomaly"
        assert out["summary"]["anomalies"] == 1


class TestDetectRecord:
    """detect_record returns the verdict, evidence types, and signed leaf."""

    def test_stomped_record_is_provisional_with_evidence(self, tmp_path) -> None:
        image, target, _ = build_stomped_image()
        path = _img(tmp_path, image)
        out = engine.detect_record(path, target)
        assert out["verdict"] == "provisional"
        assert out["evil_confirmed"] is False
        assert out["tampered_timestamp"] is not None
        assert "logfile_reverse_replay" in out["evidence_record_types"]
        assert "si_vs_fn_delta" in out["evidence_record_types"]
        assert out["scope_bounded"]
        assert "verdict" not in out["leaf"]

    def test_confirmed_with_prod_key_and_pattern(self, tmp_path) -> None:
        image, target, _ = build_pattern_matched_image(_MATCH_PATTERN)
        path = _img(tmp_path, image)
        keyp = tmp_path / "key.bin"
        keyp.write_bytes(_PROD_KEY)
        out = engine.detect_record(path, target, key_path=str(keyp))
        assert out["verdict"] == "confirmed"
        assert out["evil_confirmed"] is True
        assert out["tool_family"]

    def test_bad_record_returns_structured_error_not_raise(self, tmp_path) -> None:
        image, _, _ = build_stomped_image()
        path = _img(tmp_path, image)
        out = engine.detect_record(path, 9999)
        assert out["verdict"] == "error"
        assert "error" in out
        assert out["evil_confirmed"] is False


class TestInspectTools:
    """inspect_mft and inspect_usnjrnl expose the corroboration channels."""

    def test_inspect_mft_delta_nonzero_on_stomp(self, tmp_path) -> None:
        image, target, _ = build_stomped_image()
        path = _img(tmp_path, image)
        out = engine.inspect_mft(path, target)
        assert out["si_fn_delta_nonzero"] is True

    def test_inspect_usnjrnl_present_for_target(self, tmp_path) -> None:
        image, target, usn_record = build_stomped_image()
        path = _img(tmp_path, image)
        out = engine.inspect_usnjrnl(path, target, usnjrnl_record=usn_record)
        assert out["present"] is True
        assert len(out["records"]) >= 1
        assert "usn" in out["records"][0]


class TestVerifyTools:
    """verify_leaf and verify_db re-check signed artifacts offline."""

    def test_verify_leaf_roundtrip_with_prod_key(self, tmp_path) -> None:
        image, target, _ = build_pattern_matched_image(_MATCH_PATTERN)
        path = _img(tmp_path, image)
        keyp = tmp_path / "key.bin"
        keyp.write_bytes(_PROD_KEY)
        out = engine.detect_record(path, target, key_path=str(keyp))
        leafp = tmp_path / "leaf.json"
        leafp.write_text(json.dumps(out["leaf"]), encoding="utf-8")
        v = engine.verify_leaf(str(leafp), str(keyp))
        assert v["pass"] is True

    def test_verify_leaf_demo_key_refused(self, tmp_path) -> None:
        image, target, _ = build_stomped_image()
        path = _img(tmp_path, image)
        out = engine.detect_record(path, target)
        leafp = tmp_path / "leaf.json"
        leafp.write_text(json.dumps(out["leaf"]), encoding="utf-8")
        demo_keyp = tmp_path / "demo.bin"
        demo_keyp.write_bytes(make_demo_key())
        v = engine.verify_leaf(str(leafp), str(demo_keyp))
        assert v["pass"] is False
        # A demo-key refusal is distinguishable from a signature mismatch.
        assert v["refused"] is True
