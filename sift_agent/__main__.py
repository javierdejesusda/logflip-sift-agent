"""Command-line entry point for the sift triage agent.

Runs the autonomous triage loop over an NTFS image and writes a structured JSONL
session log plus a signed leaf per journaled finding. Three drivers share the
same loop and guards: the deterministic analyst policy (default, no API key), the
Claude driver (needs ANTHROPIC_API_KEY), and the OpenAI driver (needs
OPENAI_API_KEY).

Exit codes mirror logflip: 0 when no journaled finding, 2 when one or more
provisional/confirmed findings are present.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sift_agent.clients import ModelClient, PolicyModelClient
from sift_agent.orchestrator import triage_image
from sift_agent.session_log import SessionLog

_DEFAULT_MODELS = {"claude": "claude-sonnet-4-6", "openai": "gpt-4o"}


def _load_dotenv_if_available() -> None:
    """Load a .env file into the environment when python-dotenv is installed.

    python-dotenv is a runtime dependency, so it is normally present. The guarded
    import keeps the CLI working even in a vendored or minimal environment where it
    is missing, degrading to a no-op rather than failing at import time.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def _build_client(driver: str, model: str | None) -> tuple[ModelClient, str]:
    """Return (model_client, resolved_driver_name).

    An LLM driver falls back to the deterministic policy when its API key is not
    present, so the agent always runs for a judge. When model is None, the
    driver's default model id is used.
    """
    if driver == "claude":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "note: ANTHROPIC_API_KEY not set; falling back to the "
                "deterministic policy driver",
                file=sys.stderr,
            )
            return PolicyModelClient(), "policy"
        from sift_agent.llm_client import AnthropicModelClient

        return AnthropicModelClient(model=model or _DEFAULT_MODELS["claude"]), "claude"
    if driver == "openai":
        if not os.environ.get("OPENAI_API_KEY"):
            print(
                "note: OPENAI_API_KEY not set; falling back to the "
                "deterministic policy driver",
                file=sys.stderr,
            )
            return PolicyModelClient(), "policy"
        from sift_agent.llm_client_openai import OpenAIModelClient

        return OpenAIModelClient(model=model or _DEFAULT_MODELS["openai"]), "openai"
    return PolicyModelClient(), "policy"


def run(argv: list[str] | None = None) -> int:
    """Parse arguments, run a triage, write artifacts, and return an exit code."""
    _load_dotenv_if_available()
    parser = argparse.ArgumentParser(
        prog="sift-agent",
        description="Autonomous NTFS anti-forensics triage agent (read-only tools).",
    )
    parser.add_argument("--image", required=True, help="Path to the NTFS image file.")
    parser.add_argument(
        "--driver", choices=["policy", "claude", "openai"], default="policy",
        help=(
            "policy (deterministic, no key), claude (needs ANTHROPIC_API_KEY), "
            "or openai (needs OPENAI_API_KEY)."
        ),
    )
    parser.add_argument(
        "--model", default=None,
        help="Model id for an LLM driver (driver default when omitted).",
    )
    parser.add_argument("--key-file", dest="key_file", default=None, help="Engagement key path.")
    parser.add_argument(
        "--usnjrnl-record", dest="usnjrnl_record", type=int, default=None,
        help="$UsnJrnl $J MFT record number (for images without $Extend auto-discovery).",
    )
    parser.add_argument("--log", default=None, help="JSONL session log path (default logs/session.jsonl).")
    parser.add_argument(
        "--leaf-dir", dest="leaf_dir", default=None,
        help="Directory for signed leaf_<rec>.json files (default: alongside the log).",
    )
    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=24)
    args = parser.parse_args(argv)

    client, driver = _build_client(args.driver, args.model)
    log_path = Path(args.log) if args.log else Path("logs/session.jsonl")
    session = SessionLog(log_path)
    try:
        report = triage_image(
            args.image,
            model_client=client,
            key_path=args.key_file,
            usnjrnl_record=args.usnjrnl_record,
            max_iterations=args.max_iterations,
            session=session,
        )
    finally:
        session.close()

    leaf_dir = Path(args.leaf_dir) if args.leaf_dir else log_path.parent
    leaf_dir.mkdir(parents=True, exist_ok=True)
    for finding in report.findings:
        if finding.get("leaf"):
            (leaf_dir / f"leaf_{finding['mft_record']}.json").write_text(
                json.dumps(finding["leaf"], indent=2), encoding="utf-8"
            )

    print(
        f"driver: {driver}  image: {args.image}  "
        f"iterations: {report.iterations}  halted: {report.halted_reason}"
    )
    print(f"{'mft_record':<12}{'verdict':<14}tool_family")
    journaled = 0
    anomalies = 0
    for finding in sorted(report.findings, key=lambda f: f["mft_record"]):
        family = finding.get("tool_family") or "-"
        print(f"{finding['mft_record']:<12}{finding['verdict']:<14}{family}")
        if finding["verdict"] in ("provisional", "confirmed"):
            journaled += 1
        elif finding["verdict"] == "anomaly":
            anomalies += 1
    print(f"findings: {journaled}  anomalies: {anomalies}  session log: {log_path}")
    if report.final_text:
        print(f"summary: {report.final_text}")
    return 2 if journaled > 0 else 0


def main() -> None:
    """Console-script entry point."""
    sys.exit(run())


if __name__ == "__main__":
    main()
