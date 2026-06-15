"""Smoke test for the CLI entry point (sift_agent.__main__.run).

Strict TDD. Drives a full triage run through the deterministic policy driver and
asserts the runnable contract: a findings exit code, a JSONL session log on disk,
and signed leaf files for the journaled findings.
"""

from __future__ import annotations

import json
import os

from logflip.lab.synthetic import build_multi_stomped_image

from sift_agent.__main__ import run


def test_policy_run_writes_log_and_reports_findings(tmp_path) -> None:
    img = tmp_path / "img.raw"
    img.write_bytes(build_multi_stomped_image())
    log_path = tmp_path / "session.jsonl"
    leaf_dir = tmp_path / "leaves"

    rc = run(
        [
            "--image",
            str(img),
            "--driver",
            "policy",
            "--log",
            str(log_path),
            "--leaf-dir",
            str(leaf_dir),
        ]
    )

    assert rc == 2  # provisional findings present
    assert log_path.exists()

    lines = [json.loads(x) for x in log_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(line["event"] == "finding" for line in lines)
    assert any(line["event"] == "tool" and line["tool"] == "scan_image" for line in lines)

    leaves = list(leaf_dir.glob("leaf_*.json"))
    assert len(leaves) >= 2
    # Each written leaf is valid JSON with the closed schema (no verdict key).
    for leaf_file in leaves:
        leaf = json.loads(leaf_file.read_text(encoding="utf-8"))
        assert "evil_confirmed" in leaf
        assert "verdict" not in leaf


def test_run_loads_key_from_dotenv(tmp_path, monkeypatch) -> None:
    """run() calls load_dotenv() at startup so a .env-defined key is available.

    The probe variable is unset first, and load_dotenv() is pinned to an
    isolated .env file (real python-dotenv parsing), so the assertion only
    passes if run() loaded that file into the environment before resolving the
    driver. Pinning the path keeps the test independent of the repository's own
    .env and the current working directory.
    """
    import dotenv

    monkeypatch.delenv("SIFT_DOTENV_PROBE", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("SIFT_DOTENV_PROBE=loaded-from-dotenv\n", encoding="utf-8")
    real_load_dotenv = dotenv.load_dotenv
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: real_load_dotenv(env_file))

    img = tmp_path / "img.raw"
    img.write_bytes(build_multi_stomped_image())

    rc = run(
        [
            "--image",
            str(img),
            "--driver",
            "policy",
            "--log",
            str(tmp_path / "session.jsonl"),
            "--leaf-dir",
            str(tmp_path / "leaves"),
        ]
    )

    assert rc == 2
    assert os.environ.get("SIFT_DOTENV_PROBE") == "loaded-from-dotenv"


def test_load_dotenv_helper_is_noop_without_python_dotenv(monkeypatch) -> None:
    """The .env convenience degrades to a no-op when python-dotenv is absent.

    python-dotenv is a runtime dependency, so it is normally present. The guarded
    import still degrades to a no-op if it is somehow missing (a vendored or
    minimal environment), so the CLI never hard-crashes on the optional .env
    convenience.
    """
    import sys

    from sift_agent import __main__ as cli

    monkeypatch.setitem(sys.modules, "dotenv", None)
    assert cli._load_dotenv_if_available() is None


def test_python_dotenv_is_a_runtime_dependency() -> None:
    """python-dotenv is a runtime dependency so .env auto-loads on clean installs.

    The CLI auto-loads a .env at startup for the convenience of judges running the
    LLM driver. Declaring python-dotenv only under the dev extras meant a plain
    `pip install .` (the Docker and judge path) did not pull it, so .env loading
    silently no-opped there. Pinning it as a runtime dependency makes the
    convenience work on every documented install path.
    """
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    runtime = config["project"]["dependencies"]
    dev = config["project"].get("optional-dependencies", {}).get("dev", [])

    assert any(req.startswith("python-dotenv") for req in runtime), (
        "python-dotenv must be a runtime dependency so .env loads on clean installs"
    )
    assert not any(req.startswith("python-dotenv") for req in dev), (
        "python-dotenv should not remain duplicated in the dev extras"
    )


def test_build_client_selects_openai_driver(monkeypatch) -> None:
    """--driver openai with a key present builds the OpenAI client."""
    import openai

    from sift_agent.__main__ import _build_client
    from sift_agent.llm_client_openai import OpenAIModelClient

    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key")
    monkeypatch.setattr(openai, "OpenAI", lambda *a, **k: object())
    client, driver = _build_client("openai", None)

    assert driver == "openai"
    assert isinstance(client, OpenAIModelClient)


def test_build_client_openai_falls_back_without_key(monkeypatch) -> None:
    """--driver openai with no key falls back to the deterministic policy."""
    from sift_agent.__main__ import _build_client
    from sift_agent.clients import PolicyModelClient

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client, driver = _build_client("openai", None)

    assert driver == "policy"
    assert isinstance(client, PolicyModelClient)
