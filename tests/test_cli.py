"""CLI tests: the engine and orchestrator are mocked so we don't shell out."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from ghosttype.cli import cli, VERSION
from ghosttype.models import Finding


def _make_finding(tmp_path: Path, *, verified: bool = False) -> Finding:
    return Finding(
        tool="claude_code",
        secret_type="github",
        secret_value="ghp_xxx",
        file_path=tmp_path / "session.jsonl",
        position="line:1",
        confidence="verified" if verified else "unverified",
        context="ghp_xxx",
        discovered_at=datetime.now(timezone.utc),
        severity="critical" if verified else "high",
        verified=verified,
        detector_name="Github",
        extra_data={"version": "2"},
    )


def _patch_binary(monkeypatch):
    """Make resolve_binary succeed without a real trufflehog on PATH."""
    monkeypatch.setattr(
        "ghosttype.cli.resolve_binary", lambda b=None: "/usr/local/bin/trufflehog"
    )


def test_list_tools_command_runs():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-tools"])
    assert result.exit_code == 0
    for name in ["cursor", "chatgpt", "codex", "claude", "claude_code"]:
        assert name in result.output


def test_version_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "ghosttype" in result.output
    assert VERSION in result.output


def test_doctor_reports_trufflehog(monkeypatch):
    monkeypatch.setattr(
        "ghosttype.cli.resolve_binary", lambda b=None: "/usr/local/bin/trufflehog"
    )
    monkeypatch.setattr(
        "ghosttype.cli.trufflehog_version", lambda b=None: "trufflehog 3.94.3"
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "trufflehog 3.94.3" in result.output


def test_doctor_fails_when_binary_missing(monkeypatch):
    from ghosttype.trufflehog_engine import TruffleHogNotFoundError

    def fake_resolve(b=None):
        raise TruffleHogNotFoundError("nope")

    monkeypatch.setattr("ghosttype.cli.resolve_binary", fake_resolve)
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 2
    assert "TruffleHog not found" in result.output


def test_scan_creates_output_dir(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 0
    assert (tmp_path / "report").exists()


def test_scan_writes_json_and_csv(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    finding = _make_finding(tmp_path)
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [finding]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "r")])
    assert result.exit_code == 1
    assert (tmp_path / "r" / "findings.json").exists()
    assert (tmp_path / "r" / "findings.csv").exists()


def test_scan_tool_filter(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        runner.invoke(cli, ["scan", "--tool", "cursor", "--output", str(tmp_path / "r")])
        MockOrch.return_value.run.assert_called_once_with(tool_filter="cursor")


def test_scan_format_json_only(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [_make_finding(tmp_path)]
        MockOrch.return_value.files_scanned = 1
        runner.invoke(cli, ["scan", "--format", "json", "--output", str(tmp_path / "r")])
    assert (tmp_path / "r" / "findings.json").exists()
    assert not (tmp_path / "r" / "findings.csv").exists()


def test_scan_min_confidence_verified_filters_unverified(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    unverified = _make_finding(tmp_path, verified=False)
    verified = _make_finding(tmp_path, verified=True)
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [unverified, verified]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(
            cli,
            ["scan", "--min-confidence", "verified", "--output", str(tmp_path / "r")],
        )
    assert result.exit_code == 1
    import json as _json
    data = _json.loads((tmp_path / "r" / "findings.json").read_text())
    assert len(data) == 1
    assert data[0]["verified"] is True


def test_scan_only_verified_passes_through(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        runner.invoke(
            cli, ["scan", "--only-verified", "--output", str(tmp_path / "r")]
        )
        # Orchestrator was constructed with only_verified=True
        _, kwargs = MockOrch.call_args
        assert kwargs["only_verified"] is True
        assert kwargs["verify"] is True


def test_scan_no_verification_passes_through(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        runner.invoke(
            cli, ["scan", "--no-verification", "--output", str(tmp_path / "r")]
        )
        _, kwargs = MockOrch.call_args
        assert kwargs["verify"] is False


def test_scan_missing_trufflehog_engine_trufflehog_exits_2(tmp_path, monkeypatch):
    """With --engine trufflehog, a missing binary is a hard failure (exit 2)."""
    from ghosttype.trufflehog_engine import TruffleHogNotFoundError

    def boom(b=None):
        raise TruffleHogNotFoundError("nope, no binary")

    monkeypatch.setattr("ghosttype.cli.resolve_binary", boom)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "--engine", "trufflehog", "--output", str(tmp_path / "r")]
    )
    assert result.exit_code == 2
    assert "nope, no binary" in result.output


def test_scan_missing_trufflehog_engine_both_falls_back_to_patterns(tmp_path, monkeypatch):
    """With the default --engine both, a missing binary degrades to
    patterns-only with a visible warning (not a silent failure, not exit 2)."""
    from ghosttype.trufflehog_engine import TruffleHogNotFoundError

    def boom(b=None):
        raise TruffleHogNotFoundError("no binary here")

    monkeypatch.setattr("ghosttype.cli.resolve_binary", boom)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "r")])
    assert result.exit_code == 0
    assert "falling back to patterns-only" in result.output
    # Orchestrator must have been constructed with engine="patterns"
    _, kwargs = MockOrch.call_args
    assert kwargs["engine"] == "patterns"


def test_scan_engine_patterns_skips_binary_resolution(tmp_path, monkeypatch):
    """--engine patterns must not even attempt to resolve the binary."""
    called = {"resolve": False}

    def tracker(b=None):
        called["resolve"] = True
        return "/usr/local/bin/trufflehog"

    monkeypatch.setattr("ghosttype.cli.resolve_binary", tracker)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        runner.invoke(
            cli, ["scan", "--engine", "patterns", "--output", str(tmp_path / "r")]
        )
    assert called["resolve"] is False
    _, kwargs = MockOrch.call_args
    assert kwargs["engine"] == "patterns"


def test_scan_with_allow_list(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    allow_list = tmp_path / "allowlist.txt"
    allow_list.write_text("ghp_xxx\n# comment\n")
    finding = _make_finding(tmp_path)
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [finding]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(
            cli,
            [
                "scan",
                "--output",
                str(tmp_path / "r"),
                "--allow-list",
                str(allow_list),
            ],
        )
    assert "Allow-list suppressed" in result.output


def test_scan_stats_only(tmp_path, monkeypatch):
    _patch_binary(monkeypatch)
    runner = CliRunner()
    finding = _make_finding(tmp_path)
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [finding]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(
            cli, ["scan", "--output", str(tmp_path / "r"), "--stats-only"]
        )
    assert result.exit_code == 1
    assert "By Detector" in result.output or "By Tool" in result.output


def test_scan_stdout_empty_findings_is_valid_json_array():
    import json as _json

    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        result = runner.invoke(
            cli,
            ["scan", "--engine", "patterns", "--no-verification",
             "--output", "-", "--quiet"],
        )
    assert result.exit_code == 0
    assert _json.loads(result.output.strip()) == []


def test_scan_stdout_redacts_secret_everywhere(tmp_path):
    import json as _json

    runner = CliRunner()
    f = _make_finding(tmp_path)
    f.context = "key = ghp_xxx appears here"
    f.extra_data = {"raw": "ghp_xxx", "harmless": "keep"}
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [f]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(
            cli,
            ["scan", "--engine", "patterns", "--no-verification",
             "--redact", "--output", "-", "--quiet"],
        )
    assert result.exit_code == 1
    payload = _json.loads(result.output.strip())
    assert "ghp_xxx" not in _json.dumps(payload)
    assert payload[0]["secret_value"] == "***REDACTED***"
    assert "***REDACTED***" in payload[0]["context"]
    assert payload[0]["extra_data"]["harmless"] == "keep"


def test_scan_only_verified_plus_no_verification_is_rejected(tmp_path, monkeypatch):
    """The combination silently filtered out every finding and exited 0 — a
    false 'all clear'. It must now be refused up front (issue #3)."""
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        result = runner.invoke(
            cli,
            ["scan", "--only-verified", "--no-verification",
             "--output", str(tmp_path / "r")],
        )
    # click.UsageError -> exit code 2, and the scan never reached the engine.
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    MockOrch.return_value.run.assert_not_called()


def test_scan_only_verified_alone_still_works(tmp_path, monkeypatch):
    """Guard must not over-trigger: each flag on its own is still valid."""
    _patch_binary(monkeypatch)
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        result = runner.invoke(
            cli, ["scan", "--only-verified", "--output", str(tmp_path / "r")]
        )
    assert result.exit_code == 0
    MockOrch.return_value.run.assert_called_once()


def test_engine_build_argv_rejects_no_verify_with_only_verified():
    """Defense-in-depth for programmatic callers that bypass the CLI guard."""
    import pytest

    from ghosttype.trufflehog_engine import _build_argv

    with pytest.raises(ValueError, match="incompatible"):
        _build_argv(
            "trufflehog",
            Path("/tmp"),
            verify=False,
            only_verified=True,
            concurrency=10,
            detector_timeout="10s",
        )
