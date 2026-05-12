from pathlib import Path
from click.testing import CliRunner
from ghosttype.cli import cli


def test_list_tools_command_runs():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-tools"])
    assert result.exit_code == 0
    # Should mention all five tool names
    for name in ["cursor", "chatgpt", "codex", "claude", "claude_code"]:
        assert name in result.output


def test_scan_command_creates_output_dir(tmp_path, monkeypatch):
    from unittest.mock import MagicMock, patch
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 0
    assert (tmp_path / "report").exists()


def test_scan_writes_json_by_default(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from ghosttype.models import Finding
    from unittest.mock import patch
    runner = CliRunner()
    fake_finding = Finding(
        tool="claude_code", secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=tmp_path / "session.jsonl",
        position="line:1:0", confidence="high",
        context="key = AKIAIOSFODNN7EXAMPLE",
        discovered_at=datetime.now(timezone.utc),
    )
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [fake_finding]
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 0
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


def test_scan_tool_filter(tmp_path):
    from unittest.mock import patch, call
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        runner.invoke(cli, ["scan", "--tool", "cursor", "--output", str(tmp_path / "r")])
        MockOrch.return_value.run.assert_called_once_with(tool_filter="cursor")


def test_scan_format_json_only(tmp_path):
    from unittest.mock import patch
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        runner.invoke(cli, ["scan", "--format", "json", "--output", str(tmp_path / "r")])
    # csv should NOT exist, json should
    assert (tmp_path / "r" / "findings.json").exists()
    assert not (tmp_path / "r" / "findings.csv").exists()
