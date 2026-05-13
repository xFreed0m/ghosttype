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
        MockOrch.return_value.files_scanned = 0
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
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 1  # non-zero when findings are present (CI/CD behavior)
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


def test_scan_tool_filter(tmp_path):
    from unittest.mock import patch, call
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        MockOrch.return_value.files_scanned = 0
        runner.invoke(cli, ["scan", "--tool", "cursor", "--output", str(tmp_path / "r")])
        MockOrch.return_value.run.assert_called_once_with(tool_filter="cursor")


def test_scan_format_json_only(tmp_path):
    from datetime import datetime, timezone
    from ghosttype.models import Finding
    from unittest.mock import patch
    runner = CliRunner()
    fake_finding = Finding(
        tool="cursor", secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=tmp_path / "session.db",
        position="line:1:0", confidence="high",
        context="key = AKIAIOSFODNN7EXAMPLE",
        discovered_at=datetime.now(timezone.utc),
    )
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [fake_finding]
        MockOrch.return_value.files_scanned = 1
        runner.invoke(cli, ["scan", "--format", "json", "--output", str(tmp_path / "r")])
    # csv should NOT exist, json should
    assert (tmp_path / "r" / "findings.json").exists()
    assert not (tmp_path / "r" / "findings.csv").exists()


def test_version_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "ghosttype" in result.output
    assert "v0.2.0" in result.output
    assert "credential scanner" in result.output


def test_scan_with_allow_list(tmp_path):
    from datetime import datetime, timezone
    from ghosttype.models import Finding
    from unittest.mock import patch
    runner = CliRunner()

    # Create allow-list file with one value
    allow_list_file = tmp_path / "allowlist.txt"
    allow_list_file.write_text("AKIAIOSFODNN7EXAMPLE\n# comment line\nANOTHER_SECRET_VALUE\n")

    # Create two findings
    finding1 = Finding(
        tool="cursor", secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=tmp_path / "session.db",
        position="line:1:0", confidence="high",
        context="key = AKIAIOSFODNN7EXAMPLE",
        discovered_at=datetime.now(timezone.utc),
    )
    finding2 = Finding(
        tool="claude_code", secret_type="api_key",
        secret_value="sk-1234567890",
        file_path=tmp_path / "session.jsonl",
        position="line:2:0", confidence="high",
        context="key = sk-1234567890",
        discovered_at=datetime.now(timezone.utc),
    )

    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [finding1, finding2]
        MockOrch.return_value.files_scanned = 2
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report"), "--allow-list", str(allow_list_file)])

    assert result.exit_code == 1  # non-zero when findings remain after suppression
    assert "Allow-list suppressed" in result.output


def test_scan_with_stats_only(tmp_path):
    from datetime import datetime, timezone
    from ghosttype.models import Finding
    from unittest.mock import patch
    runner = CliRunner()

    finding = Finding(
        tool="cursor", secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=tmp_path / "session.db",
        position="line:1:0", confidence="high",
        context="key = AKIAIOSFODNN7EXAMPLE",
        discovered_at=datetime.now(timezone.utc),
    )

    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [finding]
        MockOrch.return_value.files_scanned = 1
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report"), "--stats-only"])

    assert result.exit_code == 1  # non-zero when findings are present (CI/CD behavior)
    # With --stats-only, we should see the stats breakdown (By Type, By Tool)
    assert "By Type" in result.output or "By Tool" in result.output
    # Should still have findings summary
    assert "1 finding(s) discovered" in result.output
