"""Tests for the TruffleHog subprocess engine.

These tests mock `subprocess.run` so they do not require network access or even
a real TruffleHog binary on PATH. Live behavior is exercised in
tests/test_integration.py.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ghosttype import trufflehog_engine as te
from ghosttype.models import ConversationRecord, TextChunk


@pytest.fixture
def fake_record(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("...")
    return ConversationRecord(
        source_path=src,
        tool="claude_code",
        conversation_id="conv-abc",
        created_at=datetime.now(timezone.utc),
        raw={},
    )


@pytest.fixture
def chunks(fake_record):
    return [
        TextChunk(
            text="GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA00000001",
            position="line:1",
            record=fake_record,
        )
    ]


def _which_returns(path: str | None):
    """Patch shutil.which used by resolve_binary."""
    return patch("ghosttype.trufflehog_engine.shutil.which", return_value=path)


def _make_ndjson(events: list[dict]) -> str:
    return "\n".join(json.dumps(e) for e in events) + "\n"


def _make_event(file_path: str, **overrides) -> dict:
    base = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": file_path, "line": 1}}},
        "DetectorName": "Github",
        "DetectorType": 8,
        "Verified": False,
        "Raw": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA00000001",
        "RawV2": "",
        "ExtraData": {"version": "2"},
    }
    base.update(overrides)
    return base


def test_resolve_binary_uses_path(monkeypatch):
    with _which_returns("/usr/local/bin/trufflehog"):
        monkeypatch.delenv("GHOSTTYPE_TRUFFLEHOG_BIN", raising=False)
        assert te.resolve_binary() == "/usr/local/bin/trufflehog"


def test_resolve_binary_env_override(monkeypatch):
    monkeypatch.setenv("GHOSTTYPE_TRUFFLEHOG_BIN", "/opt/th/trufflehog")
    with _which_returns("/opt/th/trufflehog"):
        assert te.resolve_binary() == "/opt/th/trufflehog"


def test_resolve_binary_raises_when_missing(monkeypatch):
    monkeypatch.delenv("GHOSTTYPE_TRUFFLEHOG_BIN", raising=False)
    with _which_returns(None):
        with pytest.raises(te.TruffleHogNotFoundError):
            te.resolve_binary()


def test_scan_chunks_empty_returns_empty():
    assert te.scan_chunks("claude_code", []) == []


def test_scan_chunks_happy_path_maps_back_to_record(chunks, tmp_path):
    captured_argv: list[str] = []

    def fake_run(argv, **kwargs):
        captured_argv.extend(argv)
        # locate the staged file path in argv (last positional)
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(str(staged_file.resolve()))
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, verify=True, binary="/usr/local/bin/trufflehog"
            )

    assert "filesystem" in captured_argv
    assert "--json" in captured_argv
    assert "--results=verified,unverified,unknown" in captured_argv
    assert "--no-verification" not in captured_argv  # verify=True
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "claude_code"
    assert f.detector_name == "Github"
    assert f.secret_type == "github"
    assert f.verified is False
    assert f.confidence == "unverified"
    assert f.file_path == chunks[0].record.source_path
    assert f.severity in {"high", "medium", "critical"}


def test_scan_chunks_only_verified_flag(chunks):
    captured: list[str] = []

    def fake_run(argv, **kwargs):
        captured.extend(argv)
        return MagicMock(stdout="", stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            te.scan_chunks(
                "claude_code",
                chunks,
                verify=True,
                only_verified=True,
                binary="/usr/local/bin/trufflehog",
            )
    assert "--results=verified" in captured
    assert "--results=verified,unverified,unknown" not in captured


def test_scan_chunks_no_verification_flag(chunks):
    captured: list[str] = []

    def fake_run(argv, **kwargs):
        captured.extend(argv)
        return MagicMock(stdout="", stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            te.scan_chunks(
                "claude_code",
                chunks,
                verify=False,
                binary="/usr/local/bin/trufflehog",
            )
    assert "--no-verification" in captured


def test_scan_chunks_marks_verified_finding_as_critical_for_aws(fake_record):
    chunk = TextChunk(
        text="AKIA00000000000000000",
        position="line:1",
        record=fake_record,
    )

    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(
            str(staged_file.resolve()),
            DetectorName="AWS",
            DetectorType=2,
            Verified=True,
            Raw="AKIA00000000000000000",
        )
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", [chunk], binary="/usr/local/bin/trufflehog"
            )

    assert len(findings) == 1
    f = findings[0]
    assert f.verified is True
    assert f.confidence == "verified"
    assert f.severity == "critical"
    assert f.detector_name == "AWS"


def test_scan_chunks_skips_non_result_ndjson_lines(chunks):
    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(str(staged_file.resolve()))
        # mix in a non-result log line and a malformed line
        body = (
            json.dumps({"level": "info", "msg": "starting"}) + "\n"
            + "this is not json\n"
            + "\n"
            + json.dumps(event) + "\n"
        )
        return MagicMock(stdout=body, stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )
    assert len(findings) == 1


def test_scan_chunks_nonzero_exit_with_no_findings_raises(chunks):
    def fake_run(argv, **kwargs):
        return MagicMock(stdout="", stderr="boom\n", returncode=7)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            with pytest.raises(te.TruffleHogExecutionError) as exc_info:
                te.scan_chunks(
                    "claude_code", chunks, binary="/usr/local/bin/trufflehog"
                )
    assert "boom" in str(exc_info.value)


def test_scan_chunks_exit_183_with_findings_is_ok(chunks):
    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(str(staged_file.resolve()))
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=183)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )
    assert len(findings) == 1


def test_trufflehog_version_reads_stderr(monkeypatch):
    """`trufflehog --version` prints to stderr; the helper must surface that."""
    monkeypatch.delenv("GHOSTTYPE_TRUFFLEHOG_BIN", raising=False)

    def fake_run(argv, **kwargs):
        assert argv[1] == "--version"
        return MagicMock(stdout="", stderr="trufflehog 3.94.3\n", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            assert te.trufflehog_version() == "trufflehog 3.94.3"


def test_trufflehog_version_falls_back_to_stdout(monkeypatch):
    """If stderr is empty, the version line is taken from stdout instead."""
    monkeypatch.delenv("GHOSTTYPE_TRUFFLEHOG_BIN", raising=False)

    def fake_run(argv, **kwargs):
        return MagicMock(stdout="trufflehog 3.90.0\n", stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            assert te.trufflehog_version() == "trufflehog 3.90.0"


def test_scan_chunks_skips_chunks_with_empty_text(fake_record):
    """A scanner can yield blank chunks (e.g. a record whose only content was
    whitespace). Those must not be staged as files for TruffleHog and must not
    crash the run; a real secret in a sibling chunk is still found."""
    chunks = [
        TextChunk(text="", position="line:1", record=fake_record),
        TextChunk(text="   \n\t ", position="line:2", record=fake_record),
        TextChunk(
            text="GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA00000001",
            position="line:3",
            record=fake_record,
        ),
    ]
    staged_names: list[str] = []

    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        files = sorted(staged_dir.glob("*.txt"))
        staged_names.extend(p.name for p in files)
        event = _make_event(str(files[0].resolve()))
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )

    # Only the one non-empty chunk was written to disk.
    assert len(staged_names) == 1
    assert len(findings) == 1


def test_scan_chunks_returns_empty_when_all_chunks_blank(fake_record):
    """If every chunk is blank, nothing is staged and TruffleHog is never
    invoked — the engine returns [] without spawning a subprocess."""
    chunks = [
        TextChunk(text="", position="line:1", record=fake_record),
        TextChunk(text="  ", position="line:2", record=fake_record),
    ]
    with _which_returns("/usr/local/bin/trufflehog"):
        with patch(
            "ghosttype.trufflehog_engine.subprocess.run"
        ) as run_mock:
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )
    assert findings == []
    run_mock.assert_not_called()


def test_scan_chunks_timeout_raises_execution_error(chunks):
    """A subprocess timeout must surface as TruffleHogExecutionError with the
    timeout value in the message — never a bare subprocess.TimeoutExpired."""
    import subprocess as _sp

    def fake_run(argv, **kwargs):
        raise _sp.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 1))

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            with pytest.raises(te.TruffleHogExecutionError) as exc_info:
                te.scan_chunks(
                    "claude_code", chunks, timeout=42,
                    binary="/usr/local/bin/trufflehog",
                )
    assert "timed out after 42s" in str(exc_info.value)


def test_scan_chunks_position_includes_line_number(chunks):
    """When TruffleHog reports a line number, the Finding position pins it so a
    user can jump to the exact line in the source conversation chunk."""
    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(str(staged_file.resolve()))
        event["SourceMetadata"]["Data"]["Filesystem"]["line"] = 7
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )
    assert findings[0].position == "line:1:line7"


def test_scan_chunks_context_window_empty_when_secret_absent_from_chunk(fake_record):
    """If TruffleHog's reported Raw value isn't literally inside the chunk text
    (it can normalize/reconstruct secrets), the context falls back to the head
    of the chunk rather than crashing or returning a misleading window."""
    chunk = TextChunk(
        text="the credential was redacted before it reached this log line",
        position="line:1",
        record=fake_record,
    )

    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(
            str(staged_file.resolve()),
            Raw="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA00000001",
        )
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", [chunk], binary="/usr/local/bin/trufflehog"
            )
    assert len(findings) == 1
    # secret not in text -> context is the chunk head, not empty, not the secret
    assert findings[0].context == chunk.text
    assert "ghp_" not in findings[0].context


def test_scan_chunks_unmappable_result_is_dropped_not_crashed(chunks):
    """A TruffleHog result whose file path matches neither the exact staged
    path nor any staged basename is logged and skipped — the run still
    succeeds and returns the mappable findings only."""
    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        good = _make_event(str(staged_file.resolve()))
        orphan = _make_event("/totally/unrelated/path/nomatch.txt")
        return MagicMock(
            stdout=_make_ndjson([orphan, good]), stderr="", returncode=0
        )

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", chunks, binary="/usr/local/bin/trufflehog"
            )
    assert len(findings) == 1
    assert findings[0].file_path == chunks[0].record.source_path


def test_scan_chunks_verbose_logs_argv_and_stderr(chunks, caplog):
    """With verbose=True the engine surfaces the argv it ran and streams
    TruffleHog's own stderr log lines so an operator can watch progress."""
    import logging

    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        event = _make_event(str(staged_file.resolve()))
        return MagicMock(
            stdout=_make_ndjson([event]),
            stderr="trufflehog: scanned 1 file\n",
            returncode=0,
        )

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            with caplog.at_level(logging.INFO, logger="ghosttype.trufflehog_engine"):
                te.scan_chunks(
                    "claude_code", chunks, verbose=True,
                    binary="/usr/local/bin/trufflehog",
                )
    log_text = caplog.text
    assert "scanning 1 chunks from claude_code" in log_text
    assert "trufflehog argv:" in log_text
    assert "trufflehog: scanned 1 file" in log_text


def test_scan_chunks_basename_fallback_when_paths_diverge(fake_record):
    """If TruffleHog reports a /var/folders symlink-resolved path while we
    wrote to /private/var/folders, the basename fallback should still map back."""
    chunk = TextChunk(text="ghp_xxxx", position="line:1", record=fake_record)

    def fake_run(argv, **kwargs):
        staged_dir = Path(argv[-1])
        staged_file = next(staged_dir.glob("*.txt"))
        # Use the file's basename but a slightly different absolute path
        weird_path = "/some/other/prefix/" + staged_file.name
        event = _make_event(weird_path)
        return MagicMock(stdout=_make_ndjson([event]), stderr="", returncode=0)

    with _which_returns("/usr/local/bin/trufflehog"):
        with patch("ghosttype.trufflehog_engine.subprocess.run", side_effect=fake_run):
            findings = te.scan_chunks(
                "claude_code", [chunk], binary="/usr/local/bin/trufflehog"
            )
    assert len(findings) == 1
    assert findings[0].file_path == fake_record.source_path
