"""Behavior tests closing real coverage gaps in pattern_engine, scanner
resilience, and CLI output modes. Every test asserts an observable outcome
tied to a documented use case — no line-touching padding.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ghosttype import pattern_engine
from ghosttype.cli import cli
from ghosttype.models import (
    ConversationRecord,
    Finding,
    SOURCE_PATTERN,
    SOURCE_TRUFFLEHOG,
    TextChunk,
)
from ghosttype.scanner import Orchestrator


# ---------------------------------------------------------------------------
# pattern_engine
# ---------------------------------------------------------------------------

def _rec(tmp_path) -> ConversationRecord:
    p = tmp_path / "s.jsonl"
    p.write_text("x")
    return ConversationRecord(
        source_path=p,
        tool="claude_code",
        conversation_id="c1",
        created_at=datetime.now(timezone.utc),
        raw=None,
    )


def test_pattern_engine_skips_whitespace_only_chunks(tmp_path):
    """A whitespace-only chunk yields no findings and is not regex-scanned."""
    rec = _rec(tmp_path)
    chunks = [TextChunk(text="   \n\t  ", position="line:1", record=rec)]
    assert pattern_engine.scan_chunks("claude_code", chunks) == []


def test_pattern_engine_high_severity_for_critical_type(tmp_path):
    """A regex hit of a critical-class type (github_pat_classic) -> severity
    'high'. Pattern hits are inherently unverified, so they follow
    TruffleHog's *unverified* scheme: critical-class -> high (never
    'critical', which is reserved for verified critical-class detectors).
    This makes the two engines agree on the label for the same unverified
    credential type."""
    rec = _rec(tmp_path)
    chunk = TextChunk(
        text="token=ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        position="line:1",
        record=rec,
    )
    findings = pattern_engine.scan_chunks("claude_code", [chunk])
    assert any(
        f.secret_type == "github_pat_classic" and f.severity == "high"
        for f in findings
    )
    # And never 'critical' from the (always-unverified) pattern engine.
    assert all(
        f.severity != "critical"
        for f in findings
        if f.secret_type == "github_pat_classic"
    )


def test_pattern_engine_non_critical_type_is_medium(tmp_path):
    """connection_string is a regex hit NOT in the critical-class set. Under
    the unified unverified scheme it is 'medium' regardless of the regex's
    own confidence (the scheme no longer branches on confidence — that is
    exactly what makes it consistent with trufflehog_engine._severity_for)."""
    rec = _rec(tmp_path)
    chunk = TextChunk(
        text="db=postgresql://admin:S3cr3tPass@db.example.com:5432/prod",
        position="line:1",
        record=rec,
    )
    findings = pattern_engine.scan_chunks("claude_code", [chunk])
    conn = [f for f in findings if f.secret_type == "connection_string"]
    assert conn and conn[0].severity == "medium"
    assert conn[0].source == SOURCE_PATTERN
    assert conn[0].verified is False


def test_pattern_engine_dedups_same_secret_same_file(tmp_path):
    """The same secret on two lines of the same file is reported once."""
    rec = _rec(tmp_path)
    tok = "ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    chunks = [
        TextChunk(text=f"a={tok}", position="line:1", record=rec),
        TextChunk(text=f"b={tok}", position="line:2", record=rec),
    ]
    findings = pattern_engine.scan_chunks("claude_code", chunks)
    gh = [f for f in findings if f.secret_value == tok]
    assert len(gh) == 1


# ---------------------------------------------------------------------------
# Orchestrator resilience
# ---------------------------------------------------------------------------

def _scanner(name="fake", available=True):
    s = MagicMock()
    s.name = name
    s.is_available.return_value = available
    return s


def test_orchestrator_skips_scanner_whose_discover_raises(caplog):
    s = _scanner()
    s.discover.side_effect = RuntimeError("disk gone")
    with patch("ghosttype.scanner.trufflehog_scan_chunks", return_value=[]), patch(
        "ghosttype.pattern_engine.scan_chunks", return_value=[]
    ):
        with caplog.at_level(logging.WARNING):
            findings = Orchestrator(scanners=[s]).run()
    assert findings == []
    assert "failed during discover" in caplog.text


def test_orchestrator_continues_when_one_records_extract_raises(tmp_path, caplog):
    s = _scanner()
    good = _rec(tmp_path)
    bad = ConversationRecord(
        source_path=tmp_path / "bad.jsonl",
        tool="fake",
        conversation_id="bad",
        created_at=datetime.now(timezone.utc),
        raw=None,
    )
    (tmp_path / "bad.jsonl").write_text("x")
    s.discover.return_value = [bad, good]

    def extract(rec):
        if rec.conversation_id == "bad":
            raise ValueError("corrupt")
        return [TextChunk(text="hello world content", position="line:1", record=rec)]

    s.extract_text.side_effect = extract
    captured = {}

    def fake_engine(name, chunks, **kw):
        captured["chunks"] = list(chunks)
        return []

    with patch("ghosttype.scanner.trufflehog_scan_chunks", side_effect=fake_engine), patch(
        "ghosttype.pattern_engine.scan_chunks", return_value=[]
    ):
        with caplog.at_level(logging.WARNING):
            Orchestrator(scanners=[s]).run()
    assert "failed extracting" in caplog.text
    # the good record's chunk still reached the engine
    assert len(captured["chunks"]) == 1


def test_orchestrator_verbose_logs_when_no_chunks(tmp_path, caplog):
    s = _scanner()
    s.discover.return_value = [_rec(tmp_path)]
    s.extract_text.return_value = []  # discovered but nothing extractable
    with patch("ghosttype.scanner.trufflehog_scan_chunks") as eng, patch(
        "ghosttype.pattern_engine.scan_chunks"
    ):
        with caplog.at_level(logging.INFO):
            Orchestrator(scanners=[s], verbose=True).run()
    eng.assert_not_called()
    assert "extracted 0 text chunks" in caplog.text


def test_orchestrator_verbose_logs_engine_and_dedup_counts(tmp_path, caplog):
    s = _scanner()
    rec = _rec(tmp_path)
    s.discover.return_value = [rec]
    s.extract_text.return_value = [
        TextChunk(text="ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", position="l:1", record=rec)
    ]
    shared = Finding(
        tool="fake", secret_type="github", secret_value="dup",
        file_path=rec.source_path, position="l:1", confidence="unverified",
        context="dup", discovered_at=datetime.now(timezone.utc),
        source=SOURCE_TRUFFLEHOG,
    )
    pat_dup = Finding(
        tool="fake", secret_type="github_pat_classic", secret_value="dup",
        file_path=rec.source_path, position="l:1:0", confidence="high",
        context="dup", discovered_at=datetime.now(timezone.utc),
        source=SOURCE_PATTERN,
    )
    with patch("ghosttype.scanner.trufflehog_scan_chunks", return_value=[shared]), patch(
        "ghosttype.pattern_engine.scan_chunks", return_value=[pat_dup]
    ):
        with caplog.at_level(logging.INFO):
            findings = Orchestrator(scanners=[s], verbose=True, engine="both").run()
    # overlap on (value,file) -> TruffleHog kept, pattern shadowed
    assert len(findings) == 1
    assert findings[0].source == SOURCE_TRUFFLEHOG
    assert "shadowed" in caplog.text


# ---------------------------------------------------------------------------
# CLI output modes
# ---------------------------------------------------------------------------

def _finding(tmp_path, **kw) -> Finding:
    base = dict(
        tool="claude_code", secret_type="github", secret_value="ghp_v",
        file_path=tmp_path / "s.jsonl", position="line:1",
        confidence="unverified", context="ghp_v",
        discovered_at=datetime.now(timezone.utc), verified=False,
        detector_name="Github", source=SOURCE_TRUFFLEHOG,
    )
    base.update(kw)
    return Finding(**base)


def _patch_bin(mp):
    mp.setattr("ghosttype.cli.resolve_binary", lambda b=None: "/usr/local/bin/trufflehog")


def test_scan_stdout_mode_emits_valid_json_with_source(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    f = _finding(tmp_path)
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.return_value = [f]
        MO.return_value.files_scanned = 1
        res = CliRunner().invoke(cli, ["scan", "--output", "-", "--quiet"])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload[0]["source"] == "trufflehog"
    assert payload[0]["secret_value"] == "ghp_v"


def test_scan_stdout_mode_redacts(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.return_value = [_finding(tmp_path)]
        MO.return_value.files_scanned = 1
        res = CliRunner().invoke(cli, ["scan", "--output", "-", "--quiet", "--redact"])
    assert json.loads(res.output)[0]["secret_value"] == "***REDACTED***"


def test_scan_min_confidence_high_keeps_regex_and_verified(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    verified = _finding(tmp_path, verified=True, confidence="verified")
    regex_high = _finding(tmp_path, source=SOURCE_PATTERN, detector_name="",
                          secret_type="github_pat_classic", confidence="high")
    heur_med = _finding(tmp_path, source=SOURCE_PATTERN, detector_name="",
                        secret_type="heuristic_token", confidence="medium")
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.return_value = [verified, regex_high, heur_med]
        MO.return_value.files_scanned = 1
        res = CliRunner().invoke(
            cli, ["scan", "--output", "-", "--quiet", "--min-confidence", "high"]
        )
    kept = json.loads(res.output)
    confs = sorted(f["confidence"] for f in kept)
    assert confs == ["high", "verified"]  # medium heuristic dropped


def test_scan_trufflehog_error_during_run_exits_2(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    from ghosttype.trufflehog_engine import TruffleHogExecutionError
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.side_effect = TruffleHogExecutionError("boom mid-run")
        MO.return_value.files_scanned = 0
        res = CliRunner().invoke(cli, ["scan", "--output", str(tmp_path / "r")])
    assert res.exit_code == 2
    assert "boom mid-run" in res.output


def test_scan_copy_sources_copies_referenced_file(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    src = tmp_path / "s.jsonl"
    src.write_text('{"x":1}')
    f = _finding(tmp_path, file_path=src)
    out = tmp_path / "r"
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.return_value = [f]
        MO.return_value.files_scanned = 1
        CliRunner().invoke(
            cli, ["scan", "--output", str(out), "--copy-sources", "--quiet"]
        )
    copied = list((out / "sources" / "claude_code").iterdir())
    assert len(copied) == 1 and copied[0].suffix == ".jsonl"


def test_scan_verbose_initializes_logging(tmp_path, monkeypatch):
    _patch_bin(monkeypatch)
    with patch("ghosttype.cli.Orchestrator") as MO:
        MO.return_value.run.return_value = []
        MO.return_value.files_scanned = 0
        res = CliRunner().invoke(
            cli, ["scan", "--output", str(tmp_path / "r"), "--verbose"]
        )
    assert res.exit_code == 0
