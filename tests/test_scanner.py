"""Orchestrator tests: mock the engine boundaries so we don't shell out to
trufflehog or run the real regex engine in unit tests."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghosttype.models import (
    ConversationRecord,
    Finding,
    SOURCE_PATTERN,
    SOURCE_TRUFFLEHOG,
    TextChunk,
)
from ghosttype.scanner import Orchestrator


@pytest.fixture
def mock_scanner(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("x\n")
    rec = ConversationRecord(
        source_path=src,
        tool="fake_tool",
        conversation_id="conv-1",
        created_at=datetime.now(timezone.utc),
        raw={},
    )
    chunk = TextChunk(text="GITHUB_TOKEN=ghp_xxx", position="line:1", record=rec)
    scanner = MagicMock()
    scanner.name = "fake_tool"
    scanner.is_available.return_value = True
    scanner.discover.return_value = [rec]
    scanner.extract_text.return_value = [chunk]
    return scanner, rec


def _th_finding(tool, value, source_path, verified=False) -> Finding:
    return Finding(
        tool=tool,
        secret_type="github",
        secret_value=value,
        file_path=source_path,
        position="line:1",
        confidence="verified" if verified else "unverified",
        context=value,
        discovered_at=datetime.now(timezone.utc),
        severity="critical" if verified else "high",
        verified=verified,
        detector_name="Github",
        source=SOURCE_TRUFFLEHOG,
    )


def _pat_finding(tool, value, source_path, secret_type="github_pat_classic") -> Finding:
    return Finding(
        tool=tool,
        secret_type=secret_type,
        secret_value=value,
        file_path=source_path,
        position="line:1:0",
        confidence="high",
        context=value,
        discovered_at=datetime.now(timezone.utc),
        severity="critical",
        verified=False,
        detector_name="",
        source=SOURCE_PATTERN,
    )


def test_orchestrator_runs_available_scanners(mock_scanner):
    scanner, rec = mock_scanner
    expected = _th_finding("fake_tool", "ghp_xxx", rec.source_path, verified=True)
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[expected]
    ) as eng, patch("ghosttype.pattern_engine.scan_chunks", return_value=[]):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    eng.assert_called_once()
    assert len(findings) == 1
    assert findings[0].verified is True
    assert findings[0].source == SOURCE_TRUFFLEHOG


def test_orchestrator_skips_unavailable_scanners(mock_scanner):
    scanner, _ = mock_scanner
    scanner.is_available.return_value = False
    with patch("ghosttype.scanner.trufflehog_scan_chunks") as eng, patch(
        "ghosttype.pattern_engine.scan_chunks"
    ) as peng:
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    eng.assert_not_called()
    peng.assert_not_called()
    assert findings == []


def test_orchestrator_dedup_same_secret_same_file(mock_scanner):
    scanner, rec = mock_scanner
    f1 = _th_finding("fake_tool", "ghp_xxx", rec.source_path)
    f2 = _th_finding("fake_tool", "ghp_xxx", rec.source_path)
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[f1, f2]
    ), patch("ghosttype.pattern_engine.scan_chunks", return_value=[]):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    assert len(findings) == 1


def test_orchestrator_tool_filter_excludes(mock_scanner):
    scanner, _ = mock_scanner
    with patch("ghosttype.scanner.trufflehog_scan_chunks") as eng, patch(
        "ghosttype.pattern_engine.scan_chunks"
    ):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run(tool_filter="other_tool")
    eng.assert_not_called()
    assert findings == []


def test_orchestrator_tool_filter_matches(mock_scanner):
    scanner, rec = mock_scanner
    expected = _th_finding("fake_tool", "ghp_xxx", rec.source_path)
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[expected]
    ), patch("ghosttype.pattern_engine.scan_chunks", return_value=[]):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run(tool_filter="fake_tool")
    assert len(findings) == 1


def test_orchestrator_passes_verify_flag(mock_scanner):
    scanner, _ = mock_scanner
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[]
    ) as eng, patch("ghosttype.pattern_engine.scan_chunks", return_value=[]):
        orch = Orchestrator(scanners=[scanner], verify=False, only_verified=True)
        orch.run()
    _, kwargs = eng.call_args
    assert kwargs["verify"] is False
    assert kwargs["only_verified"] is True


def test_orchestrator_max_age_filter(mock_scanner, tmp_path):
    scanner, _ = mock_scanner
    old_rec = ConversationRecord(
        source_path=tmp_path / "old.jsonl",
        tool="fake_tool",
        conversation_id="old",
        created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        raw={},
    )
    (tmp_path / "old.jsonl").write_text("x")
    scanner.discover.return_value = [old_rec]
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[]
    ) as eng, patch("ghosttype.pattern_engine.scan_chunks", return_value=[]):
        orch = Orchestrator(scanners=[scanner], max_age_days=7)
        orch.run()
    eng.assert_not_called()


# ----------------------------------------------------------------------
# Dual-engine complementary behavior
# ----------------------------------------------------------------------

def test_engine_both_runs_both_and_merges(mock_scanner):
    scanner, rec = mock_scanner
    th = _th_finding("fake_tool", "ghp_truffleonly", rec.source_path)
    pat = _pat_finding("fake_tool", "AKIApatternonly00000", rec.source_path,
                       secret_type="aws_access_key")
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[th]
    ), patch("ghosttype.pattern_engine.scan_chunks", return_value=[pat]):
        orch = Orchestrator(scanners=[scanner], engine="both")
        findings = orch.run()
    values = {f.secret_value for f in findings}
    assert values == {"ghp_truffleonly", "AKIApatternonly00000"}
    sources = {f.source for f in findings}
    assert sources == {SOURCE_TRUFFLEHOG, SOURCE_PATTERN}


def test_engine_both_trufflehog_wins_overlap(mock_scanner):
    """Same secret value + file found by both engines -> keep TruffleHog's."""
    scanner, rec = mock_scanner
    shared = "ghp_sharedSecretValue000000000000000001"
    th = _th_finding("fake_tool", shared, rec.source_path, verified=True)
    pat = _pat_finding("fake_tool", shared, rec.source_path)
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[th]
    ), patch("ghosttype.pattern_engine.scan_chunks", return_value=[pat]):
        orch = Orchestrator(scanners=[scanner], engine="both")
        findings = orch.run()
    assert len(findings) == 1
    assert findings[0].source == SOURCE_TRUFFLEHOG
    assert findings[0].verified is True


def test_engine_trufflehog_only_skips_pattern_engine(mock_scanner):
    scanner, rec = mock_scanner
    th = _th_finding("fake_tool", "ghp_xxx", rec.source_path)
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks", return_value=[th]
    ), patch("ghosttype.pattern_engine.scan_chunks") as peng:
        orch = Orchestrator(scanners=[scanner], engine="trufflehog")
        findings = orch.run()
    peng.assert_not_called()
    assert len(findings) == 1


def test_engine_patterns_only_skips_trufflehog(mock_scanner):
    scanner, rec = mock_scanner
    pat = _pat_finding("fake_tool", "AKIApatternonly00000", rec.source_path,
                       secret_type="aws_access_key")
    with patch(
        "ghosttype.scanner.trufflehog_scan_chunks"
    ) as eng, patch("ghosttype.pattern_engine.scan_chunks", return_value=[pat]):
        orch = Orchestrator(scanners=[scanner], engine="patterns")
        findings = orch.run()
    eng.assert_not_called()
    assert len(findings) == 1
    assert findings[0].source == SOURCE_PATTERN


def test_invalid_engine_raises():
    with pytest.raises(ValueError):
        Orchestrator(scanners=[], engine="bogus")
