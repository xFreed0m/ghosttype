from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ghosttype.models import ConversationRecord, TextChunk, Finding
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
    chunk = TextChunk(
        text="AWS_ACCESS_KEY_ID=AKIATESTFAKEKEY12345",
        position="line:1",
        record=rec,
    )
    scanner = MagicMock()
    scanner.name = "fake_tool"
    scanner.is_available.return_value = True
    scanner.discover.return_value = [rec]
    scanner.extract_text.return_value = [chunk]
    return scanner


def test_orchestrator_runs_available_scanners(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    assert len(findings) >= 1
    assert findings[0].tool == "fake_tool"
    assert findings[0].secret_type == "aws_access_key"
    assert findings[0].secret_value == "AKIATESTFAKEKEY12345"
    assert findings[0].confidence == "high"


def test_orchestrator_skips_unavailable_scanners(mock_scanner):
    mock_scanner.is_available.return_value = False
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    assert findings == []


def test_orchestrator_deduplicates_same_secret_same_file(mock_scanner, tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("x\n")
    rec = ConversationRecord(source_path=src, tool="fake_tool", conversation_id="c1",
                             created_at=datetime.now(timezone.utc), raw={})
    chunk1 = TextChunk(text="key=AKIATESTFAKEKEY12345", position="line:1", record=rec)
    chunk2 = TextChunk(text="key=AKIATESTFAKEKEY12345", position="line:2", record=rec)
    mock_scanner.extract_text.return_value = [chunk1, chunk2]
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    aws_findings = [f for f in findings if f.secret_value == "AKIATESTFAKEKEY12345"]
    assert len(aws_findings) == 1


def test_orchestrator_tool_filter(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run(tool_filter="other_tool")
    assert findings == []


def test_orchestrator_returns_findings_for_matching_tool_filter(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run(tool_filter="fake_tool")
    assert len(findings) >= 1
