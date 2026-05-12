from pathlib import Path
import pytest
from ghosttype.scanners.claude_code import ClaudeCodeScanner

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_conversation.jsonl"


def test_scanner_name():
    s = ClaudeCodeScanner()
    assert s.name == "claude_code"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = ClaudeCodeScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_finds_jsonl_files(tmp_path, monkeypatch):
    projects = tmp_path / "projects" / "-Users-test-project"
    projects.mkdir(parents=True)
    session = projects / "abc-123.jsonl"
    session.write_text('{"type":"user","message":{"content":"hello"},"uuid":"u1","sessionId":"s1","timestamp":"2026-01-01T00:00:00Z","cwd":"/tmp","version":"1","userType":"human","parentUuid":null,"isSidechain":false,"entrypoint":"cli","gitBranch":"main"}\n')
    monkeypatch.setattr(type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path))
    s = ClaudeCodeScanner()
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "claude_code"
    assert records[0].conversation_id == "abc-123"


def test_extract_text_from_string_content():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    texts = [c.text for c in chunks]
    assert any("AKIAIOSFODNN7EXAMPLE" in t for t in texts)


def test_extract_text_from_content_block_array():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    texts = [c.text for c in chunks]
    # msg-3 uses content block array form
    assert any("hunter2" in t for t in texts)


def test_extract_text_position_is_line_number():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    assert all(c.position.startswith("line:") for c in chunks)
