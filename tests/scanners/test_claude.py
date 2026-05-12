from pathlib import Path
from ghosttype.scanners.claude import ClaudeScanner


def test_claude_scanner_name():
    s = ClaudeScanner()
    assert s.name == "claude"
    assert isinstance(s.display_name, str)


def test_claude_scanner_discover_returns_empty_when_not_installed(tmp_path, monkeypatch):
    s = ClaudeScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False
    assert s.discover() == []


def test_claude_scanner_extract_text_returns_empty(tmp_path, monkeypatch):
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeScanner()
    rec = ConversationRecord(
        source_path=tmp_path / "placeholder",
        tool="claude",
        conversation_id="stub",
        created_at=datetime.now(timezone.utc),
        raw={},
    )
    assert s.extract_text(rec) == []
