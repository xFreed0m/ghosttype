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


def test_discover_includes_history_jsonl(tmp_path, monkeypatch):
    """history.jsonl in the base dir is discovered as a single record."""
    history = tmp_path / "history.jsonl"
    history.write_text('{"display": "some command", "pastedContents": {}}\n')
    monkeypatch.setattr(type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path))
    s = ClaudeCodeScanner()
    records = s.discover()
    ids = [r.conversation_id for r in records]
    assert "history" in ids


def test_extract_text_from_history(tmp_path):
    """History entries with display text are extracted; slash commands are skipped."""
    import json
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone

    history = tmp_path / "history.jsonl"
    lines = [
        json.dumps({"display": "/help", "pastedContents": {}}),
        json.dumps({"display": "run ANTHROPIC_API_KEY=sk-ant-abc123 myscript.py", "pastedContents": {}}),
        json.dumps({"display": "", "pastedContents": {}}),
    ]
    history.write_text("\n".join(lines) + "\n")

    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=history,
        tool="claude_code",
        conversation_id="history",
        created_at=datetime.now(timezone.utc),
        raw={"source_type": "history"},
    )
    chunks = s.extract_text(rec)
    texts = [c.text for c in chunks]
    # Slash command and empty entries must be skipped; real command must be present
    assert len(chunks) == 1
    assert "sk-ant-abc123" in texts[0]
    assert chunks[0].position == "entry:1"


def test_discover_includes_task_json_files(tmp_path, monkeypatch):
    """JSON files under tasks/ are discovered as individual records."""
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    task_file = tasks_dir / "task-abc.json"
    task_file.write_text('{"title": "debug something", "notes": "use key=secret123"}')
    monkeypatch.setattr(type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path))
    s = ClaudeCodeScanner()
    records = s.discover()
    task_records = [r for r in records if r.raw and r.raw.get("source_type") == "task"]
    assert len(task_records) == 1
    assert task_records[0].conversation_id == "task-abc"


def test_extract_text_from_task_json(tmp_path):
    """String values are recursively extracted from task JSON."""
    import json
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone

    task_file = tmp_path / "task-xyz.json"
    task_data = {
        "title": "investigate issue",
        "env": {"TOKEN": "ghp_RpQs7vXzBnCkDmWjEtFuGhYi12345678901234"},
        "steps": ["check config", "run test"],
    }
    task_file.write_text(json.dumps(task_data))

    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=task_file,
        tool="claude_code",
        conversation_id="task-xyz",
        created_at=datetime.now(timezone.utc),
        raw={"source_type": "task"},
    )
    chunks = s.extract_text(rec)
    assert len(chunks) == 1
    assert chunks[0].position == "task:0"
    assert "ghp_RpQs7vXzBnCkDmWjEtFuGhYi12345678901234" in chunks[0].text
