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


# ----------------------------------------------------------------------
# Drop-surface tests added after the v0.3.0 audit found that thinking /
# tool_use / attachment / system / file-history-snapshot records were
# silently being dropped by the extractor. These tests pin each case
# so the regression cannot recur.
# ----------------------------------------------------------------------

def _make_session(tmp_path, lines):
    """Helper: write a JSONL session file and return a discover record for it."""
    import json
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone

    path = tmp_path / "audit-session.jsonl"
    path.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    return ConversationRecord(
        source_path=path,
        tool="claude_code",
        conversation_id="audit",
        created_at=datetime.now(timezone.utc),
        raw=None,
    )


def test_thinking_blocks_are_extracted(tmp_path):
    """An assistant `thinking` block must be mined (the v0.2/0.3 silent leak)."""
    rec = _make_session(tmp_path, [
        {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "user pasted TOKEN=ghp_inThinking01"}
        ]}}
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert any("ghp_inThinking01" in c.text for c in chunks), (
        "thinking blocks are silently dropped"
    )


def test_tool_use_input_is_extracted(tmp_path):
    """tool_use blocks carry credentials in their .input dict (e.g. bash cmds)."""
    rec = _make_session(tmp_path, [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash",
             "input": {"command": "curl -H 'Authorization: Bearer ghp_inToolUse02' https://api.github.com"}}
        ]}}
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert any("ghp_inToolUse02" in c.text for c in chunks), (
        "tool_use.input fields are silently dropped"
    )


def test_attachment_records_are_extracted(tmp_path):
    """Top-level attachment records must be processed."""
    rec = _make_session(tmp_path, [
        {"type": "attachment",
         "attachment": {"text": "GITHUB_TOKEN=ghp_inAttachment03",
                        "kind": "clipboard-paste"}}
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert any("ghp_inAttachment03" in c.text for c in chunks), (
        "attachment records are silently dropped"
    )


def test_system_records_are_extracted(tmp_path):
    """system records carry hook output / tool errors / compact metadata."""
    rec = _make_session(tmp_path, [
        {"type": "system",
         "subtype": "tool_error",
         "content": "command failed: API_KEY=sk-inSystemRecord04 is invalid"}
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert any("sk-inSystemRecord04" in c.text for c in chunks), (
        "system records are silently dropped"
    )


def test_file_history_snapshot_records_are_extracted(tmp_path):
    """file-history-snapshot records can contain the contents of .env files."""
    rec = _make_session(tmp_path, [
        {"type": "file-history-snapshot",
         "snapshot": {"path": "/proj/.env",
                      "before": "DB_URL=postgresql://u:p@db/x",
                      "after": "DB_URL=postgresql://admin:Sn4pH1stP4ssw0rd05@db/prod"}}
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert any("Sn4pH1stP4ssw0rd05" in c.text for c in chunks), (
        "file-history-snapshot records are silently dropped"
    )


def test_bookkeeping_records_remain_skipped(tmp_path):
    """queue-operation / last-prompt / permission-mode / ai-title / pr-link
    carry no payload that warrants per-line chunks; they should still be skipped
    so we don't pay TruffleHog cost for empty content."""
    rec = _make_session(tmp_path, [
        {"type": "queue-operation"},
        {"type": "last-prompt"},
        {"type": "permission-mode", "permissionMode": "default"},
        {"type": "ai-title", "title": "some chat"},
        {"type": "pr-link", "url": "https://github.com/x/y/pull/1"},
    ])
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert chunks == [], f"expected no chunks for bookkeeping types, got: {chunks!r}"
