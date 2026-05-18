import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.scanners.codex import CodexScanner


@pytest.fixture
def codex_dir(tmp_path) -> Path:
    """Synthetic ~/.codex/ with state_5.sqlite and logs_2.sqlite."""
    codex = tmp_path / ".codex"
    codex.mkdir()

    # state_5.sqlite: threads table
    state_db = codex / "state_5.sqlite"
    with closing(sqlite3.connect(state_db)) as conn:
        conn.execute("""
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                title TEXT,
                first_user_message TEXT,
                model TEXT,
                cwd TEXT,
                created_at INTEGER,
                updated_at INTEGER
            )
        """)
        conn.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
            ("thread-abc", "Test session", "my token is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012", "gpt-4o", "/tmp/proj", 1704067200, 1704067260),
        )
        conn.commit()

    # logs_2.sqlite: logs table (empty for this fixture)
    logs_db = codex / "logs_2.sqlite"
    with closing(sqlite3.connect(logs_db)) as conn2:
        conn2.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, feedback_log_body TEXT)")
        conn2.commit()

    return codex


def test_scanner_name():
    assert CodexScanner().name == "codex"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_returns_thread_records(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    assert len(records) == 1
    assert records[0].conversation_id == "thread-abc"
    assert records[0].tool == "codex"


def test_extract_text_includes_first_user_message(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    combined = " ".join(c.text for c in chunks)
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012" in combined


def test_extract_text_position_includes_thread_id(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert all("thread-abc" in c.position for c in chunks)
