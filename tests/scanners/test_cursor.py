import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.scanners.cursor import CursorScanner


@pytest.fixture
def cursor_db(tmp_path) -> Path:
    """Synthetic state.vscdb with one composerData entry containing a fake credential."""
    db_path = tmp_path / "state.vscdb"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
    conversation_data = json.dumps({
        "_v": 1,
        "composerId": "composer-uuid-1",
        "text": "Here is my config: api_key = AKIAIOSFODNN7EXAMPLE and it works.",
        "conversationMap": {},
        "createdAt": 1704067200000,
    })
    conn.execute(
        "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
        ("composerData:composer-uuid-1", conversation_data),
    )
    conn.commit()
    conn.close()
    return db_path


def test_scanner_name():
    s = CursorScanner()
    assert s.name == "cursor"


def test_not_available_when_db_missing(tmp_path, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_returns_one_record_per_composer(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "cursor"
    assert records[0].conversation_id == "composer-uuid-1"


def test_extract_text_reads_text_field(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    chunks = s.extract_text(records[0])
    combined = " ".join(c.text for c in chunks)
    assert "AKIAIOSFODNN7EXAMPLE" in combined


def test_extract_text_position_includes_row_key(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert all("composerData:" in c.position for c in chunks)
