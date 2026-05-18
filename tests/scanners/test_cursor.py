import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.scanners.cursor import CursorScanner


@pytest.fixture
def cursor_db(tmp_path) -> Path:
    """Synthetic state.vscdb with one composerData entry containing a fake credential."""
    db_path = tmp_path / "state.vscdb"
    conversation_data = json.dumps({
        "_v": 1,
        "composerId": "composer-uuid-1",
        "text": "Here is my config: api_key = AKIAIOSFODNN7EXAMPLE and it works.",
        "conversationMap": {},
        "createdAt": 1704067200000,
    })
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            ("composerData:composer-uuid-1", conversation_data),
        )
        conn.commit()
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


def _make_vscdb(path: Path, composer_id: str, text: str) -> None:
    """Helper: create a minimal state.vscdb at path."""
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (f"composerData:{composer_id}", json.dumps({"composerId": composer_id, "text": text})),
        )
        conn.commit()


def test_discover_also_scans_workspace_dbs(tmp_path, monkeypatch):
    """Records from workspace storage DBs are included alongside the global DB."""
    global_db = tmp_path / "state.vscdb"
    _make_vscdb(global_db, "global-composer", "global text")

    ws_dir = tmp_path / "workspaceStorage" / "abc123"
    ws_dir.mkdir(parents=True)
    ws_db = ws_dir / "state.vscdb"
    _make_vscdb(ws_db, "workspace-composer", "workspace text with token")

    monkeypatch.setattr(type(CursorScanner()), "_db_path", property(lambda self: global_db))

    def fake_workspace_dbs(self):
        return [ws_db]

    monkeypatch.setattr(CursorScanner, "_workspace_dbs", fake_workspace_dbs)

    s = CursorScanner()
    records = s.discover()
    ids = {r.conversation_id for r in records}
    assert "global-composer" in ids
    assert "workspace-composer" in ids


def test_workspace_dbs_returns_empty_when_dir_missing(tmp_path):
    """_workspace_dbs() returns [] gracefully when workspaceStorage does not exist."""
    s = CursorScanner()
    # Point home to tmp_path so the workspaceStorage path won't exist
    import unittest.mock as mock
    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        result = s._workspace_dbs()
    assert result == []
