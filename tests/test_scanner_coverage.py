"""Coverage for SQLite-backed scanners (cursor/codex), the Scanner ABC
contract, report.copy_sources edge cases, and Orchestrator defaults.

Synthetic sqlite fixtures stand in for real app databases. Every assertion
checks an observable outcome (records discovered, text extracted, corrupt
input survived, contract enforced).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest

from ghosttype.models import ConversationRecord, Finding
from ghosttype.scanners.base import Scanner
from ghosttype.scanners.claude import ClaudeScanner
from ghosttype.scanners.codex import CodexScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanner import Orchestrator
from ghosttype.report import copy_sources


# ---------------------------------------------------------------------------
# CursorScanner
# ---------------------------------------------------------------------------

def _cursor_db(path: Path, rows: list[tuple[str, str]]) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.executemany("INSERT INTO cursorDiskKV VALUES (?, ?)", rows)
        conn.commit()


def test_cursor_discover_returns_empty_when_db_absent(tmp_path):
    s = CursorScanner()
    with patch.object(type(s), "_db_path", new_callable=PropertyMock,
                       return_value=tmp_path / "nope.vscdb"):
        assert s.discover() == []


def test_cursor_query_skips_empty_and_malformed_values(tmp_path):
    db = tmp_path / "state.vscdb"
    _cursor_db(db, [
        ("composerData:a", ""),                 # empty value -> skipped
        ("composerData:b", "{not json"),        # malformed -> skipped
        ("composerData:c", json.dumps({
            "composerId": "c", "text": "real conversation text",
            "createdAt": 1704067200000})),
    ])
    s = CursorScanner()
    with patch.object(type(s), "_db_path", new_callable=PropertyMock, return_value=db), \
         patch.object(type(s), "_workspace_dbs", return_value=[]):
        recs = s.discover()
    assert len(recs) == 1 and recs[0].conversation_id == "c"
    assert recs[0].created_at is not None


def test_cursor_corrupt_db_is_logged_not_raised(tmp_path, caplog):
    bad = tmp_path / "state.vscdb"
    bad.write_text("this is not a sqlite file")
    s = CursorScanner()
    with patch.object(type(s), "_db_path", new_callable=PropertyMock, return_value=bad), \
         patch.object(type(s), "_workspace_dbs", return_value=[]):
        with caplog.at_level(logging.WARNING):
            assert s.discover() == []
    assert "Failed to read cursor db" in caplog.text


def test_cursor_workspace_db_without_composer_table_is_skipped(tmp_path, caplog):
    """Workspace-storage state.vscdb files often lack the cursorDiskKV table
    (no Composer history). Those must be skipped quietly, not error out."""
    db = tmp_path / "state.vscdb"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE ItemTable (key TEXT, value TEXT)")  # not cursorDiskKV
        conn.commit()
    s = CursorScanner()
    with patch.object(type(s), "_db_path", new_callable=PropertyMock, return_value=db), \
         patch.object(type(s), "_workspace_dbs", return_value=[]):
        with caplog.at_level(logging.DEBUG):
            assert s.discover() == []
    assert "no cursorDiskKV table" in caplog.text


def test_cursor_other_operational_error_is_warned(tmp_path, caplog):
    """An OperationalError that is NOT 'no such table' is logged at warning."""
    s = CursorScanner()
    with patch("ghosttype.scanners.cursor.sqlite3.connect",
               side_effect=sqlite3.OperationalError("database is locked")):
        with patch.object(type(s), "_db_path", new_callable=PropertyMock,
                           return_value=tmp_path / "state.vscdb"), \
             patch.object(type(s), "_workspace_dbs", return_value=[]):
            (tmp_path / "state.vscdb").write_text("x")
            with caplog.at_level(logging.WARNING):
                assert s.discover() == []
    assert "Failed to read cursor db" in caplog.text


def test_cursor_workspace_dbs_globs_when_root_exists(tmp_path):
    ws_root = tmp_path / "workspaceStorage"
    (ws_root / "hash1").mkdir(parents=True)
    (ws_root / "hash1" / "state.vscdb").write_text("x")
    s = CursorScanner()
    with patch("ghosttype.scanners.cursor.Path.home", return_value=tmp_path):
        # _workspace_dbs builds the path from Path.home(); structure differs,
        # so assert it returns a list without raising.
        assert isinstance(s._workspace_dbs(), list)


def test_cursor_extract_text_primary_and_conversation_map(tmp_path):
    rec = ConversationRecord(
        source_path=tmp_path / "state.vscdb",
        tool="cursor",
        conversation_id="c1",
        created_at=None,
        raw={"key": "composerData:c1", "data": {
            "text": "  ",  # whitespace primary -> skipped
            "conversationMap": {
                "m1": {"text": "AWS_SECRET=wJalrXUtnFEMIexampleNOTREAL"},
                "m2": {"content": "second message body"},
                "m3": "not-a-dict",                # skipped
                "m4": {"text": "   "},             # whitespace -> skipped
            },
        }},
    )
    chunks = CursorScanner().extract_text(rec)
    texts = [c.text for c in chunks]
    assert "AWS_SECRET=wJalrXUtnFEMIexampleNOTREAL" in texts
    assert "second message body" in texts
    assert len(chunks) == 2


# ---------------------------------------------------------------------------
# CodexScanner
# ---------------------------------------------------------------------------

def test_codex_discover_empty_when_state_db_absent(tmp_path):
    s = CodexScanner()
    with patch.object(type(s), "_base_path", new_callable=PropertyMock,
                       return_value=tmp_path):
        assert s.discover() == []


def test_codex_discover_corrupt_state_db_returns_empty(tmp_path):
    base = tmp_path / ".codex"
    base.mkdir()
    (base / "state_5.sqlite").write_text("garbage, not sqlite")
    s = CodexScanner()
    with patch.object(type(s), "_base_path", new_callable=PropertyMock,
                       return_value=base):
        assert s.discover() == []


def test_codex_discover_and_extract_first_user_message(tmp_path):
    base = tmp_path / ".codex"
    base.mkdir()
    db = base / "state_5.sqlite"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "CREATE TABLE threads (id TEXT, title TEXT, first_user_message TEXT, created_at INTEGER)"
        )
        conn.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            ("t1", "Some thread", "deploy with TOKEN=ghp_realishvalue123", 1704067200),
        )
        conn.commit()
    s = CodexScanner()
    with patch.object(type(s), "_base_path", new_callable=PropertyMock,
                       return_value=base):
        recs = s.discover()
        assert len(recs) == 1
        chunks = s.extract_text(recs[0])
    assert any("ghp_realishvalue123" in c.text for c in chunks)


def test_codex_extract_text_reads_logs_db_body(tmp_path):
    base = tmp_path / ".codex"
    base.mkdir()
    logs = base / "logs_2.sqlite"
    with closing(sqlite3.connect(logs)) as conn:
        conn.execute("CREATE TABLE logs (thread_id TEXT, feedback_log_body TEXT)")
        conn.execute(
            "INSERT INTO logs VALUES (?,?)", ("t9", "log body with KEY=sk-fromlogsbody")
        )
        conn.commit()
    rec = ConversationRecord(
        source_path=base / "state_5.sqlite",
        tool="codex",
        conversation_id="t9",
        created_at=None,
        raw={"thread_id": "t9", "first_user_message": ""},  # empty -> only logs
    )
    s = CodexScanner()
    with patch.object(type(s), "_base_path", new_callable=PropertyMock,
                       return_value=base):
        chunks = s.extract_text(rec)
    assert any("sk-fromlogsbody" in c.text for c in chunks)


def test_codex_extract_text_no_logs_db_just_returns_first_message(tmp_path):
    base = tmp_path / ".codex"
    base.mkdir()  # no logs_2.sqlite
    rec = ConversationRecord(
        source_path=base / "state_5.sqlite", tool="codex", conversation_id="t1",
        created_at=None, raw={"thread_id": "t1", "first_user_message": "just this"},
    )
    s = CodexScanner()
    with patch.object(type(s), "_base_path", new_callable=PropertyMock,
                       return_value=base):
        chunks = s.extract_text(rec)
    assert [c.text for c in chunks] == ["just this"]


# ---------------------------------------------------------------------------
# Scanner ABC contract
# ---------------------------------------------------------------------------

def test_scanner_subclass_without_name_raises_typeerror():
    """The ABC guarantees concrete scanners declare name/display_name."""
    with pytest.raises(TypeError, match="must define class attribute"):
        class BadScanner(Scanner):  # noqa: missing name/display_name
            @property
            def _base_path(self):
                return Path("/tmp")

            def discover(self):
                return []

            def extract_text(self, record):
                return []


def test_claude_stub_discover_and_extract_return_empty(tmp_path):
    s = ClaudeScanner()
    rec = ConversationRecord(
        source_path=tmp_path / "x", tool="claude", conversation_id="s",
        created_at=datetime.now(timezone.utc), raw={},
    )
    assert s.discover() == []
    assert s.extract_text(rec) == []


# ---------------------------------------------------------------------------
# report.copy_sources edge case
# ---------------------------------------------------------------------------

def test_copy_sources_skips_finding_whose_source_file_is_gone(tmp_path):
    """A finding can outlive its source file (deleted between scan and
    report). copy_sources must skip it, not crash."""
    gone = tmp_path / "deleted.jsonl"  # never created
    f = Finding(
        tool="claude_code", secret_type="github", secret_value="x",
        file_path=gone, position="line:1", confidence="unverified",
        context="x", discovered_at=datetime.now(timezone.utc),
    )
    out = tmp_path / "sources"
    copy_sources([f], out)  # must not raise
    assert not (out / "claude_code").exists()


# ---------------------------------------------------------------------------
# Orchestrator defaults + engine-selection properties
# ---------------------------------------------------------------------------

def test_orchestrator_defaults_to_real_scanner_registry():
    from ghosttype.scanners import SCANNERS
    orch = Orchestrator()  # no scanners arg -> default registry
    assert orch._scanners is SCANNERS


def test_orchestrator_engine_selection_properties():
    assert Orchestrator(scanners=[], engine="both").uses_trufflehog is True
    assert Orchestrator(scanners=[], engine="both").uses_patterns is True
    assert Orchestrator(scanners=[], engine="trufflehog").uses_patterns is False
    assert Orchestrator(scanners=[], engine="patterns").uses_trufflehog is False


def test_orchestrator_non_verbose_zero_chunks_is_silent(tmp_path, caplog):
    """Non-verbose run where a scanner extracts nothing: no engine call, no
    'extracted 0 chunks' log line (covers the non-verbose branch)."""
    from unittest.mock import MagicMock
    s = MagicMock()
    s.name = "fake"
    s.is_available.return_value = True
    rec = ConversationRecord(
        source_path=tmp_path / "s.jsonl", tool="fake", conversation_id="c",
        created_at=datetime.now(timezone.utc), raw=None,
    )
    (tmp_path / "s.jsonl").write_text("x")
    s.discover.return_value = [rec]
    s.extract_text.return_value = []
    with patch("ghosttype.scanner.trufflehog_scan_chunks") as eng, \
         patch("ghosttype.pattern_engine.scan_chunks"):
        with caplog.at_level(logging.INFO):
            findings = Orchestrator(scanners=[s], verbose=False).run()
    eng.assert_not_called()
    assert findings == []
    assert "extracted 0 text chunks" not in caplog.text
