"""Resilience + record-dispatch coverage for the Claude Code scanner.

Real-world inputs: corrupt JSONL lines, unreadable files, history/task
discovery, and the per-record-type text dispatch added in the v0.3.0 audit.
Every assertion checks an observable outcome.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.models import ConversationRecord
from ghosttype.scanners.claude_code import (
    ClaudeCodeScanner,
    _extract_record_text,
)


def _session_rec(path: Path) -> ConversationRecord:
    return ConversationRecord(
        source_path=path,
        tool="claude_code",
        conversation_id=path.stem,
        created_at=datetime.now(timezone.utc),
        raw=None,
    )


# --- discover() over projects + history + tasks --------------------------

def test_discover_includes_session_history_and_task_records(tmp_path, monkeypatch):
    projects = tmp_path / "projects" / "-proj"
    projects.mkdir(parents=True)
    (projects / "abc.jsonl").write_text('{"type":"user","message":{"content":"hi"}}\n')
    (tmp_path / "history.jsonl").write_text('{"display":"run something useful"}\n')
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    (tasks / "t1.json").write_text('{"title":"do x"}')

    monkeypatch.setattr(
        type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path)
    )
    recs = ClaudeCodeScanner().discover()
    kinds = {
        (r.raw or {}).get("source_type") if isinstance(r.raw, dict) else None
        for r in recs
    }
    ids = {r.conversation_id for r in recs}
    assert "abc" in ids and "history" in ids and "t1" in ids
    assert "history" in kinds and "task" in kinds


# --- session extraction resilience ---------------------------------------

def test_session_skips_blank_and_malformed_lines(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text(
        "\n"
        "   \n"
        "this is not json\n"
        '{"type":"user","message":{"content":"AKIA-style noise but real text here"}}\n'
        '{"type":"queue-operation"}\n'  # known bookkeeping type -> skipped
    )
    chunks = ClaudeCodeScanner().extract_text(_session_rec(p))
    assert len(chunks) == 1
    assert "real text here" in chunks[0].text


def test_session_unreadable_file_is_logged_not_raised(tmp_path, caplog):
    import logging

    d = tmp_path / "adir.jsonl"
    d.mkdir()  # opening a directory as a file raises OSError
    with caplog.at_level(logging.WARNING):
        chunks = ClaudeCodeScanner().extract_text(_session_rec(d))
    assert chunks == []
    assert "Failed to read" in caplog.text


def test_session_record_yielding_empty_text_produces_no_chunk(tmp_path):
    """An assistant message whose only block is an (empty) image yields no
    text -> no chunk (exercises the text.strip() false branch)."""
    p = tmp_path / "s.jsonl"
    p.write_text(
        '{"type":"assistant","message":{"content":[{"type":"image","source":{}}]}}\n'
    )
    assert ClaudeCodeScanner().extract_text(_session_rec(p)) == []


# --- history extraction resilience ---------------------------------------

def test_history_skips_blank_malformed_slash_and_short(tmp_path):
    p = tmp_path / "history.jsonl"
    p.write_text(
        "\n"
        "not json\n"
        '{"display":"/help"}\n'        # slash command -> skipped
        '{"display":"abc"}\n'          # <=4 chars -> skipped
        '{"display":"export TOKEN=ghp_realisticlongcommand"}\n'
    )
    rec = ConversationRecord(
        source_path=p, tool="claude_code", conversation_id="history",
        created_at=datetime.now(timezone.utc), raw={"source_type": "history"},
    )
    chunks = ClaudeCodeScanner().extract_text(rec)
    assert len(chunks) == 1
    assert "export TOKEN=" in chunks[0].text


def test_history_unreadable_is_logged_not_raised(tmp_path, caplog):
    import logging

    d = tmp_path / "history.jsonl"
    d.mkdir()
    rec = ConversationRecord(
        source_path=d, tool="claude_code", conversation_id="history",
        created_at=datetime.now(timezone.utc), raw={"source_type": "history"},
    )
    with caplog.at_level(logging.WARNING):
        assert ClaudeCodeScanner().extract_text(rec) == []
    assert "Failed to read history" in caplog.text


# --- task extraction resilience ------------------------------------------

def test_task_malformed_json_is_logged_not_raised(tmp_path, caplog):
    import logging

    p = tmp_path / "t.json"
    p.write_text("{ not valid json ")
    rec = ConversationRecord(
        source_path=p, tool="claude_code", conversation_id="t",
        created_at=datetime.now(timezone.utc), raw={"source_type": "task"},
    )
    with caplog.at_level(logging.WARNING):
        assert ClaudeCodeScanner().extract_text(rec) == []
    assert "Failed to read task" in caplog.text


# --- _extract_record_text dispatch ---------------------------------------

def test_extract_record_text_system_with_non_string_content():
    """A system record whose `content` is not a str still mines
    compactMetadata strings (content branch skipped, metadata branch taken)."""
    entry = {
        "type": "system",
        "content": {"structured": "not-a-string"},
        "compactMetadata": {"summary": "leaked KEY=sk-fromCompactMetadata123456"},
    }
    out = _extract_record_text(entry)
    assert "sk-fromCompactMetadata123456" in out


def test_extract_record_text_unknown_type_returns_empty():
    assert _extract_record_text({"type": "totally-unknown-record"}) == ""


def test_extract_record_text_file_history_snapshot_mines_contents():
    entry = {
        "type": "file-history-snapshot",
        "snapshot": {"path": "/p/.env", "after": "DB=postgres://u:Pa55w0rdLeak@h/d"},
    }
    assert "Pa55w0rdLeak" in _extract_record_text(entry)


def test_content_list_with_non_dict_block_is_skipped(tmp_path):
    """A content array may contain bare strings alongside blocks; non-dict
    items must be skipped without crashing, dict blocks still mined."""
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps({
        "type": "user",
        "message": {"content": [
            "a bare string item",
            {"type": "text", "text": "AWS key AKIA-real-ish-value-here"},
        ]},
    }) + "\n")
    chunks = ClaudeCodeScanner().extract_text(_session_rec(p))
    assert len(chunks) == 1
    assert "AKIA-real-ish-value-here" in chunks[0].text


def test_tool_result_string_and_list_content_both_mined(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text(
        json.dumps({
            "type": "user",
            "message": {"content": [
                {"type": "tool_result",
                 "content": "string form: SECRET=sk-toolResultStringForm01"},
            ]},
        }) + "\n"
        + json.dumps({
            "type": "user",
            "message": {"content": [
                {"type": "tool_result", "content": [
                    {"type": "text", "text": "list form: SECRET=sk-toolResultListForm02"},
                    {"type": "image", "source": {}},
                ]},
            ]},
        }) + "\n"
    )
    text = "\n".join(c.text for c in ClaudeCodeScanner().extract_text(_session_rec(p)))
    assert "sk-toolResultStringForm01" in text
    assert "sk-toolResultListForm02" in text


def test_task_with_only_short_strings_yields_no_chunk(tmp_path):
    """A task JSON whose string values are all below the extraction floor
    produces no chunk (the empty-combined branch)."""
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"a": "x", "b": "y", "n": 1}))
    rec = ConversationRecord(
        source_path=p, tool="claude_code", conversation_id="t",
        created_at=datetime.now(timezone.utc), raw={"source_type": "task"},
    )
    assert ClaudeCodeScanner().extract_text(rec) == []


def test_discover_with_only_history_no_projects_dir(tmp_path, monkeypatch):
    """Host that has ~/.claude/history.jsonl but no projects/ dir: discover
    still returns the history record (projects_dir.exists() false branch)."""
    (tmp_path / "history.jsonl").write_text('{"display":"a real command here"}\n')
    monkeypatch.setattr(
        type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path)
    )
    recs = ClaudeCodeScanner().discover()
    assert [r.conversation_id for r in recs] == ["history"]
