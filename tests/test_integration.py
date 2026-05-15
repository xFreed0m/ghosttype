"""End-to-end test: synthetic conversation files with planted fake credentials."""
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch, PropertyMock

import pytest

from ghosttype.scanners.claude_code import ClaudeCodeScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanner import Orchestrator
from ghosttype.report import write_json, write_csv


@pytest.fixture
def synthetic_claude_code_dir(tmp_path) -> Path:
    projects = tmp_path / "projects" / "-Users-test"
    projects.mkdir(parents=True)
    session = projects / "integ-session.jsonl"
    lines = [
        json.dumps({"type": "user", "message": {"content": "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12"}, "uuid": "u1", "sessionId": "s1", "timestamp": "2026-01-01T00:00:00Z", "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": None, "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"}),
        json.dumps({"type": "assistant", "message": {"content": "I see an OpenAI key."}, "uuid": "u2", "sessionId": "s1", "timestamp": "2026-01-01T00:00:01Z", "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": "u1", "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"}),
    ]
    session.write_text("\n".join(lines) + "\n")
    return tmp_path


@pytest.fixture
def synthetic_cursor_dir(tmp_path) -> Path:
    db_path = tmp_path / "state.vscdb"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?, ?)",
        ("composerData:integ-uuid", json.dumps({
            "composerId": "integ-uuid",
            "text": "connect to postgresql://admin:S3cr3tP@ss@db.example.com:5432/prod",
            "conversationMap": {},
            "createdAt": 1704067200000,
        })),
    )
    conn.commit()
    conn.close()
    return tmp_path


def test_end_to_end_claude_code_finds_openai_key(synthetic_claude_code_dir, tmp_path):
    scanner = ClaudeCodeScanner()
    with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_claude_code_dir):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()

    assert any(f.secret_type == "openai_token" for f in findings)
    openai_finding = next(f for f in findings if f.secret_type == "openai_token")
    assert openai_finding.tool == "claude_code"
    assert openai_finding.confidence == "high"

    # Write reports and verify structure
    write_json(findings, tmp_path / "report" / "findings.json")
    write_csv(findings, tmp_path / "report" / "findings.csv", redact=True)
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


def test_end_to_end_cursor_finds_connection_string(synthetic_cursor_dir, tmp_path):
    scanner = CursorScanner()
    with patch.object(type(scanner), "_db_path", new_callable=PropertyMock, return_value=synthetic_cursor_dir / "state.vscdb"):
        with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_cursor_dir):
            orch = Orchestrator(scanners=[scanner])
            findings = orch.run()

    assert any(f.secret_type == "connection_string" for f in findings)
    conn_finding = next(f for f in findings if f.secret_type == "connection_string")
    assert "postgresql://" in conn_finding.secret_value
    assert conn_finding.tool == "cursor"


def test_deduplication_across_files(synthetic_claude_code_dir, tmp_path):
    """Same secret in two different session files should produce two findings (different source paths)."""
    # Add a second session with the same key
    projects = synthetic_claude_code_dir / "projects" / "-Users-test"
    dup = projects / "dup-session.jsonl"
    dup.write_text(json.dumps({
        "type": "user", "message": {"content": "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12"},
        "uuid": "u3", "sessionId": "s2", "timestamp": "2026-01-01T00:00:02Z",
        "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": None,
        "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"
    }) + "\n")

    scanner = ClaudeCodeScanner()
    with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_claude_code_dir):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()

    # Same value in different files = two findings (different source paths)
    openai_findings = [f for f in findings if f.secret_type == "openai_token"]
    assert len(openai_findings) == 2  # two different files
