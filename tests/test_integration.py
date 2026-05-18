"""End-to-end tests over synthetic conversation files.

Most tests drive the real `trufflehog` binary and are skipped automatically
when it is not on PATH (`@requires_trufflehog`). All credentials below are
obviously-fake and crafted to match TruffleHog's structural patterns but WILL
fail live verification (they aren't real). These assert:

  - the engine produces a Finding for the planted secret
  - the discovery layer correctly hands the right ConversationRecord

One test is deliberately NOT trufflehog-gated:
`test_end_to_end_cursor_pattern_engine_finds_connection_string` exercises the
`--engine patterns` path (Cursor -> orchestrator -> in-tree pattern engine)
for a `connection_string` — a type only the pattern engine detects. It is the
regression guard for the pattern-engine-only e2e coverage that existed in
v0.2.0 and was dropped in commit fa16b0c when TruffleHog became primary.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch, PropertyMock

import pytest

from ghosttype.scanners.claude_code import ClaudeCodeScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanner import Orchestrator
from ghosttype.report import write_csv, write_json

requires_trufflehog = pytest.mark.skipif(
    shutil.which("trufflehog") is None,
    reason="trufflehog binary not on PATH",
)

# An obviously-fake but structurally-valid GitHub PAT pattern. TruffleHog's
# Github detector matches `ghp_` + 36 alphanumeric chars.
FAKE_GITHUB_PAT = "ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


@pytest.fixture
def synthetic_claude_code_dir(tmp_path) -> Path:
    projects = tmp_path / "projects" / "-Users-test"
    projects.mkdir(parents=True)
    session = projects / "integ-session.jsonl"
    lines = [
        json.dumps({
            "type": "user",
            "message": {"content": f"GITHUB_TOKEN={FAKE_GITHUB_PAT}"},
            "uuid": "u1", "sessionId": "s1",
            "timestamp": "2026-01-01T00:00:00Z",
            "cwd": "/tmp", "version": "1", "userType": "human",
            "parentUuid": None, "isSidechain": False,
            "entrypoint": "cli", "gitBranch": "main",
        }),
        json.dumps({
            "type": "assistant",
            "message": {"content": "I see a GitHub token."},
            "uuid": "u2", "sessionId": "s1",
            "timestamp": "2026-01-01T00:00:01Z",
            "cwd": "/tmp", "version": "1", "userType": "human",
            "parentUuid": "u1", "isSidechain": False,
            "entrypoint": "cli", "gitBranch": "main",
        }),
    ]
    session.write_text("\n".join(lines) + "\n")
    return tmp_path


@pytest.fixture
def synthetic_cursor_dir(tmp_path) -> Path:
    db_path = tmp_path / "state.vscdb"
    # closing() guarantees the handle is released even if execute() raises,
    # so the fixture never leaks a connection into later tests.
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO cursorDiskKV VALUES (?, ?)",
            (
                "composerData:integ-uuid",
                json.dumps(
                    {
                        "composerId": "integ-uuid",
                        "text": f"GITHUB_TOKEN={FAKE_GITHUB_PAT}",
                        "conversationMap": {},
                        "createdAt": 1704067200000,
                    }
                ),
            ),
        )
        conn.commit()
    return tmp_path


@pytest.fixture
def synthetic_cursor_connstring_dir(tmp_path) -> Path:
    """Cursor corpus planting a DB connection string — a type the in-tree
    pattern engine detects but TruffleHog does NOT. Used to drive the
    pattern-engine-only path with no trufflehog binary present."""
    db_path = tmp_path / "state.vscdb"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO cursorDiskKV VALUES (?, ?)",
            (
                "composerData:conn-uuid",
                json.dumps(
                    {
                        "composerId": "conn-uuid",
                        "text": (
                            "DATABASE_URL="
                            "postgresql://svc:s3cr3tPlaceholder@db.internal:5432/prod"
                        ),
                        "conversationMap": {},
                        "createdAt": 1704067200000,
                    }
                ),
            ),
        )
        conn.commit()
    return tmp_path


def test_end_to_end_cursor_pattern_engine_finds_connection_string(
    synthetic_cursor_connstring_dir,
):
    """Pattern-engine-only e2e (NO trufflehog binary needed). Cursor scanner
    -> orchestrator -> in-tree pattern engine still surfaces a DB connection
    string. Regression guard for the coverage dropped in commit fa16b0c."""
    scanner = CursorScanner()
    with patch.object(
        type(scanner),
        "_db_path",
        new_callable=PropertyMock,
        return_value=synthetic_cursor_connstring_dir / "state.vscdb",
    ), patch.object(
        type(scanner),
        "_base_path",
        new_callable=PropertyMock,
        return_value=synthetic_cursor_connstring_dir,
    ):
        orch = Orchestrator(scanners=[scanner], engine="patterns")
        findings = orch.run()

    assert any(f.secret_type == "connection_string" for f in findings)
    conn = next(f for f in findings if f.secret_type == "connection_string")
    assert conn.tool == "cursor"
    assert conn.secret_value.startswith("postgresql://")
    # Pattern-engine hits are never verified, and under the unified severity
    # scheme a non-critical-class type is `medium` (was `high`/`critical`
    # before the cross-engine alignment).
    assert conn.verified is False
    assert conn.severity == "medium"
    assert conn.source != "trufflehog"


@requires_trufflehog
def test_end_to_end_claude_code_finds_github_token(synthetic_claude_code_dir, tmp_path):
    scanner = ClaudeCodeScanner()
    with patch.object(
        type(scanner),
        "_base_path",
        new_callable=PropertyMock,
        return_value=synthetic_claude_code_dir,
    ):
        orch = Orchestrator(scanners=[scanner], verify=False)
        findings = orch.run()

    assert any(f.detector_name.lower() == "github" for f in findings)
    gh = next(f for f in findings if f.detector_name.lower() == "github")
    assert gh.tool == "claude_code"
    assert gh.secret_value == FAKE_GITHUB_PAT
    # verify=False was passed, so every finding should be unverified
    assert gh.verified is False
    assert gh.confidence == "unverified"

    write_json(findings, tmp_path / "report" / "findings.json")
    write_csv(findings, tmp_path / "report" / "findings.csv", redact=True)
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


@requires_trufflehog
def test_end_to_end_cursor_finds_github_token(synthetic_cursor_dir, tmp_path):
    scanner = CursorScanner()
    with patch.object(
        type(scanner),
        "_db_path",
        new_callable=PropertyMock,
        return_value=synthetic_cursor_dir / "state.vscdb",
    ), patch.object(
        type(scanner),
        "_base_path",
        new_callable=PropertyMock,
        return_value=synthetic_cursor_dir,
    ):
        orch = Orchestrator(scanners=[scanner], verify=False)
        findings = orch.run()

    assert any(f.detector_name.lower() == "github" for f in findings)
    gh = next(f for f in findings if f.detector_name.lower() == "github")
    assert gh.tool == "cursor"
    assert gh.secret_value == FAKE_GITHUB_PAT


@requires_trufflehog
def test_deduplication_across_files(synthetic_claude_code_dir, tmp_path):
    """Same secret in two different session files should produce two findings
    (different source paths)."""
    projects = synthetic_claude_code_dir / "projects" / "-Users-test"
    dup = projects / "dup-session.jsonl"
    dup.write_text(
        json.dumps(
            {
                "type": "user",
                "message": {"content": f"GITHUB_TOKEN={FAKE_GITHUB_PAT}"},
                "uuid": "u3", "sessionId": "s2",
                "timestamp": "2026-01-01T00:00:02Z",
                "cwd": "/tmp", "version": "1", "userType": "human",
                "parentUuid": None, "isSidechain": False,
                "entrypoint": "cli", "gitBranch": "main",
            }
        )
        + "\n"
    )

    scanner = ClaudeCodeScanner()
    with patch.object(
        type(scanner),
        "_base_path",
        new_callable=PropertyMock,
        return_value=synthetic_claude_code_dir,
    ):
        orch = Orchestrator(scanners=[scanner], verify=False)
        findings = orch.run()

    gh_findings = [f for f in findings if f.detector_name.lower() == "github"]
    assert len(gh_findings) == 2
    assert len({f.file_path for f in gh_findings}) == 2
