import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.models import Finding
from ghosttype.report import write_json, write_csv, copy_sources


@pytest.fixture
def findings(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text('{"type":"user","message":{"content":"hi"}}\n')
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        Finding(
            tool="claude_code",
            secret_type="aws_access_key",
            secret_value="AKIAIOSFODNN7EXAMPLE",
            file_path=src,
            position="line:1",
            confidence="high",
            context="key = AKIAIOSFODNN7EXAMPLE",
            discovered_at=now,
        )
    ]


def test_write_json_creates_valid_file(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=False)
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"
    assert data[0]["tool"] == "claude_code"
    assert data[0]["confidence"] == "high"


def test_write_json_redacts_when_requested(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=True)
    data = json.loads(out.read_text())
    assert data[0]["secret_value"] == "***REDACTED***"


def test_write_csv_redacts_by_default(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=True)
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["secret_value"] == "***REDACTED***"
    assert rows[0]["tool"] == "claude_code"


def test_write_csv_no_redact_shows_value(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=False)
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"


def test_copy_sources_copies_jsonl_file(tmp_path, findings):
    sources_dir = tmp_path / "sources"
    copy_sources(findings, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1
    assert copied[0].suffix == ".jsonl"


def test_copy_sources_deduplicates_same_file(tmp_path, findings):
    # Two findings pointing to the same source file
    doubled = findings + [
        Finding(
            tool=findings[0].tool,
            secret_type="openai_token",
            secret_value="sk-xxxx",
            file_path=findings[0].file_path,
            position="line:2",
            confidence="high",
            context="token = sk-xxxx",
            discovered_at=findings[0].discovered_at,
        )
    ]
    sources_dir = tmp_path / "sources"
    copy_sources(doubled, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1  # only one copy despite two findings
