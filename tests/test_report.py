import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.models import Finding
from ghosttype.report import copy_sources, write_csv, write_json


@pytest.fixture
def findings(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text('{"type":"user","message":{"content":"hi"}}\n')
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        Finding(
            tool="claude_code",
            secret_type="aws",
            secret_value="AKIA00000000000000000",
            file_path=src,
            position="line:1",
            confidence="verified",
            context="key = AKIA00000000000000000",
            discovered_at=now,
            severity="critical",
            verified=True,
            detector_name="AWS",
            extra_data={"resource_type": "Access key"},
        )
    ]


def test_write_json_creates_valid_file(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=False)
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["secret_value"] == "AKIA00000000000000000"
    assert data[0]["tool"] == "claude_code"
    assert data[0]["confidence"] == "verified"
    assert data[0]["verified"] is True
    assert data[0]["detector_name"] == "AWS"
    assert data[0]["extra_data"]["resource_type"] == "Access key"


def test_write_json_redacts_when_requested(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=True)
    data = json.loads(out.read_text())
    assert data[0]["secret_value"] == "***REDACTED***"


def test_write_csv_redacts_by_default(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=True)
    with out.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["secret_value"] == "***REDACTED***"
    assert rows[0]["tool"] == "claude_code"
    assert rows[0]["verified"] in {"True", "true"}
    assert rows[0]["detector_name"] == "AWS"
    # extra_data is JSON-encoded into one cell
    assert json.loads(rows[0]["extra_data"])["resource_type"] == "Access key"


def test_write_csv_no_redact_shows_value(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=False)
    with out.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["secret_value"] == "AKIA00000000000000000"


def test_copy_sources_copies_jsonl_file(tmp_path, findings):
    sources_dir = tmp_path / "sources"
    copy_sources(findings, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1
    assert copied[0].suffix == ".jsonl"


def test_copy_sources_deduplicates_same_file(tmp_path, findings):
    doubled = findings + [
        Finding(
            tool=findings[0].tool,
            secret_type="openai",
            secret_value="sk-xxxx",
            file_path=findings[0].file_path,
            position="line:2",
            confidence="unverified",
            context="token = sk-xxxx",
            discovered_at=findings[0].discovered_at,
            verified=False,
            detector_name="OpenAI",
        )
    ]
    sources_dir = tmp_path / "sources"
    copy_sources(doubled, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1


def test_write_json_is_owner_only(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=False)
    assert out.stat().st_mode & 0o077 == 0


def test_write_csv_is_owner_only(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=False)
    assert out.stat().st_mode & 0o077 == 0


def test_report_perms_tightened_when_file_preexists_world_readable(
    tmp_path, findings
):
    # A prior run may have left a world-readable report in place; the writers
    # must re-restrict it, not inherit the looser mode.
    j = tmp_path / "findings.json"
    j.write_text("[]")
    j.chmod(0o644)
    write_json(findings, j, redact=False)
    assert j.stat().st_mode & 0o077 == 0

    c = tmp_path / "findings.csv"
    c.write_text("stale")
    c.chmod(0o644)
    write_csv(findings, c, redact=False)
    assert c.stat().st_mode & 0o077 == 0


def test_redact_scrubs_secret_from_context_and_extra_data(tmp_path, findings):
    f = findings[0]
    f.context = "leak: AKIA00000000000000000 in surrounding text"
    f.extra_data = {"rotation": "AKIA00000000000000000", "ok": "safe"}
    out = tmp_path / "findings.json"
    write_json([f], out, redact=True)
    blob = out.read_text()
    assert "AKIA00000000000000000" not in blob
    data = json.loads(blob)
    assert data[0]["secret_value"] == "***REDACTED***"
    assert "***REDACTED***" in data[0]["context"]
    assert data[0]["extra_data"]["rotation"] == "***REDACTED***"
    assert data[0]["extra_data"]["ok"] == "safe"


def test_redact_false_leaves_context_and_extra_data_intact(tmp_path, findings):
    f = findings[0]
    f.context = "raw AKIA00000000000000000 here"
    out = tmp_path / "findings.json"
    write_json([f], out, redact=False)
    data = json.loads(out.read_text())
    assert data[0]["secret_value"] == "AKIA00000000000000000"
    assert "AKIA00000000000000000" in data[0]["context"]


def test_redact_scrubs_secret_from_verification_error(tmp_path, findings):
    """TruffleHog's live verifier echoes provider API error bodies into
    verification_error, and some providers include the submitted token
    verbatim. --redact must scrub it there too, or a 'redacted' report still
    leaks the credential."""
    f = findings[0]
    f.verification_error = (
        "provider rejected token 'AKIA00000000000000000': 403 Forbidden"
    )
    out = tmp_path / "findings.json"
    write_json([f], out, redact=True)
    blob = out.read_text()
    assert "AKIA00000000000000000" not in blob
    data = json.loads(blob)
    assert "***REDACTED***" in data[0]["verification_error"]
    assert "403 Forbidden" in data[0]["verification_error"]


def test_redact_false_leaves_verification_error_intact(tmp_path, findings):
    f = findings[0]
    f.verification_error = "token 'AKIA00000000000000000' invalid"
    out = tmp_path / "findings.json"
    write_json([f], out, redact=False)
    data = json.loads(out.read_text())
    assert data[0]["verification_error"] == "token 'AKIA00000000000000000' invalid"


def test_redact_handles_none_verification_error(tmp_path, findings):
    """The common case: no verification error. Scrub must pass None through
    untouched (not crash, not stringify)."""
    f = findings[0]
    f.verification_error = None
    out = tmp_path / "findings.json"
    write_json([f], out, redact=True)
    data = json.loads(out.read_text())
    assert data[0]["verification_error"] is None


def test_public_finding_to_dict_is_exported_and_aliased():
    """report.finding_to_dict is the public serialization API; the historical
    underscore name stays bound to it for back-compat (issue #13)."""
    from ghosttype import report

    assert hasattr(report, "finding_to_dict")
    assert report._finding_to_dict is report.finding_to_dict
