from datetime import datetime, timezone
from pathlib import Path
from ghosttype.models import ConversationRecord, TextChunk, Finding


def test_conversation_record_fields():
    rec = ConversationRecord(
        source_path=Path("/tmp/test.jsonl"),
        tool="claude_code",
        conversation_id="abc-123",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw={"messages": []},
    )
    assert rec.tool == "claude_code"
    assert rec.conversation_id == "abc-123"


def test_text_chunk_back_reference():
    rec = ConversationRecord(
        source_path=Path("/tmp/test.jsonl"),
        tool="claude_code",
        conversation_id="abc-123",
        created_at=None,
        raw={},
    )
    chunk = TextChunk(text="hello world", position="line:5", record=rec)
    assert chunk.record is rec


def test_finding_default_fields():
    now = datetime.now(timezone.utc)
    f = Finding(
        tool="cursor",
        secret_type="github",
        secret_value="ghp_xxx",
        file_path=Path("/tmp/state.vscdb"),
        position="composerData:uuid-1:42",
        confidence="unverified",
        context="ghp_xxx",
        discovered_at=now,
    )
    assert f.verified is False
    assert f.detector_name == ""
    assert f.verification_error is None
    assert f.extra_data == {}


def test_finding_verified_fields():
    now = datetime.now(timezone.utc)
    f = Finding(
        tool="claude_code",
        secret_type="aws",
        secret_value="AKIA00000000000000000",
        file_path=Path("/tmp/session.jsonl"),
        position="line:1",
        confidence="verified",
        context="...AKIA00000000000000000...",
        discovered_at=now,
        severity="critical",
        verified=True,
        detector_name="AWS",
        extra_data={"resource_type": "Access key"},
    )
    assert f.verified is True
    assert f.confidence == "verified"
    assert f.severity == "critical"
    assert f.detector_name == "AWS"
    assert f.extra_data["resource_type"] == "Access key"
