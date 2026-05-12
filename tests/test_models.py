from datetime import datetime, timezone
from pathlib import Path
from ghosttype.models import ConversationRecord, TextChunk, PatternMatch, Finding


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


def test_finding_fields():
    now = datetime.now(timezone.utc)
    f = Finding(
        tool="cursor",
        secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=Path("/tmp/state.vscdb"),
        position="composerData:uuid-1:42",
        confidence="high",
        context="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        discovered_at=now,
    )
    assert f.confidence == "high"
    assert f.secret_type == "aws_access_key"
