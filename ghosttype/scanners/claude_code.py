from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

_CONTENT_TYPES = {"user", "assistant"}


def _extract_content_text(content: str | list) -> str:
    """Extract plain text from a message content field.

    Handles both string content and content block arrays of the form
    [{"type": "text", "text": "..."}, ...].
    """
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif block.get("type") == "tool_result":
                inner = block.get("content", [])
                if isinstance(inner, list):
                    for b in inner:
                        if isinstance(b, dict) and b.get("type") == "text":
                            parts.append(b.get("text", ""))
    return "\n".join(parts)


class ClaudeCodeScanner(Scanner):
    """Scanner for Claude Code CLI conversation history (~/.claude/projects/)."""

    name = "claude_code"
    display_name = "Claude Code CLI"

    @property
    def _base_path(self) -> Path:
        return Path.home() / ".claude"

    def discover(self) -> list[ConversationRecord]:
        """Return one ConversationRecord per JSONL session file found."""
        projects_dir = self._base_path / "projects"
        if not projects_dir.exists():
            return []
        records: list[ConversationRecord] = []
        for jsonl_path in projects_dir.rglob("*.jsonl"):
            records.append(
                ConversationRecord(
                    source_path=jsonl_path,
                    tool=self.name,
                    conversation_id=jsonl_path.stem,
                    created_at=datetime.fromtimestamp(
                        jsonl_path.stat().st_mtime, tz=timezone.utc
                    ),
                    raw=None,
                )
            )
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract all text-bearing messages from a JSONL session file."""
        chunks: list[TextChunk] = []
        try:
            with record.source_path.open(encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("type") not in _CONTENT_TYPES:
                        continue
                    msg = entry.get("message", {})
                    content = msg.get("content", "")
                    text = _extract_content_text(content)
                    if text.strip():
                        chunks.append(
                            TextChunk(
                                text=text,
                                position=f"line:{line_num}",
                                record=record,
                            )
                        )
        except OSError:
            pass
        return chunks
