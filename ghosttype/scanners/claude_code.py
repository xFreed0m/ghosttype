from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)

# Top-level record types whose payload should be mined for credentials.
# - user/assistant: the conversation itself
# - attachment: pasted clipboard content, dropped files, image OCR, etc.
# - system: hook output, tool-call errors, compact metadata
# - file-history-snapshot: file contents Claude touched (can include .env etc)
_CONTENT_RECORD_TYPES = {
    "user",
    "assistant",
    "attachment",
    "system",
    "file-history-snapshot",
}


def _extract_content_text(content: str | list) -> str:
    """Extract plain text from a message `content` field.

    Handles all Anthropic content block kinds that can plausibly carry pasted
    secrets:

    - string content (legacy / shorthand)
    - {"type":"text", "text":"..."}
    - {"type":"thinking", "thinking":"..."} — extended thinking output
    - {"type":"tool_use", "input": {...}} — flatten every string leaf in the
      tool input (bash commands, file paths, MCP args, etc.)
    - {"type":"tool_result", "content": "..." | [{"type":"text", "text":"..."}, ...]}

    Block kinds that cannot carry text (image, document, etc.) are skipped.
    """
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            parts.append(block.get("text", ""))
        elif btype == "thinking":
            parts.append(block.get("thinking", ""))
        elif btype == "tool_use":
            # tool_use.input is an arbitrary dict; recurse into every string.
            parts.extend(_extract_strings_from_json(block.get("input", {}), min_len=1))
        elif btype == "tool_result":
            inner = block.get("content", [])
            if isinstance(inner, str):
                parts.append(inner)
            elif isinstance(inner, list):
                for b in inner:
                    if isinstance(b, dict) and b.get("type") == "text":
                        parts.append(b.get("text", ""))
    return "\n".join(parts)


def _extract_strings_from_json(data: Any, min_len: int = 8) -> list[str]:
    """Recursively extract string values from JSON data."""
    results: list[str] = []
    if isinstance(data, str) and len(data) >= min_len:
        results.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            results.extend(_extract_strings_from_json(v, min_len))
    elif isinstance(data, list):
        for item in data:
            results.extend(_extract_strings_from_json(item, min_len))
    return results


def _extract_record_text(entry: dict) -> str:
    """Pull credential-bearing text out of a top-level JSONL record.

    Dispatches on `entry["type"]`. Records whose type is not in
    `_CONTENT_RECORD_TYPES` return ""; the caller skips empty chunks.
    """
    rtype = entry.get("type")
    if rtype in {"user", "assistant"}:
        msg = entry.get("message", {}) or {}
        return _extract_content_text(msg.get("content", ""))
    if rtype == "attachment":
        # `attachment` payload lives under entry["attachment"] (a dict).
        # Flatten string leaves; skip identifier fields handled in the loop.
        return "\n".join(_extract_strings_from_json(entry.get("attachment", {})))
    if rtype == "system":
        # `system` records carry hook output / compact info / tool errors in
        # both `content` and `compactMetadata`. Mine both.
        chunks: list[str] = []
        content = entry.get("content")
        if isinstance(content, str):
            chunks.append(content)
        chunks.extend(_extract_strings_from_json(entry.get("compactMetadata", {})))
        return "\n".join(chunks)
    if rtype == "file-history-snapshot":
        # `snapshot` holds the file contents Claude saw. Anything inside is fair
        # game for the scanner.
        return "\n".join(_extract_strings_from_json(entry.get("snapshot", {})))
    return ""


class ClaudeCodeScanner(Scanner):
    """Scanner for Claude Code CLI conversation history (~/.claude/projects/)."""

    name = "claude_code"
    display_name = "Claude Code CLI"

    @property
    def _base_path(self) -> Path:
        return Path.home() / ".claude"

    def discover(self) -> list[ConversationRecord]:
        """Return one ConversationRecord per JSONL session file, history file, or task JSON found."""
        records: list[ConversationRecord] = []

        projects_dir = self._base_path / "projects"
        if projects_dir.exists():
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

        # Also scan command history (can contain credentials in CLI args)
        history_path = self._base_path / "history.jsonl"
        if history_path.exists():
            records.append(ConversationRecord(
                source_path=history_path,
                tool=self.name,
                conversation_id="history",
                created_at=datetime.fromtimestamp(
                    history_path.stat().st_mtime, tz=timezone.utc
                ),
                raw={"source_type": "history"},
            ))

        # Also scan task JSON files
        tasks_dir = self._base_path / "tasks"
        if tasks_dir.exists():
            for task_file in tasks_dir.rglob("*.json"):
                records.append(ConversationRecord(
                    source_path=task_file,
                    tool=self.name,
                    conversation_id=task_file.stem,
                    created_at=datetime.fromtimestamp(
                        task_file.stat().st_mtime, tz=timezone.utc
                    ),
                    raw={"source_type": "task"},
                ))

        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Dispatch extraction based on record source type."""
        raw = record.raw or {}
        source_type = raw.get("source_type")

        if source_type == "history":
            return self._extract_history(record)
        elif source_type == "task":
            return self._extract_task(record)
        else:
            return self._extract_session(record)

    def _extract_session(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract text-bearing content from every record type that can carry
        pasted secrets — `user`, `assistant`, `attachment`, `system`, and
        `file-history-snapshot`. Bookkeeping types (`queue-operation`,
        `last-prompt`, `permission-mode`, `ai-title`, `pr-link`) are skipped.
        """
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
                    if entry.get("type") not in _CONTENT_RECORD_TYPES:
                        continue
                    text = _extract_record_text(entry)
                    if text.strip():
                        chunks.append(
                            TextChunk(
                                text=text,
                                position=f"line:{line_num}",
                                record=record,
                            )
                        )
        except OSError:
            logger.warning("Failed to read %s", record.source_path, exc_info=True)
        return chunks

    def _extract_history(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract typed commands from history.jsonl, skipping slash commands."""
        chunks: list[TextChunk] = []
        try:
            with record.source_path.open(encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    display = entry.get("display", "")
                    if display and not display.startswith("/") and len(display) > 4:
                        chunks.append(TextChunk(
                            text=display,
                            position=f"entry:{i}",
                            record=record,
                        ))
        except OSError:
            logger.warning("Failed to read history %s", record.source_path, exc_info=True)
        return chunks

    def _extract_task(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract all string values from a task JSON file."""
        chunks: list[TextChunk] = []
        try:
            data = json.loads(
                record.source_path.read_text(encoding="utf-8", errors="replace")
            )
            strings = _extract_strings_from_json(data)
            combined = "\n".join(strings)
            if combined.strip():
                chunks.append(TextChunk(
                    text=combined,
                    position="task:0",
                    record=record,
                ))
        except (OSError, json.JSONDecodeError):
            logger.warning("Failed to read task %s", record.source_path, exc_info=True)
        return chunks
