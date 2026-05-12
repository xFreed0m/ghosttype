from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class CursorScanner(Scanner):
    """Scanner for Cursor IDE conversation history (SQLite state.vscdb)."""

    name = "cursor"
    display_name = "Cursor IDE"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage"

    @property
    def _db_path(self) -> Path:
        return self._base_path / "state.vscdb"

    def is_available(self) -> bool:
        return self._db_path.exists()

    def discover(self) -> list[ConversationRecord]:
        """Return one ConversationRecord per composerData entry found."""
        if not self.is_available():
            return []
        records: list[ConversationRecord] = []
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
            rows = conn.execute(
                "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'"
            ).fetchall()
            conn.close()
        except sqlite3.Error:
            return []

        for key, value in rows:
            if not value:
                continue
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                continue
            composer_id = data.get("composerId", key.split(":", 1)[-1])
            created_ms = data.get("createdAt")
            created_at = (
                datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
                if created_ms
                else None
            )
            records.append(ConversationRecord(
                source_path=self._db_path,
                tool=self.name,
                conversation_id=composer_id,
                created_at=created_at,
                raw={"key": key, "data": data},
            ))
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract text chunks from a conversation record."""
        raw = record.raw or {}
        key = raw.get("key", f"composerData:{record.conversation_id}")
        data = raw.get("data", {})
        chunks: list[TextChunk] = []

        # Primary: plain text field
        text = data.get("text", "")
        if text.strip():
            chunks.append(TextChunk(
                text=text,
                position=f"{key}:0",
                record=record,
            ))

        # Secondary: walk conversationMap for individual message texts
        conv_map = data.get("conversationMap", {})
        for msg_id, msg in conv_map.items():
            if not isinstance(msg, dict):
                continue
            msg_text = msg.get("text", "") or msg.get("content", "")
            if isinstance(msg_text, str) and msg_text.strip():
                chunks.append(TextChunk(
                    text=msg_text,
                    position=f"{key}:msg:{msg_id}",
                    record=record,
                ))

        return chunks
