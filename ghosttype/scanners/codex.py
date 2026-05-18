from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)


class CodexScanner(Scanner):
    """Scanner for Codex CLI conversation history (~/.codex/ SQLite databases)."""

    name = "codex"
    display_name = "Codex CLI"

    @property
    def _base_path(self) -> Path:
        return Path.home() / ".codex"

    def _state_db(self) -> Path:
        return self._base_path / "state_5.sqlite"

    def _logs_db(self) -> Path:
        return self._base_path / "logs_2.sqlite"

    def discover(self) -> list[ConversationRecord]:
        """Return one ConversationRecord per thread found in state_5.sqlite."""
        state_db = self._state_db()
        if not state_db.exists():
            return []
        records: list[ConversationRecord] = []
        try:
            # contextlib.closing: `with sqlite3.connect(...)` manages the
            # transaction, not the connection lifetime. Without closing()
            # the handle leaks until GC (ResourceWarning under -W error).
            with closing(
                sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
            ) as conn:
                rows = conn.execute(
                    "SELECT id, title, first_user_message, created_at FROM threads"
                ).fetchall()
        except sqlite3.Error:
            return []

        for thread_id, title, first_msg, created_ts in rows:
            created_at = (
                datetime.fromtimestamp(created_ts, tz=timezone.utc)
                if created_ts
                else None
            )
            records.append(ConversationRecord(
                source_path=state_db,
                tool=self.name,
                conversation_id=thread_id,
                created_at=created_at,
                raw={"thread_id": thread_id, "title": title, "first_user_message": first_msg},
            ))
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract text chunks from a conversation record.

        Extracts from:
        - first_user_message in the raw record (from state_5.sqlite)
        - feedback_log_body entries from logs_2.sqlite (if thread_id match exists)
        """
        raw = record.raw or {}
        thread_id = raw.get("thread_id", record.conversation_id)
        chunks: list[TextChunk] = []

        first_msg = raw.get("first_user_message", "")
        if first_msg and first_msg.strip():
            chunks.append(TextChunk(
                text=first_msg,
                position=f"{thread_id}:first_user_message",
                record=record,
            ))

        # Also scan logs_2.sqlite for this thread's log body
        logs_db = self._logs_db()
        if logs_db.exists():
            try:
                with closing(
                    sqlite3.connect(f"file:{logs_db}?mode=ro", uri=True)
                ) as conn:
                    # thread_id is stored in logs via thread_id column if present
                    # Try with thread_id filter; if column doesn't exist, skip
                    try:
                        rows = conn.execute(
                            "SELECT feedback_log_body FROM logs WHERE thread_id = ? AND feedback_log_body IS NOT NULL",
                            (thread_id,),
                        ).fetchall()
                    except sqlite3.OperationalError:
                        # thread_id column may not exist in all versions
                        rows = []
                for (body,) in rows:
                    if body and body.strip():
                        chunks.append(TextChunk(
                            text=body,
                            position=f"{thread_id}:log_body",
                            record=record,
                        ))
            except sqlite3.Error:
                logger.warning("Failed to read logs db %s", logs_db, exc_info=True)

        return chunks
