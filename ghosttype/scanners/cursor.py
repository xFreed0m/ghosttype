from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)


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

    def _workspace_dbs(self) -> list[Path]:
        """Return all workspace state.vscdb paths under workspaceStorage."""
        ws_root = (
            Path.home()
            / "Library"
            / "Application Support"
            / "Cursor"
            / "User"
            / "workspaceStorage"
        )
        if not ws_root.exists():
            return []
        return list(ws_root.rglob("state.vscdb"))

    def _query_db(self, db_path: Path) -> list[ConversationRecord]:
        """Query a single Cursor SQLite DB and return ConversationRecords."""
        records: list[ConversationRecord] = []
        try:
            # `with sqlite3.connect(...)` only commits/rolls back the
            # transaction; it does NOT close the connection. Wrap in
            # contextlib.closing so the handle is released deterministically
            # instead of leaking until GC (ResourceWarning under -W error).
            with closing(
                sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            ) as conn:
                rows = conn.execute(
                    "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'"
                ).fetchall()
        except sqlite3.OperationalError as e:
            # Workspace storage DBs that don't use Cursor's Composer won't have
            # this table — silently skip them.
            if "no such table" in str(e).lower():
                logger.debug("Skipping %s: no cursorDiskKV table", db_path)
            else:
                logger.warning("Failed to read cursor db %s", db_path, exc_info=True)
            return []
        except sqlite3.Error:
            logger.warning("Failed to read cursor db %s", db_path, exc_info=True)
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
                source_path=db_path,
                tool=self.name,
                conversation_id=composer_id,
                created_at=created_at,
                raw={"key": key, "data": data},
            ))
        return records

    def discover(self) -> list[ConversationRecord]:
        """Return one ConversationRecord per composerData entry found.

        Scans the global storage DB and all workspace storage DBs.
        """
        if not self.is_available():
            return []
        records = self._query_db(self._db_path)

        for ws_db in self._workspace_dbs():
            records.extend(self._query_db(ws_db))

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
