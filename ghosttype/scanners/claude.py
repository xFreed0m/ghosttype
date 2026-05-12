from __future__ import annotations

from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class ClaudeScanner(Scanner):
    name = "claude"
    display_name = "Claude Desktop"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "Claude"

    def discover(self) -> list[ConversationRecord]:
        # Storage format unconfirmed - app not available for research.
        # Returns empty until format is investigated and implemented.
        return []

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        return []
