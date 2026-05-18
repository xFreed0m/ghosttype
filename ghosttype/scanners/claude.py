from __future__ import annotations

from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class ClaudeScanner(Scanner):
    """Stub. The directory exists on most installs but the storage format
    has not been reverse-engineered yet. `is_available()` returns False so
    `list-tools` and the orchestrator don't advertise coverage we don't have.
    """

    name = "claude"
    display_name = "Claude Desktop"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "Claude"

    def is_available(self) -> bool:
        # Until extraction is implemented, do not advertise this scanner as
        # active — `_base_path` exists on every install, which is misleading.
        return False

    def discover(self) -> list[ConversationRecord]:
        return []

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        return []
