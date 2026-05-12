from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk


class Scanner(ABC):
    name: str
    display_name: str

    @property
    @abstractmethod
    def _base_path(self) -> Path:
        """Root path for this tool's data directory."""

    def is_available(self) -> bool:
        return self._base_path.exists()

    @abstractmethod
    def discover(self) -> list[ConversationRecord]:
        """Return all conversation records found on this machine."""

    @abstractmethod
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract text chunks from a conversation record."""
