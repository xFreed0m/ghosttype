from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ConversationRecord:
    source_path: Path
    tool: str
    conversation_id: str
    created_at: datetime | None
    raw: Any  # dict or bytes depending on scanner


@dataclass
class TextChunk:
    text: str
    position: str  # "line:N" for JSONL; "<row_key>:<char_offset>" for SQLite
    record: ConversationRecord


@dataclass
class PatternMatch:
    secret_type: str
    secret_value: str
    confidence: str  # "high" or "medium"
    context: str
    char_offset: int


@dataclass
class Finding:
    tool: str
    secret_type: str
    secret_value: str
    file_path: Path
    position: str
    confidence: str
    context: str
    discovered_at: datetime
    severity: str = "medium"
