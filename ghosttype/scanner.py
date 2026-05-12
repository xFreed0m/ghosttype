from __future__ import annotations

import logging
from datetime import datetime, timezone

from ghosttype.models import Finding
from ghosttype.patterns import scan_text
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, scanners: list[Scanner] | None = None, context_window: int = 200) -> None:
        if scanners is None:
            from ghosttype.scanners import SCANNERS
            self._scanners = SCANNERS
        else:
            self._scanners = scanners
        self._context_window = context_window

    def run(self, tool_filter: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()

        for scanner in self._scanners:
            if tool_filter and scanner.name != tool_filter:
                continue
            if not scanner.is_available():
                continue
            try:
                records = scanner.discover()
            except Exception:
                logger.warning("Scanner %s failed during discover", scanner.name, exc_info=True)
                continue
            for record in records:
                try:
                    chunks = scanner.extract_text(record)
                except Exception:
                    logger.warning(
                        "Scanner %s failed extracting %s", scanner.name, record.source_path, exc_info=True
                    )
                    continue
                for chunk in chunks:
                    for match in scan_text(chunk.text, self._context_window):
                        dedup_key = (match.secret_value, str(record.source_path), match.secret_type)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append(Finding(
                            tool=scanner.name,
                            secret_type=match.secret_type,
                            secret_value=match.secret_value,
                            file_path=record.source_path,
                            position=f"{chunk.position}:{match.char_offset}",
                            confidence=match.confidence,
                            context=match.context,
                            discovered_at=datetime.now(timezone.utc),
                        ))
        return findings
