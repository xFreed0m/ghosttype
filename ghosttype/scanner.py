from __future__ import annotations

import logging
from datetime import datetime, timezone

from ghosttype.models import Finding
from ghosttype.patterns import scan_text
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)

_HIGH_SEVERITY_TYPES = frozenset({
    "aws_access_key",
    "anthropic_key",
    "openai_token",
    "github_pat_classic",
    "github_pat_fine",
    "github_app_token",
    "stripe_secret_key",
    "private_key_pem",
    "vault_token",
    "heuristic_aws_secret",
    "heuristic_supabase_key",
})


class Orchestrator:
    def __init__(
        self,
        scanners: list[Scanner] | None = None,
        context_window: int = 200,
        max_age_days: int | None = None,
    ) -> None:
        if scanners is None:
            from ghosttype.scanners import SCANNERS
            self._scanners = SCANNERS
        else:
            self._scanners = scanners
        self._context_window = context_window
        self._max_age_days = max_age_days
        self.files_scanned: int = 0

    def run(self, tool_filter: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        self.files_scanned = 0

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

            # Filter records by age if max_age_days is set
            if self._max_age_days is not None:
                from datetime import timedelta
                cutoff = datetime.now(timezone.utc) - timedelta(days=self._max_age_days)
                records = [
                    r for r in records if r.created_at is None or r.created_at >= cutoff
                ]

            self.files_scanned += len({r.source_path for r in records})
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
                        severity = (
                            "critical"
                            if match.secret_type in _HIGH_SEVERITY_TYPES
                            else "high"
                            if match.confidence == "high"
                            else "medium"
                        )
                        findings.append(Finding(
                            tool=scanner.name,
                            secret_type=match.secret_type,
                            secret_value=match.secret_value,
                            file_path=record.source_path,
                            position=f"{chunk.position}:{match.char_offset}",
                            confidence=match.confidence,
                            context=match.context,
                            discovered_at=datetime.now(timezone.utc),
                            severity=severity,
                        ))
        findings.sort(key=lambda f: (0 if f.confidence == "high" else 1, f.secret_type))
        return findings
