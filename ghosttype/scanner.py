from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ghosttype.models import ConversationRecord, Finding, SOURCE_TRUFFLEHOG
from ghosttype.scanners.base import Scanner
from ghosttype import pattern_engine
from ghosttype.trufflehog_engine import (
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_TIMEOUT_SECONDS,
    scan_chunks as trufflehog_scan_chunks,
)

logger = logging.getLogger(__name__)

# Valid --engine values.
ENGINE_BOTH = "both"
ENGINE_TRUFFLEHOG = "trufflehog"
ENGINE_PATTERNS = "patterns"
ENGINES = (ENGINE_BOTH, ENGINE_TRUFFLEHOG, ENGINE_PATTERNS)


class Orchestrator:
    """Discover conversation files via per-tool scanners, then run the
    selected detection engine(s) over the extracted text.

    Two engines, complementary:
      - TruffleHog: 800+ structural detectors WITH live verification.
      - In-tree patterns: 30 regex + 10 heuristic patterns, offline,
        unverifiable, but catches loose variable-name context signals
        (`password=`, `secret_key=`) that TruffleHog's structural
        detectors miss.

    When `engine="both"` (default), both run on the same chunks and results
    are merged. If the same secret value in the same file is found by both,
    the TruffleHog finding wins (it carries verification + detector metadata);
    pattern-only hits are kept as the heuristic safety net.
    """

    def __init__(
        self,
        scanners: list[Scanner] | None = None,
        context_window: int = DEFAULT_CONTEXT_WINDOW,
        max_age_days: int | None = None,
        *,
        engine: str = ENGINE_BOTH,
        verify: bool = True,
        only_verified: bool = False,
        trufflehog_binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        verbose: bool = False,
    ) -> None:
        if engine not in ENGINES:
            raise ValueError(f"engine must be one of {ENGINES}, got {engine!r}")
        if scanners is None:
            from ghosttype.scanners import SCANNERS
            self._scanners = SCANNERS
        else:
            self._scanners = scanners
        self._context_window = context_window
        self._max_age_days = max_age_days
        self._engine = engine
        self._verify = verify
        self._only_verified = only_verified
        self._trufflehog_binary = trufflehog_binary
        self._timeout = timeout
        self._verbose = verbose
        self.files_scanned: int = 0
        self.chunks_scanned: int = 0

    @property
    def uses_trufflehog(self) -> bool:
        return self._engine in (ENGINE_BOTH, ENGINE_TRUFFLEHOG)

    @property
    def uses_patterns(self) -> bool:
        return self._engine in (ENGINE_BOTH, ENGINE_PATTERNS)

    def _run_engines(self, scanner_name: str, chunks: list) -> list[Finding]:
        """Run the selected engine(s) over one scanner's chunks and merge.

        TruffleHog findings take precedence over pattern findings on a
        (secret_value, file_path) collision so verified metadata isn't lost.
        """
        th_findings: list[Finding] = []
        pat_findings: list[Finding] = []

        if self.uses_trufflehog:
            th_findings = trufflehog_scan_chunks(
                scanner_name,
                chunks,
                verify=self._verify,
                only_verified=self._only_verified,
                binary=self._trufflehog_binary,
                timeout=self._timeout,
                context_window=self._context_window,
                verbose=self._verbose,
            )
            if self._verbose:
                logger.info(
                    "scanner %s: trufflehog returned %d findings",
                    scanner_name, len(th_findings),
                )

        if self.uses_patterns:
            pat_findings = pattern_engine.scan_chunks(
                scanner_name, chunks, context_window=self._context_window
            )
            if self._verbose:
                logger.info(
                    "scanner %s: pattern engine returned %d findings",
                    scanner_name, len(pat_findings),
                )

        # Cross-engine dedup: drop pattern findings whose (value, file) is
        # already covered by TruffleHog (which may have verified it).
        th_keys = {(f.secret_value, str(f.file_path)) for f in th_findings}
        kept_pat = [
            f for f in pat_findings
            if (f.secret_value, str(f.file_path)) not in th_keys
        ]
        if self._verbose and self.uses_trufflehog and self.uses_patterns:
            logger.info(
                "scanner %s: %d pattern findings kept after TruffleHog overlap dedup "
                "(%d shadowed)",
                scanner_name, len(kept_pat), len(pat_findings) - len(kept_pat),
            )
        return th_findings + kept_pat

    def run(self, tool_filter: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        self.files_scanned = 0
        self.chunks_scanned = 0
        cutoff: datetime | None = None
        if self._max_age_days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._max_age_days)

        for scanner in self._scanners:
            if tool_filter and scanner.name != tool_filter:
                continue
            if not scanner.is_available():
                continue
            try:
                records: list[ConversationRecord] = scanner.discover()
            except Exception:
                logger.warning(
                    "Scanner %s failed during discover", scanner.name, exc_info=True
                )
                continue

            if cutoff is not None:
                records = [
                    r for r in records if r.created_at is None or r.created_at >= cutoff
                ]
            if not records:
                continue
            self.files_scanned += len({r.source_path for r in records})

            chunks = []
            for record in records:
                try:
                    chunks.extend(scanner.extract_text(record))
                except Exception:
                    logger.warning(
                        "Scanner %s failed extracting %s",
                        scanner.name,
                        record.source_path,
                        exc_info=True,
                    )
                    continue
            if not chunks:
                if self._verbose:
                    logger.info(
                        "scanner %s discovered %d record(s) but extracted 0 text chunks",
                        scanner.name, len(records),
                    )
                continue

            self.chunks_scanned += len(chunks)
            if self._verbose:
                logger.info(
                    "scanner %s: %d records -> %d chunks; engine=%s",
                    scanner.name, len(records), len(chunks), self._engine,
                )

            for f in self._run_engines(scanner.name, chunks):
                dedup_key = (f.secret_value, str(f.file_path), f.secret_type)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

        # verified first, then unverified-trufflehog, then pattern; stable by type
        def sort_key(f: Finding):
            if f.verified:
                rank = 0
            elif f.source == SOURCE_TRUFFLEHOG:
                rank = 1
            else:
                rank = 2
            return (rank, f.secret_type)

        findings.sort(key=sort_key)
        return findings
