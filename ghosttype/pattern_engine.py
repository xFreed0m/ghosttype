"""In-tree regex/heuristic pattern engine adapter.

This wraps the original ghosttype detection layer (`ghosttype.patterns.scan_text`,
30 regex + 10 heuristic patterns with entropy + placeholder + known-example
filtering) and adapts its `PatternMatch` output into `Finding` objects, mirroring
`trufflehog_engine.scan_chunks` so the orchestrator can drive both engines the
same way.

This engine runs entirely offline. It can never set `verified=True` — regex
structure matching cannot confirm a credential is live. Its value is the
heuristic layer: loose variable-name context signals (`password=`,
`secret_key=`, `JWT_SECRET=`, ...) that TruffleHog's structural detectors do
not catch. It complements TruffleHog; it does not replace it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from ghosttype.models import SOURCE_PATTERN, Finding, TextChunk
from ghosttype.patterns import scan_text

DEFAULT_CONTEXT_WINDOW = 200

# Critical-class credential types. Pattern-engine hits are NEVER verified
# (the in-tree engine does no live check), so they follow TruffleHog's
# *unverified* severity scheme for cross-engine consistency: a hit of one of
# these types is `high`, everything else is `medium`. `critical` is reserved
# for VERIFIED critical-class detectors — a state the pattern engine cannot
# reach — so the two engines now agree on the label for the same unverified
# credential type (see trufflehog_engine._severity_for).
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


def _severity_for(secret_type: str, confidence: str) -> str:
    # `confidence` is kept in the signature for caller compatibility but is
    # intentionally unused: the unverified scheme does not branch on it, which
    # is exactly what makes it consistent with trufflehog_engine._severity_for
    # for the unverified case.
    del confidence
    return "high" if secret_type in _HIGH_SEVERITY_TYPES else "medium"


def scan_chunks(
    scanner_name: str,
    chunks: Sequence[TextChunk],
    *,
    context_window: int = DEFAULT_CONTEXT_WINDOW,
    **_ignored,
) -> list[Finding]:
    """Run the in-tree pattern engine over chunks; return Findings.

    Extra keyword args (verify, only_verified, binary, timeout, verbose, ...)
    are accepted and ignored so this is a drop-in peer of
    `trufflehog_engine.scan_chunks`.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for chunk in chunks:
        if not chunk.text.strip():
            continue
        record = chunk.record
        for match in scan_text(chunk.text, context_window):
            dedup_key = (
                match.secret_value,
                str(record.source_path),
                match.secret_type,
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(
                Finding(
                    tool=scanner_name,
                    secret_type=match.secret_type,
                    secret_value=match.secret_value,
                    file_path=record.source_path,
                    position=f"{chunk.position}:{match.char_offset}",
                    confidence=match.confidence,  # "high" | "medium"
                    context=match.context,
                    discovered_at=datetime.now(timezone.utc),
                    severity=_severity_for(match.secret_type, match.confidence),
                    verified=False,  # pattern matching can never verify
                    detector_name="",
                    verification_error=None,
                    extra_data={},
                    source=SOURCE_PATTERN,
                )
            )
    return findings
