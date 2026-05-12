from __future__ import annotations

import re

from ghosttype.models import PatternMatch

# Layer 1: known credential formats (confidence: high)
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("openai_token", re.compile(r"(?<![a-zA-Z0-9])(sk-[a-zA-Z0-9]{48,})(?![a-zA-Z0-9])")),
    ("github_pat_classic", re.compile(r"\b(ghp_[a-zA-Z0-9]{36,})\b")),
    ("github_pat_fine", re.compile(r"\b(github_pat_[a-zA-Z0-9_]{82})\b")),
    ("anthropic_key", re.compile(r"\b(sk-ant-[a-zA-Z0-9\-]{20,})\b")),
    (
        "gcp_service_account",
        re.compile(
            r"\b([a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com)\b"
        ),
    ),
    ("private_key_pem", re.compile(r"(-----BEGIN [A-Z ]+PRIVATE KEY-----)")),
    (
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b"
        ),
    ),
    (
        "connection_string",
        re.compile(
            r"((?:postgresql|mysql|mongodb|redis)://[^\s\"\'<>\n]{8,})"
        ),
    ),
]

# Layer 2: variable-name context signals (confidence: medium)
_HEURISTIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "heuristic_api_key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
    (
        "heuristic_password",
        re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']?([^\s\"']{6,})"
        ),
    ),
    ("heuristic_secret_key", re.compile(r'(?i)(?:secret[_\-]?key)\s*[=:]\s*["\']?([^\s"\']{8,})')),
    (
        "heuristic_token",
        re.compile(
            r"(?i)(?:access[_\-]?token|auth[_\-]?token|bearer)\s*[=:]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
    (
        "heuristic_private_key",
        re.compile(
            r"(?i)(?:private[_\-]?key)\s*[=:]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
]


def _extract_context(text: str, start: int, end: int, window: int) -> str:
    """Return a context snippet centered on the match span."""
    half = window // 2
    ctx_start = max(0, start - half)
    ctx_end = min(len(text), end + half)
    return text[ctx_start:ctx_end]


def scan_text(text: str, context_window: int = 200) -> list[PatternMatch]:
    """Scan text for credential patterns. Returns deduplicated PatternMatch list.

    context_window controls the number of surrounding characters captured.
    For matches longer than context_window, the returned context will be larger.

    Two detection layers are applied:
    - Regex patterns (confidence: "high") for known credential formats.
    - Heuristic patterns (confidence: "medium") for variable-name context signals.
    """
    matches: list[PatternMatch] = []
    seen: set[tuple[str, str]] = set()

    for secret_type, pattern in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                PatternMatch(
                    secret_type=secret_type,
                    secret_value=value,
                    confidence="high",
                    context=_extract_context(
                        text, m.start(1), m.end(1), context_window
                    ),
                    char_offset=m.start(1),
                )
            )

    # Collect high-confidence values for dedup across layers.
    high_confidence_values: set[str] = {m.secret_value for m in matches}

    for secret_type, pattern in _HEURISTIC_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            # Skip if already captured by a high-confidence pattern.
            if value in high_confidence_values:
                continue
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                PatternMatch(
                    secret_type=secret_type,
                    secret_value=value,
                    confidence="medium",
                    context=_extract_context(
                        text, m.start(1), m.end(1), context_window
                    ),
                    char_offset=m.start(1),
                )
            )

    return matches
