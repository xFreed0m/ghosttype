from __future__ import annotations

import math
import re
import re as _re

from ghosttype.models import PatternMatch

# Layer 1: known credential formats (confidence: high)
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    # OpenAI tokens: classic sk- and newer sk-proj- formats
    ("openai_token", re.compile(r"\b(sk-(?:proj-)?[a-zA-Z0-9\-_]{20,})\b")),
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
    # Stripe keys
    ("stripe_secret_key", re.compile(r"\b(sk_live_[a-zA-Z0-9]{24,})\b")),
    ("stripe_test_key", re.compile(r"\b(sk_test_[a-zA-Z0-9]{24,})\b")),
    # Slack tokens
    ("slack_token", re.compile(r"\b(xox[bpas]-[0-9a-zA-Z\-]{10,})\b")),
    # SendGrid
    ("sendgrid_key", re.compile(r"\b(SG\.[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,})\b")),
]

# Layer 2: variable-name context signals (confidence: medium)
_HEURISTIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "heuristic_api_key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
    # Negative lookbehind prevents matching inside HTML tags or compound
    # variable names (e.g. user_password where _ precedes "password").
    # Value chars exclude < and > to avoid HTML content matches.
    (
        "heuristic_password",
        re.compile(
            r"(?i)(?<![<\w])(?:password|passwd|pwd)\s*[=:]\s*[\"']?([^\s\"'<>]{8,})"
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
    # AWS Secret Access Key (40-char base64, needs variable-name context)
    (
        "heuristic_aws_secret",
        re.compile(
            r"(?i)(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\s*[=:]\s*[\"']?([A-Za-z0-9/+]{40})[\"']?"
        ),
    ),
    # JWT signing secrets
    (
        "heuristic_jwt_secret",
        re.compile(
            r"(?i)(?:JWT_SECRET|jwt_secret|SIGNING_KEY|signing_key|TOKEN_SECRET|token_secret)\s*[=:]\s*[\"']?([^\s\"']{8,})"
        ),
    ),
]

# Placeholder patterns that indicate a fake or example credential value.
_PLACEHOLDER_PATTERNS = _re.compile(
    r"^(?:your[-_]?(?:key|token|secret|api[-_]?key)|"
    r"example|test|demo|placeholder|changeme|"
    r"<[^>]+>|</[^>]+>|"  # HTML tags
    r"xxx+|yyy+|aaa+|000+|"  # repeated chars
    r"insert[-_]?here|replace[-_]?me|"
    r"my[-_]?(?:key|token|secret|password)|"
    r"secret[-_]?here|key[-_]?here|"
    r"user[-_]?password|user[-_]?secret|user[-_]?token|"  # code-example variable names
    r"some[-_]?(?:password|secret|token|key)|"
    r"actual[-_]?(?:password|secret|token|key))$",
    _re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in freq.values())


def _is_likely_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder, not a real credential."""
    if len(value) < 8:
        return True
    if _PLACEHOLDER_PATTERNS.match(value):
        return True
    # Real passwords/keys have entropy > 2.0 bits/char.
    if _shannon_entropy(value) < 2.0:
        return True
    # HTML-like content
    if value.startswith("<") or value.startswith("</"):
        return True
    if value.endswith(">") or value.endswith("/>"):
        return True
    return False


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
      Heuristic matches are filtered through _is_likely_placeholder to reduce FPs.
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
            # Filter out placeholder/example values to reduce false positives.
            if _is_likely_placeholder(value):
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
