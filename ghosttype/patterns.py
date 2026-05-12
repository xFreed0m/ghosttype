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
    # GitHub App tokens (server-to-server, user-to-server)
    ("github_app_token", re.compile(r"\b(ghs_[a-zA-Z0-9]{36})\b")),
    ("github_user_token", re.compile(r"\b(ghu_[a-zA-Z0-9]{36})\b")),
    # HashiCorp Vault tokens (service, batch, recovery)
    ("vault_token", re.compile(r"\b(hv[sbr]\.[a-zA-Z0-9]{24,})\b")),
    # Linear API keys
    ("linear_api_key", re.compile(r"\b(lin_api_[a-zA-Z0-9]{40})\b")),
    # Databricks personal access tokens
    ("databricks_token", re.compile(r"\b(dapi[a-zA-Z0-9]{32})\b")),
    # npm automation tokens
    ("npm_token", re.compile(r"\b(npm_[a-zA-Z0-9]{36,})\b")),
    # Telegram bot tokens
    ("telegram_bot_token", re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_-]{34,})\b")),
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
    # Azure storage/AD credentials (high-entropy base64 with keyword context)
    (
        "heuristic_azure_secret",
        re.compile(
            r"(?i)(?:AZURE_CLIENT_SECRET|client_secret|AZURE_STORAGE_KEY|storage_account_key|AccountKey)\s*[=:]\s*[\"']?([A-Za-z0-9+/]{32,}={0,2})[\"']?"
        ),
    ),
]

# Placeholder patterns that indicate a fake or example credential value.
# Anchored at start — these stems indicate a placeholder prefix regardless of suffix.
_PLACEHOLDER_STEMS = _re.compile(
    r"^(?:your[-_]?(?:key|token|secret|api[-_]?key|password|credential)|"
    r"insert[-_]?(?:key|token|secret|password)|"
    r"replace[-_]?(?:with|me|this)|"
    r"<[^>]+>|</[^>]+>)",              # HTML tags
    _re.IGNORECASE,
)

# Exact-match known placeholder strings (full string must match)
_PLACEHOLDER_EXACT = _re.compile(
    r"^(?:example|test|demo|placeholder|changeme|"
    r"xxx+|yyy+|aaa+|000+|none|null|undefined|"
    r"my[-_]?(?:key|token|secret|password|api[-_]?key)|"
    r"secret[-_]?here|key[-_]?here|token[-_]?here|password[-_]?here|"
    r"some[-_]?(?:password|secret|token|key)|"
    r"actual[-_]?(?:password|secret|token|key)|"
    r"user[-_]?(?:password|secret|token)|"
    r"fake[-_]?(?:key|token|secret)|"
    r"sample[-_]?(?:key|token|secret))$",
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
    if _PLACEHOLDER_STEMS.match(value):
        return True
    if _PLACEHOLDER_EXACT.match(value):
        return True
    # HTML-like content
    if value.startswith("<") or value.startswith("</"):
        return True
    if value.endswith(">") or value.endswith("/>"):
        return True
    # Common placeholder suffixes (your-key-here, insert-token-here, etc.)
    if _re.search(r'[-_](?:here|there|goes|value|placeholder|example|token|key|secret)$', value, _re.IGNORECASE):
        return True
    # Real credentials have entropy > 3.0 bits/char (industry standard from gitleaks/detect-secrets)
    if _shannon_entropy(value) < 3.0:
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
