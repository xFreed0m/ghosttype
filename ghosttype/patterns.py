from __future__ import annotations

import math
import re
import re as _re

from ghosttype.models import PatternMatch

# Layer 1: known credential formats (confidence: high)
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    # OpenAI tokens: classic sk- and newer sk-proj- formats.
    # Negative lookahead (?!ant-) prevents overlap with anthropic_key (sk-ant-...).
    ("openai_token", re.compile(r"\b(sk-(?!ant-)(?:proj-)?[a-zA-Z0-9\-_]{20,})\b")),
    ("github_pat_classic", re.compile(r"\b(ghp_[a-zA-Z0-9]{36,})\b")),
    ("github_pat_fine", re.compile(r"\b(github_pat_[a-zA-Z0-9_]{82})\b")),
    ("anthropic_key", re.compile(r"\b(sk-ant-[a-zA-Z0-9\-]{20,})\b")),
    (
        "gcp_service_account",
        re.compile(
            r"\b([a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com)\b"
        ),
    ),
    # Negative lookbehind: don't match when PEM header is inside a quoted string or backtick block.
    ("private_key_pem", re.compile(r'(?<!["\'`])(-----BEGIN [A-Z ]+PRIVATE KEY-----)')),
    (
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b"
        ),
    ),
    (
        "connection_string",
        re.compile(
            r"((?:postgresql|mysql|mongodb|redis)://[^\s\"\'<>`\n]{8,})"
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
    # Linear API keys (alphanumeric, underscores and hyphens allowed in practice)
    ("linear_api_key", re.compile(r"\b(lin_api_[a-zA-Z0-9_-]{38,44})\b")),
    # Databricks personal access tokens
    ("databricks_token", re.compile(r"\b(dapi[a-zA-Z0-9]{32})\b")),
    # npm automation tokens
    ("npm_token", re.compile(r"\b(npm_[a-zA-Z0-9]{36,})\b")),
    # Telegram bot tokens
    ("telegram_bot_token", re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_-]{34,})\b")),
    # Hugging Face tokens
    ("huggingface_token", re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b")),
    # DigitalOcean personal access tokens
    ("digitalocean_token", re.compile(r"\b(dop_v1_[a-zA-Z0-9]{64})\b")),
    # GitHub OAuth access tokens
    ("github_oauth_token", re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b")),
    # GitHub refresh tokens
    ("github_refresh_token", re.compile(r"\b(ghr_[a-zA-Z0-9]{76})\b")),
    # GCP API keys (browser/server keys)
    ("gcp_api_key",         re.compile(r"\b(AIzaSy[a-zA-Z0-9_-]{33})\b")),
    # AWS STS temporary tokens (ASIA prefix)
    ("aws_sts_token",       re.compile(r"(?<![A-Z0-9])(ASIA[0-9A-Z]{16})(?![A-Z0-9])")),
    # Docker Hub personal access tokens
    ("dockerhub_token",     re.compile(r"\b(dckr_pat_[a-zA-Z0-9_-]{20,})\b")),
    # Pulumi access tokens
    ("pulumi_token",        re.compile(r"\b(pul-[a-zA-Z0-9]{40})\b")),
    # Doppler service tokens
    ("doppler_token",       re.compile(r"\b(dp\.st\.[a-zA-Z0-9]{43})\b")),
    # PyPI API tokens
    ("pypi_token",          re.compile(r"\b(pypi-[a-zA-Z0-9_-]{100,})\b")),
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
    # Generic high-entropy API key/secret triggered by strong keyword context
    (
        "heuristic_generic_secret",
        re.compile(
            r"(?i)(?:api[_-]?(?:key|token|secret)|auth[_-]?(?:key|token)|private[_-]?token|access[_-]?key)\s*[=:]\s*[\"']?([a-zA-Z0-9+/=_-]{32,})[\"']?"
        ),
    ),
    # Supabase service role and anon keys (long JWTs with specific structure)
    (
        "heuristic_supabase_key",
        re.compile(
            r"(?i)(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_ANON_KEY|supabase_key)\s*[=:]\s*[\"']?(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})[\"']?"
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


# Well-known documentation/example credential values that should never be reported.
# These appear in official docs, tutorials, and test suites worldwide.
_KNOWN_EXAMPLE_VALUES: frozenset[str] = frozenset({
    # AWS documentation canonical example credentials
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIAIOSFODNN7EXAMPLE",
    # AWS STS docs canonical example token prefix
    "ASIAIOSFODNN7EXAMPLE",
    # Famous test passwords
    "hunter2supersecretvalue",
    "hunter2",
    "correcthorsebatterystaple",
    # JWT examples from jwt.io
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    # Generic doc examples
    "mysecretpassword123",
    "mysupersecretkey",
    "thisisasecret",
    # Common tutorial values
    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
    "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK12",
    "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghp_xYzAbCdEfGhIjKlMnOpQrStUvWxYz12345678",
    "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
    "hvs.CvmS4c0DPTvHv5eJgXWMJg9rABC123xyz",
    "lin_api_abcdefghijklmnopqrstuvwxyz1234567890ab12",
    "dapi1234567890abcdef1234567890abcdef",
    "npm_1234567890abcdefghijklmnopqrstuvwxyz",
    "123456789:AABBccDDeeffGGhhIIjjKKllMMnnOOppQQrr",
    # Common test connection strings
    "postgresql://user:password@localhost:5432/mydb",
    "postgresql://user:password@localhost/mydb",
    "mysql://user:password@localhost:3306/mydb",
    "mongodb://user:password@localhost:27017/mydb",
    # GCP API key test value
    "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567",
})


def _is_likely_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder, not a real credential."""
    if len(value) < 8:
        return True
    if value in _KNOWN_EXAMPLE_VALUES:
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
            if value in _KNOWN_EXAMPLE_VALUES:
                continue
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

    # Tracks all captured values (regex + heuristic) to prevent cross-layer duplication.
    # Updated as heuristics fire so later heuristics don't re-report the same value.
    captured_values: set[str] = {m.secret_value for m in matches}

    for secret_type, pattern in _HEURISTIC_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            # Skip if already captured by any earlier pattern (regex or heuristic).
            if value in captured_values:
                continue
            # Filter out placeholder/example values to reduce false positives.
            if _is_likely_placeholder(value):
                continue
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            captured_values.add(value)  # mark so subsequent heuristics skip this value
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
