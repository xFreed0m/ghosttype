# Architecture

## Overview

ghosttype is a CLI tool with a plugin-style scanner architecture. Each target AI tool has its own scanner module that knows how to find and read that tool's conversation files. A shared pattern engine (30 regex patterns + 10 heuristic patterns) runs on the extracted text. A thin orchestrator ties scanners, patterns, and reporting together.

## Directory layout

```
ghosttype/
├── cli.py                # click CLI entry point
├── scanner.py            # Orchestrator: discovers -> filters by max_age_days -> extracts -> detects -> reports
├── patterns.py           # 30 regex + 10 heuristic pattern registry; entropy filter; deduplication
├── models.py             # dataclasses: ConversationRecord, TextChunk, PatternMatch, Finding
├── report.py             # CSV + JSON writer; source file copier
└── scanners/
    ├── base.py           # Scanner ABC with _base_path, is_available(), discover(), extract_text()
    ├── __init__.py       # SCANNERS registry
    ├── claude_code.py    # Claude Code CLI (~/.claude/projects/**/*.jsonl + history.jsonl + tasks/**/*.json)
    ├── cursor.py         # Cursor IDE (globalStorage/ + workspaceStorage/*/)
    ├── codex.py          # Codex CLI (~/.codex/ SQLite)
    ├── chatgpt.py        # ChatGPT desktop (.data files, macOS Keychain-backed AES-128-CBC)
    └── claude.py         # Claude desktop (stub; SQLite under ~/Library/Application Support/Claude/)
```

## Data flow

```
CLI invocation (--tool, --format, --output, --max-age-days, etc.)
    |
    v
Orchestrator.run(tool_filter)
    |-- for each registered scanner:
    |       |-- if available: scanner.discover() -> list[ConversationRecord]
    |       |-- filter by max_age_days (if set)
    |       |-- for each record: scanner.extract_text() -> list[TextChunk]
    |       |-- for each chunk: pattern engine scans text
    |
    v
Pattern engine (scan_text)
    |-- run 30 regex patterns (high confidence)
    |-- run 10 heuristic patterns (medium confidence)
    |-- filter by entropy threshold (3.0 bits/char)
    |-- filter known example values
    |-- deduplicate: (secret_value, file_path, secret_type)
    |
    v
Finding list (sorted by severity)
    |
    v
Report writer
    |-- JSON: findings.json (optionally redacted)
    |-- CSV: findings.csv (optionally redacted)
    |-- Sources: copy referenced files to sources/ (if --copy-sources)
    |-- Stdout: (if --output -)
```

## Scanner interface (base.py)

Each scanner implements the `Scanner` ABC:

```python
class Scanner(ABC):
    name: str                            # tool identifier, e.g. "cursor"
    display_name: str                    # human label, e.g. "Cursor IDE"

    @property
    @abstractmethod
    def _base_path(self) -> Path:
        """Root path for this tool's data directory."""

    def is_available(self) -> bool:
        """Return True if this tool's data directory exists."""
        return self._base_path.exists()

    @abstractmethod
    def discover(self) -> list[ConversationRecord]:
        """Return list of discovered conversation records with metadata."""

    @abstractmethod
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract plain text chunks from a conversation record."""
```

`ConversationRecord` carries: `source_path`, `tool`, `conversation_id`, `created_at`, `raw`.

`TextChunk` carries: `text`, `position` (line number or row:offset), `record` (back-reference).

## Pattern engine (patterns.py)

### Layer 1: Regex patterns (30 types, confidence: high)

Known credential formats with exact structure:

**AWS:** aws_access_key (AKIA...), aws_sts_token (ASIA...)

**GitHub:** github_pat_classic (ghp_...), github_pat_fine (github_pat_...), github_app_token (ghs_...), github_user_token (ghu_...), github_oauth_token (gho_...), github_refresh_token (ghr_...)

**OpenAI & Anthropic:** openai_token (sk-proj-..., sk-...), anthropic_key (sk-ant-...)

**Cloud & DevOps:** gcp_service_account, gcp_api_key, stripe_secret_key, stripe_test_key, slack_token, vault_token, sendgrid_key

**Tools & Services:** linear_api_key, databricks_token, npm_token, telegram_bot_token, huggingface_token, digitalocean_token, dockerhub_token, pulumi_token, doppler_token, pypi_token

**Infrastructure:** private_key_pem, jwt, connection_string

### Layer 2: Heuristic patterns (10 types, confidence: medium)

Variable-name context signals that unlock loose value matching:

1. heuristic_api_key: api_key=, apikey=, etc.
2. heuristic_password: password=, passwd=, pwd=
3. heuristic_secret_key: secret_key=, secret=
4. heuristic_token: access_token=, auth_token=, bearer=
5. heuristic_private_key: private_key=
6. heuristic_aws_secret: AWS_SECRET_ACCESS_KEY= (40-char base64)
7. heuristic_jwt_secret: JWT_SECRET=, SIGNING_KEY=, TOKEN_SECRET=
8. heuristic_azure_secret: AZURE_CLIENT_SECRET=, storage_account_key=
9. heuristic_generic_secret: api-secret=, auth-key=, private-token=
10. heuristic_supabase_key: SUPABASE_SERVICE_ROLE_KEY=, SUPABASE_ANON_KEY=

### False positive reduction

- **Entropy filter:** Matches must have >= 3.0 bits/char (filters random garbage)
- **Placeholder filter:** Reject matches starting with: your[-_]?(?:key|secret|api|password|credential), fake[-_]?, test[-_]?, example[-_]?, placeholder[-_]?, demo[-_]?, dummy[-_]?, sample[-_]?
- **Known-examples exclusion:** Hardcoded set of common documentation examples and generated test values

### Deduplication

Two-level dedup per text chunk:
- Regex layer: track (secret_type, value) in seen set
- Heuristic layer: track captured_values to avoid duplicate heuristic matches

Orchestrator-level dedup: (secret_value, file_path, secret_type)

## Finding severity

Findings are classified by severity based on secret type:

**Critical:** aws_access_key, anthropic_key, openai_token, github_pat_classic, github_pat_fine, github_app_token, stripe_secret_key, private_key_pem, vault_token, heuristic_aws_secret, heuristic_supabase_key

**High:** (reserved for future expansion)

**Medium:** all others (heuristic patterns, less-sensitive token types)

Severity filters CLI output and report generation.

## CLI options

All scan options:

```bash
--tool {cursor|chatgpt|codex|claude|claude_code}  # Scan only this tool
--format {json|csv|both}                          # Output format (default: both)
--output OUTPUT                                   # Output directory or - for stdout (default: ./ghosttype_report)
--redact                                          # Redact secret values in files
--context-window N                                # Context chars around match (default: 200)
--copy-sources                                    # Copy source files to output/sources/
--min-confidence {high|medium}                    # Filter by confidence (default: medium)
--allow-list PATH                                 # Suppress known-safe values (one per line)
--stats-only                                      # Print stats only, no findings table
--quiet / -q                                      # Suppress banner and progress
--max-age-days N                                  # Only scan files modified within last N days
```

Special output modes:

- `--output ./dir`: Write findings.json, findings.csv, sources/ to ./dir
- `--output -`: Write findings JSON to stdout only (for piping to jq, etc.)

## Scanner coverage

| Scanner | Data Sources | Format |
|---------|--------------|--------|
| claude_code | ~/.claude/projects/**/*.jsonl + history.jsonl + tasks/**/*.json | JSONL + JSON |
| cursor | ~/.config/Cursor/globalStorage/state.vscdb + workspaceStorage/*/state.vscdb | SQLite |
| codex | ~/.codex/state_5.sqlite + logs_2.sqlite | SQLite |
| chatgpt | ~/Library/Application Support/com.openai.chat/conversations-v3-*/*.data | Binary (AES-128-CBC, Keychain-backed) |
| claude | ~/Library/Application Support/Claude/ (stub implementation) | SQLite |

## Adding a new scanner

1. Create `ghosttype/scanners/<toolname>.py`
2. Implement the Scanner ABC: define `name`, `display_name`, `_base_path` property, and override `discover()` and `extract_text()`
3. Register in `ghosttype/scanners/__init__.py` by adding an instance to the SCANNERS list
4. No changes needed to orchestrator, patterns, or CLI
