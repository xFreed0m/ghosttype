# Architecture

## Overview

ghosttype is a CLI tool with a plugin-style scanner architecture. Each target AI tool has its own scanner module that knows how to find and read that tool's conversation files. A shared pattern engine runs on the extracted text. A thin orchestrator ties them together.

```
ghosttype/
├── cli.py              # click CLI entry point
├── scanner.py          # orchestrator: discovers -> extracts -> detects -> reports
├── patterns.py         # compiled regex + heuristic pattern registry
├── report.py           # CSV + JSON writer
└── scanners/
    ├── base.py         # Scanner ABC
    ├── cursor.py       # Cursor IDE (state.vscdb SQLite)
    ├── chatgpt.py      # ChatGPT desktop (.data files, macOS Keychain-backed)
    ├── codex.py        # Codex CLI (~/.codex/ SQLite)
    ├── claude.py       # Claude desktop app (SQLite)
    └── claude_code.py  # Claude Code CLI (~/.claude/projects/ JSONL)
```

---

## Data flow

```
CLI invocation
    |
    v
Orchestrator (scanner.py)
    |-- iterates registered scanner plugins
    |       |
    |       v
    |   scanner.discover() -> list[Path | ConversationRecord]
    |       |
    |       v
    |   scanner.extract_text(record) -> list[TextChunk]
    |
    v
Pattern engine (patterns.py)
    |-- run regex patterns against each chunk
    |-- run heuristic patterns against each chunk
    |-- deduplicate by (value, file_path)
    |
    v
Report writer (report.py)
    |-- write findings.json
    |-- write findings.csv
    |-- write summary to stdout
```

---

## Scanner interface (base.py)

Each scanner implements the `Scanner` ABC:

```python
class Scanner(ABC):
    name: str                    # tool identifier, e.g. "cursor"
    display_name: str            # human label, e.g. "Cursor IDE"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this tool's data directory exists on the current machine."""

    @abstractmethod
    def discover(self) -> list[ConversationRecord]:
        """Return list of discovered conversation records with metadata."""

    @abstractmethod
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract plain text chunks from a conversation record."""
```

`ConversationRecord` carries: `source_path`, `tool`, `conversation_id`, `created_at`, `raw` (bytes or dict).

`TextChunk` carries: `text`, `position`, `record` (back-reference).

---

## Pattern engine (patterns.py)

Two layers:

**Layer 1 - Regex (high confidence)**

Known credential formats with named groups:

```python
PATTERNS = {
    "aws_access_key":      r'(?P<val>AKIA[0-9A-Z]{16})',
    "aws_secret_key":      r'(?P<val>[0-9a-zA-Z/+]{40})',  # context-gated
    "openai_token":        r'(?P<val>sk-[a-zA-Z0-9]{48,})',
    "github_pat_classic":  r'(?P<val>ghp_[a-zA-Z0-9]{36})',
    "github_pat_fine":     r'(?P<val>github_pat_[a-zA-Z0-9_]{82})',
    "anthropic_key":       r'(?P<val>sk-ant-[a-zA-Z0-9\-]{95,})',
    "gcp_service_account": r'(?P<val>[a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com)',
    "private_key_pem":     r'(?P<val>-----BEGIN [A-Z ]+PRIVATE KEY-----)',
    "jwt":                 r'(?P<val>eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',
    "connection_string":   r'(?P<val>(?:postgresql|mysql|mongodb|redis)://[^\s"\'<>]+)',
    "generic_api_key":     r'(?i)(?P<val>[a-zA-Z0-9]{32,64})',  # heuristic-gated
}
```

**Layer 2 - Heuristic (medium confidence)**

Variable name context signals that unlock loose value matching:

```python
HEURISTIC_SIGNALS = [
    r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']?(?P<val>[^\s"\']{8,})',
    r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?(?P<val>[^\s"\']{6,})',
    r'(?i)(?:secret[_\-]?key|secret)\s*[=:]\s*["\']?(?P<val>[^\s"\']{8,})',
    r'(?i)(?:access[_\-]?token|auth[_\-]?token|bearer)\s*[=:]\s*["\']?(?P<val>[^\s"\']{8,})',
    r'(?i)(?:private[_\-]?key)\s*[=:]\s*["\']?(?P<val>[^\s"\']{8,})',
]
```

---

## Report output

All findings are written to the output directory (default: `./ghosttype_report/`):

```
ghosttype_report/
├── findings.json        # full detail, secret values in plaintext
├── findings.csv         # tabular, secret values redacted by default (--no-redact to disable)
└── sources/             # copies of source conversation files referenced in findings
    └── <tool>/<hash>.{jsonl,sqlite,data,...}
```

The `sources/` copy allows offline review and is what red teamers hand off as loot evidence and what blue teamers hand to the credential rotation team.

---

## Adding a new scanner

1. Create `ghosttype/scanners/<toolname>.py`
2. Implement the `Scanner` ABC
3. Register in `ghosttype/scanners/__init__.py`

No changes needed to the orchestrator or pattern engine.
