# ghosttype

A local forensic scanner that discovers AI conversation stores on a machine, extracts credentials and secrets from them, and produces a structured report with each finding linked to its source file.

> **Authorized use only.** ghosttype is a research tool for licensed penetration testers, red teams, and DLP/blue teams operating under explicit written authorization. Use against systems you do not own or have permission to test is illegal. See [THREAT-MODEL.md](THREAT-MODEL.md).

---

## What it does

ghosttype walks the local filesystem looking for conversation history files from known AI tools:

- **Cursor** - chat and composer history (SQLite `state.vscdb`)
- **ChatGPT desktop** - conversation `.data` files (encrypted, macOS Keychain-backed)
- **Codex CLI** - session and conversation SQLite databases (`~/.codex/`)
- **Claude desktop** - conversation storage (SQLite, `~/Library/Application Support/Claude/`)
- **Claude Code CLI** - session JSONL files (`~/.claude/projects/`)

For each discovered conversation, it runs a two-layer detection engine:

1. **Regex patterns** - known credential formats: AWS keys, OpenAI tokens, GitHub PATs, GCP service accounts, private keys, JWTs, connection strings, generic API key patterns
2. **Heuristic signals** - contextual variable names (`api_key =`, `password:`, `token =`) that indicate secrets even when the value doesn't match a known format

Output is a structured report (CSV and/or JSON) where each row includes the tool name, secret type, redacted secret value, source file path, line/position, confidence score, and timestamp.

---

## Quick start

```bash
# Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Scan current machine, output to ./ghosttype_report/
ghosttype scan

# Specific tool only
ghosttype scan --tool cursor

# Choose output format
ghosttype scan --format json
ghosttype scan --format csv
ghosttype scan --format both  # default

# Output directory
ghosttype scan --output /tmp/loot
```

---

## Requirements

- Python 3.11+
- macOS (primary target; Linux support planned)
- No external API calls; runs fully offline

---

## Output schema

Each finding row:

| Field | Description |
|-------|-------------|
| `tool` | Source AI tool (e.g., `cursor`, `claude_code`) |
| `secret_type` | Pattern category (e.g., `aws_access_key`, `openai_token`) |
| `secret_value` | The matched value (shown in full in JSON; redacted in CSV by default) |
| `file_path` | Absolute path to the source conversation file |
| `position` | Line number or byte offset within the file |
| `confidence` | `high` (known regex match) or `medium` (heuristic signal) |
| `context` | Surrounding text snippet (configurable window) |
| `discovered_at` | Timestamp of the scan |

---

## Project docs

- [ARCHITECTURE.md](ARCHITECTURE.md) - module design and data flow
- [RESEARCH.md](RESEARCH.md) - per-tool storage location findings
- [DECISIONS.md](DECISIONS.md) - key technical decisions and rationale
- [ROADMAP.md](ROADMAP.md) - v1 scope and future plans
- [THREAT-MODEL.md](THREAT-MODEL.md) - intended use cases and misuse considerations
- [CLAUDE.md](CLAUDE.md) - context for AI-assisted development sessions
