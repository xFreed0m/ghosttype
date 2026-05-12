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

1. **Regex patterns** - 30+ known credential formats across cloud providers and services
2. **Heuristic signals** - contextual variable name patterns (`api_key =`, `password:`, `JWT_SECRET=`) with entropy filtering to reduce false positives

**Detected credential types include:**
AWS access/secret keys, OpenAI tokens (sk-, sk-proj-), Anthropic API keys, GitHub PATs (ghp_, ghs_, ghu_), Stripe keys (sk_live_, sk_test_), Slack tokens (xoxb-, xoxp-), HashiCorp Vault tokens (hvs., hvb.), Linear API keys, Databricks tokens, npm tokens, SendGrid, Telegram bot tokens, Hugging Face tokens, DigitalOcean tokens, GCP service accounts, JWT tokens, PEM private keys, database connection strings, and more.

Output is a structured JSON and/or CSV report with each finding linked to its source conversation file.

---

## Quick start

```bash
# Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Scan all detected AI tools, output to ./ghosttype_report/
ghosttype scan

# Scan a specific tool
ghosttype scan --tool cursor
ghosttype scan --tool claude_code

# Filter to high-confidence findings only (reduces noise)
ghosttype scan --min-confidence high

# Only show stats, don't print every finding
ghosttype scan --stats-only

# Redact secret values in output (safe for sharing)
ghosttype scan --redact

# Copy source conversation files to output dir (for evidence)
ghosttype scan --copy-sources --output /tmp/loot

# Suppress known-safe values (reviewed FPs)
ghosttype scan --allow-list .ghosttype-allowlist

# Show which tools are detected on this machine
ghosttype list-tools

# Print version
ghosttype version
```

---

## Requirements

- Python 3.11+
- macOS (primary target; Linux support planned)
- No external API calls; runs fully offline

---

## Output schema

Each finding:

| Field | Description |
|-------|-------------|
| `tool` | Source AI tool (`cursor`, `claude_code`, `chatgpt`, `codex`, `claude`) |
| `secret_type` | Credential category (`aws_access_key`, `openai_token`, `stripe_secret_key`, ...) |
| `severity` | `critical` (highest-value keys), `high` (other regex matches), `medium` (heuristic) |
| `secret_value` | The matched value (plaintext by default; use `--redact` to mask) |
| `file_path` | Absolute path to the source conversation file |
| `position` | Line number or row key within the file |
| `confidence` | `high` (known regex match) or `medium` (heuristic signal) |
| `context` | 200-character window centered on the match |
| `discovered_at` | Timestamp of the scan |

Output directory (default `./ghosttype_report/`):
- `findings.json` - full detail, plaintext values by default
- `findings.csv` - tabular, same values (use `--redact` to mask)
- `sources/<tool>/` - copies of source conversation files with findings (opt-in: `--copy-sources`)

---

## Project docs

- [ARCHITECTURE.md](ARCHITECTURE.md) - module design and data flow
- [RESEARCH.md](RESEARCH.md) - per-tool storage location findings
- [DECISIONS.md](DECISIONS.md) - key technical decisions and rationale
- [ROADMAP.md](ROADMAP.md) - v1 scope and future plans
- [THREAT-MODEL.md](THREAT-MODEL.md) - intended use cases and misuse considerations
- [CLAUDE.md](CLAUDE.md) - context for AI-assisted development sessions
