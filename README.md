# ghosttype

Local forensic scanner that extracts credentials from AI tool conversation history.

> Read the blog post: [**ghosttype — finding secrets in AI conversation history**](https://betheadversary.com/posts/ghosttype)

> **Authorized use only.** For licensed penetration testers, red teams, and DLP/blue teams operating under explicit written authorization. See [THREAT-MODEL.md](THREAT-MODEL.md).

---

## What it does

ghosttype scans AI tool conversation files for exposed credentials and secrets, then produces a report with each finding linked to its source conversation file.

**Supported tools:**

| Tool | Data source |
|------|------------|
| Claude Code CLI | `~/.claude/projects/**/*.jsonl` + history |
| Cursor IDE | `state.vscdb` (SQLite, global + workspace) |
| Codex CLI | `~/.codex/state_5.sqlite` + logs |
| ChatGPT Desktop | Keychain-backed `.data` files (AES-128-CBC) |
| Claude Desktop | Stub (path detected; extraction in progress) |

**Detected credential types (40+ patterns):**

AWS access/secret keys, OpenAI tokens, Anthropic API keys, GitHub PATs (6 formats), Stripe keys, Slack tokens, HashiCorp Vault tokens, Linear, Databricks, npm, Telegram, Hugging Face, DigitalOcean, Docker Hub, Pulumi, Doppler, PyPI, SendGrid, GCP service accounts/API keys, JWT tokens, PEM private keys, database connection strings, and more — plus 10 heuristic context-signal patterns (API key assignments, passwords, JWT secrets, Azure credentials, Supabase keys, etc.).

---

## Quick start

```bash
git clone https://github.com/xFreed0m/ghosttype
cd ghosttype
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Scan all detected AI tools
ghosttype scan

# High-confidence findings only (no heuristic noise)
ghosttype scan --min-confidence high

# Pipe to jq for filtering
ghosttype scan --format json --output - --quiet | jq '.[] | select(.severity == "critical")'

# Show which tools are detected on this machine
ghosttype list-tools
```

**Requirements:** Python 3.11+, macOS (Linux/Windows: update paths in scanners)

---

## Output

Default: `./ghosttype_report/findings.json` + `findings.csv`

Each finding includes:

| Field | Description |
|-------|-------------|
| `tool` | Source AI tool |
| `secret_type` | Credential category (e.g. `aws_access_key`) |
| `severity` | `critical` / `high` / `medium` |
| `secret_value` | Plaintext value (use `--redact` to mask) |
| `file_path` | Source conversation file |
| `confidence` | `high` (regex match) or `medium` (heuristic) |
| `context` | 200-char window around the match |

---

## All options

```
ghosttype scan [OPTIONS]

  --tool TEXT              Scan one tool: cursor, chatgpt, codex, claude, claude_code
  --format [json|csv|both] Output format (default: both)
  --output TEXT            Output dir, or - for stdout JSON (default: ./ghosttype_report)
  --redact                 Mask secret values in output
  --min-confidence         Filter: high or medium (default: medium)
  --max-age-days N         Only scan files modified within last N days
  --copy-sources           Copy source conversation files to output/sources/
  --allow-list PATH        Suppress known-safe values (one value per line)
  --stats-only             Print summary statistics only
  --quiet / -q             Suppress banner for scripting
  --context-window N       Context chars around match (default: 200)

ghosttype list-tools      Show detected AI tools on this machine
ghosttype version         Print version
```

---

## Detection design

Two-layer engine with false-positive reduction:

1. **Regex (high confidence)** — 30 patterns for known credential formats with exact structure
2. **Heuristic (medium confidence)** — 10 patterns using variable-name context signals (`API_KEY=`, `JWT_SECRET=`, etc.)

FP reduction: entropy threshold (≥3.0 bits/char), placeholder/example value filter, known-documentation-example exclusion list.

---

## Project docs

- [ARCHITECTURE.md](ARCHITECTURE.md) — module design, data flow, pattern engine
- [RESEARCH.md](RESEARCH.md) — per-tool storage location findings (verified on macOS 15.x)
- [DECISIONS.md](DECISIONS.md) — key technical decisions and rationale
- [ROADMAP.md](ROADMAP.md) — planned work
- [THREAT-MODEL.md](THREAT-MODEL.md) — intended use cases, out-of-scope uses
