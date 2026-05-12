# ghosttype - Design Spec

**Date:** 2026-05-12
**Status:** Approved

---

## Purpose

ghosttype is a local forensic scanner for authorized red team and DLP use. It discovers AI tool conversation files on a machine, extracts credentials and secrets from them using pattern matching, and produces a structured report (CSV + JSON) with each finding linked to its source conversation file.

Primary users: red teamers harvesting credentials from compromised machines; blue/DLP teams auditing credential exposure in AI tool history.

---

## Scope (v1)

- macOS only, local filesystem only
- Five target tools: Cursor, ChatGPT desktop, Codex CLI, Claude desktop, Claude Code CLI
  - Note: Claude desktop scanner ships as a detection stub in v1 (checks for the path, reports availability) because the app was not available for storage format research. Full extraction added once installed and researched.
- Detection: regex patterns (known credential formats) + heuristic signals (variable name context)
- Output: CSV + JSON report, source file copies

---

## Architecture

Plugin-style scanner modules. One module per target tool implementing a shared `Scanner` ABC. A shared pattern engine handles both detection layers. A thin orchestrator iterates all registered scanners and feeds results to the report writer.

### Module layout

```
ghosttype/
├── cli.py              # click CLI entry point
├── scanner.py          # orchestrator
├── patterns.py         # compiled regex + heuristic patterns
├── report.py           # CSV + JSON writer
└── scanners/
    ├── base.py         # Scanner ABC, ConversationRecord, TextChunk datatypes
    ├── cursor.py
    ├── chatgpt.py
    ├── codex.py
    ├── claude.py
    └── claude_code.py
```

### Data flow

```
CLI -> Orchestrator -> [Scanner.discover() -> Scanner.extract_text()] -> Pattern engine -> Report writer
```

---

## Scanner Interface

```python
class Scanner(ABC):
    name: str           # "cursor", "chatgpt", "codex", "claude", "claude_code"
    display_name: str

    def is_available(self) -> bool: ...    # check if tool's data dir exists
    def discover(self) -> list[ConversationRecord]: ...
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]: ...
```

`ConversationRecord`: `source_path`, `tool`, `conversation_id`, `created_at`, `raw`
`TextChunk`: `text`, `position`, `record`

---

## Storage Locations (verified on macOS 15.x)

| Tool | Format | Path |
|------|--------|------|
| Cursor | SQLite `state.vscdb` | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` |
| ChatGPT | Encrypted `.data` (AES-256-GCM, Keychain-backed) | `~/Library/Application Support/com.openai.chat/conversations-v3-<uid>/*.data` |
| Codex CLI | SQLite | `~/.codex/state_5.sqlite`, `~/.codex/logs_2.sqlite` |
| Claude desktop | SQLite (path unconfirmed; app not installed on test machine) | `~/Library/Application Support/Claude/` (expected; needs verification) |
| Claude Code | JSONL | `~/.claude/projects/<path-slug>/<session-uuid>.jsonl` |

---

## Detection Layers

**Layer 1 - Regex (confidence: high)**
Named-group patterns for: AWS access keys, OpenAI tokens, GitHub PATs, Anthropic API keys, GCP service account emails, PEM private keys, JWTs, database connection strings.

**Layer 2 - Heuristic (confidence: medium)**
Variable name context signals: `api_key =`, `password:`, `secret_key =`, `access_token =`, `private_key =`.

Deduplication: by `(secret_value, source_path)` to avoid duplicate findings from repeated messages.

---

## Output Schema

Each finding:
```
tool, secret_type, secret_value, file_path, position, confidence, context, discovered_at
```

Field clarifications:
- `position`: for JSONL files, the line number; for SQLite sources, the row key (e.g., `composerData:<uuid>`) plus character offset within the extracted text, formatted as `<row_key>:<char_offset>`
- `context`: 200-character window centered on the match (configurable via `--context-window N`; default 200)

Output directory (default `./ghosttype_report/`):
- `findings.json` - full detail, plaintext values
- `findings.csv` - tabular, values redacted by default (`--no-redact` flag)
- `sources/<tool>/` - for JSONL tools (Claude Code): copies of the individual `.jsonl` conversation files that had findings. For SQLite tools (Cursor, Codex): extracted conversation records exported as JSON (not full database copy, to avoid including unrelated conversations and keeping file sizes manageable)

---

## CLI

```
ghosttype scan                       # scan all tools
ghosttype scan --tool cursor         # specific tool
ghosttype scan --format json         # json only (default: both)
ghosttype scan --format csv
ghosttype scan --format both
ghosttype scan --output /tmp/loot    # output directory
ghosttype scan --no-redact           # show plaintext in CSV
ghosttype list-tools                 # show which tools are detected on this machine
```

---

## Key Decisions

- Plugin-style over single-script: each tool's storage format is distinct enough to warrant isolation
- Both detection layers: regex alone misses contextual secrets; heuristic alone too noisy
- Copy source files: path-only is insufficient; full file needed for red team evidence and blue team rotation audit
- CSV redacted by default: CSV is frequently opened in Excel and shared; reduce accidental exposure
- macOS-first: all five tools confirmed present; cross-platform via path table in RESEARCH.md (v2)
- ChatGPT graceful degradation: if Keychain decryption fails, report file metadata only; don't break full scan

---

## Testing Strategy

- Pattern engine: pure-function unit tests with known credential fixtures (no I/O)
- Scanners: unit tests with fixture files (sample `.vscdb`, `.jsonl`, mock SQLite DBs)
- Integration test: synthetic conversation files containing planted credentials; assert findings match expected output
- No real credentials in test fixtures; use obviously fake patterns (e.g., `AKIAIOSFODNN7EXAMPLE`)
