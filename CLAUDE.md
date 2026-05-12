# ghosttype - AI Session Context

This file provides context for AI-assisted development sessions. Read it at the start of any session before making changes.

## What this project is

A local forensic scanner for authorized red team and DLP use. It finds AI tool conversation files on macOS, extracts credentials/secrets via regex and heuristic patterns, and writes a structured report (CSV + JSON) with each finding linked to its source file.

Authorized use only. See THREAT-MODEL.md.

## Architecture summary

Plugin-style scanner modules. One Python module per target AI tool. Shared pattern engine and report writer. Thin CLI orchestrator.

```
ghosttype/
├── cli.py              # click CLI
├── scanner.py          # orchestrator
├── patterns.py         # regex + heuristic patterns
├── report.py           # output writer
└── scanners/
    ├── base.py         # Scanner ABC
    ├── cursor.py       # Cursor IDE (SQLite state.vscdb)
    ├── chatgpt.py      # ChatGPT desktop (encrypted .data)
    ├── codex.py        # Codex CLI (~/.codex/ SQLite)
    ├── claude.py       # Claude desktop (not yet researched)
    └── claude_code.py  # Claude Code CLI (~/.claude/projects/ JSONL)
```

See ARCHITECTURE.md for full detail and data flow.

## Key files to read before working on specific areas

- **Adding a scanner:** ARCHITECTURE.md (Scanner interface section), RESEARCH.md (storage locations per tool)
- **Pattern engine:** ARCHITECTURE.md (Pattern engine section), `ghosttype/patterns.py`
- **Output format:** ARCHITECTURE.md (Report output section), `ghosttype/report.py`
- **Storage locations per tool:** RESEARCH.md - contains verified paths and database schemas

## Current state

v1.0 shipped. v2 improvements merged. Active development on v3 improvements.

**Pattern coverage (30+ types):** AWS keys, OpenAI (sk-, sk-proj-), Anthropic, GitHub (ghp_, ghs_, ghu_), Stripe, Slack, HashiCorp Vault, Linear, Databricks, npm, SendGrid, Telegram, Hugging Face, DigitalOcean, GCP service accounts, JWT, PEM keys, connection strings, Azure (heuristic), AWS secret key (heuristic), JWT secrets (heuristic).

**FP reduction:** entropy threshold 3.0 bits/char, placeholder stem/suffix filters, known-example exclusion set.

**CLI flags:** `--tool`, `--format`, `--output`, `--min-confidence`, `--redact`, `--copy-sources`, `--allow-list`, `--stats-only`, `--context-window`.

**Finding fields:** tool, secret_type, severity, secret_value, file_path, position, confidence, context, discovered_at.

See ROADMAP.md for current v2 checklist and v3 scope.

## Development conventions

- Python 3.11+, formatted for Black (88 cols)
- Type hints throughout; use dataclasses for `ConversationRecord` and `TextChunk`
- Test fixtures go in `tests/fixtures/` (sample SQLite files, JSONL snippets)
- Always activate `.venv` before running Python: `source .venv/bin/activate && ...`
- No hardcoded paths - use `pathlib.Path` and expand `~`
- Pattern engine must be independently testable (pure functions, no I/O)

## Things to check if starting a new session

1. Has `RESEARCH.md` been updated with new findings?
2. What's the current v1 checklist status in `ROADMAP.md`?
3. Any open questions in `DECISIONS.md`?
4. Run `git log --oneline -10` to see recent work
