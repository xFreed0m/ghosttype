# CLAUDE.md — AI-Assisted Development Guide

Context for AI coding assistants (Claude Code, Cursor, Copilot, etc.) working on ghosttype.

## What this project is

ghosttype is a local forensic scanner for authorized red team and DLP use. It finds AI tool conversation files on macOS, extracts credentials using regex and heuristic patterns, and writes a structured report (JSON + CSV) with each finding linked to its source file.

Authorized use only. See THREAT-MODEL.md.

## Architecture in 30 seconds

Plugin-style scanner modules. One Python module per target AI tool implementing a `Scanner` ABC. Shared pattern engine. Thin orchestrator. Click CLI.

```
ghosttype/
├── cli.py              # click CLI - all user-facing flags
├── scanner.py          # Orchestrator - wires scanners → patterns → findings
├── patterns.py         # 30 regex + 10 heuristic patterns, FP filters
├── models.py           # dataclasses: ConversationRecord, TextChunk, PatternMatch, Finding
├── report.py           # write_json, write_csv, copy_sources
└── scanners/
    ├── base.py         # Scanner ABC with _base_path @abstractmethod
    ├── claude_code.py  # ~/.claude/projects/ JSONL + history + tasks
    ├── cursor.py       # SQLite state.vscdb (global + workspace storage)
    ├── codex.py        # ~/.codex/ SQLite
    ├── chatgpt.py      # AES-128-CBC .data files (Keychain-backed)
    └── claude.py       # Stub - pending storage format research
```

## Key conventions

- Python 3.11+, Black (88 cols)
- Type hints throughout; dataclasses for data models
- Always activate `.venv` before running Python: `source .venv/bin/activate && ...`
- No hardcoded paths — use `pathlib.Path` and `Path.home()`
- Pattern engine is pure (no I/O); independently testable
- Tests go in `tests/` mirroring the package structure
- Fixtures in `tests/fixtures/` — never use real credentials, use obviously fake patterns

## What to read before changing specific areas

- **Adding a scanner:** ARCHITECTURE.md (Scanner interface), RESEARCH.md (storage locations)
- **Pattern engine:** ARCHITECTURE.md (Pattern engine section), `ghosttype/patterns.py`
- **Output format:** `ghosttype/report.py` — `_FIELDS` list, `_finding_to_dict()`
- **CLI flags:** `ghosttype/cli.py` — all options are on the `scan()` function

## Current state

v0.2.0. 93 tests. Run `ghosttype scan` to try it live.
