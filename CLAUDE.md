# CLAUDE.md — AI-Assisted Development Guide

Context for AI coding assistants (Claude Code, Cursor, Copilot, etc.) working on ghosttype.

## What this project is

ghosttype is a local forensic scanner for authorized red team and DLP use. It finds AI tool conversation files on macOS, hands the extracted text to TruffleHog for detection + live verification, and writes a structured report (JSON + CSV) with each finding linked to its source file.

Authorized use only. See THREAT-MODEL.md.

## Architecture in 30 seconds

Plugin-style discovery + TruffleHog subprocess for detection/verification. One Python module per target AI tool implements the `Scanner` ABC. The orchestrator collects extracted text chunks and passes them to `trufflehog_engine.scan_chunks`, which shells out to the real TruffleHog binary in `filesystem` mode and parses NDJSON results back into `Finding`s. Click CLI on top.

```
ghosttype/
├── cli.py                 # click CLI - all user-facing flags
├── scanner.py             # Orchestrator - wires scanners → engine → findings
├── trufflehog_engine.py   # TruffleHog subprocess wrapper (NEW in 0.3.0)
├── models.py              # dataclasses: ConversationRecord, TextChunk, Finding
├── report.py              # write_json, write_csv, copy_sources
└── scanners/
    ├── base.py            # Scanner ABC with _base_path @abstractmethod
    ├── claude_code.py     # ~/.claude/projects/ JSONL + history + tasks
    ├── cursor.py          # SQLite state.vscdb (global + workspace storage)
    ├── codex.py           # ~/.codex/ SQLite
    ├── chatgpt.py         # AES-128-CBC .data files (Keychain-backed)
    └── claude.py          # Stub - pending storage format research
```

## Key conventions

- Python 3.11+, Black (88 cols)
- Type hints throughout; dataclasses for data models
- Always activate `.venv` before running Python: `source .venv/bin/activate && ...`
- No hardcoded paths — use `pathlib.Path` and `Path.home()`
- TruffleHog is the source of truth for what counts as a credential. If a credential type isn't detected, upgrade TruffleHog; do NOT re-add an in-tree pattern catalog.
- The engine layer is pure-ish (only I/O is the subprocess + temp dir); independently testable with `subprocess.run` mocked
- Tests go in `tests/` mirroring the package structure
- Fixtures in `tests/fixtures/` — never use real credentials. Use obviously fake patterns that nevertheless pass TruffleHog's entropy filter (e.g. mixed-case ASCII).

## What to read before changing specific areas

- **Adding a scanner:** ARCHITECTURE.md (Scanner interface), RESEARCH.md (storage locations)
- **Engine internals:** ARCHITECTURE.md (TruffleHog engine section), `ghosttype/trufflehog_engine.py`. NDJSON shape: `{SourceMetadata.Data.Filesystem.{file,line}, DetectorName, Verified, Raw, RawV2, ExtraData, VerificationError?}`.
- **Output format:** `ghosttype/report.py` — `_FIELDS` list, `_finding_to_dict()`
- **CLI flags:** `ghosttype/cli.py` — all options are on the `scan()` function

## Don't

- Don't casually expand the in-tree pattern catalog. ghosttype is **dual-engine by design (v0.4.0)**: TruffleHog is the verification source of truth and primary detector; the in-tree regex/heuristic engine is a deliberate *offline-capable peer* (`--engine patterns`) and a safety net for loose-context signals (`password=`, `secret_key=`) that TruffleHog's structural detectors miss. Add a pattern only with a documented rationale for why TruffleHog can't cover it; if verification matters, prefer upstreaming a detector to TruffleHog.
- Don't make the patterns-only fallback *silent*. With the default `--engine both`, a missing TruffleHog binary falls back to the pattern engine — but the CLI MUST print a visible warning (that mode does no verification). `--engine trufflehog` still hard-fails loudly with the install URL; never degrade it silently.
- Don't ship any code that hits a network endpoint other than via the TruffleHog subprocess. ghosttype itself does no network I/O; the pattern engine is fully offline.

## Current state

v0.4.0 (dual-engine: TruffleHog + in-tree patterns). 212 tests, ~97% coverage (95% floor, never 100%). Run `ghosttype doctor` to confirm TruffleHog is wired up. Run `ghosttype scan --no-verification --output -` for a fast offline sanity check, or `ghosttype scan --engine patterns --output -` for a no-binary offline run.
