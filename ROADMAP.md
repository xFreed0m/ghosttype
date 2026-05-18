# Roadmap

## Current: v0.4.0

Dual complementary engines. Local scanner on macOS, all five AI tools.

**Shipped (v0.4.0):**
- In-tree regex/heuristic pattern engine restored and running *alongside*
  TruffleHog (`ghosttype/pattern_engine.py` wrapping `ghosttype/patterns.py`)
- `--engine {both,trufflehog,patterns}` (default `both`)
- `source` field on every finding (`trufflehog` | `ghosttype-pattern`)
- Cross-engine dedup: TruffleHog wins `(value, file)` overlaps
- `--engine patterns` runs fully offline (no TruffleHog binary needed)
- `--engine both` gracefully degrades to patterns-only (visible warning) if
  TruffleHog is missing
- Dual-engine-aware `--min-confidence`; `By Source` stats column
- 127 tests (restored pattern suite + dual-engine + live integration)

---

## v0.3.0

TruffleHog-powered detection + verification. Local scanner on macOS, all five AI tools.

**Shipped (v0.3.0):**
- Claude Code, Cursor, Codex, ChatGPT, Claude Desktop scanners (discovery layer)
- TruffleHog subprocess engine — 800+ detectors, live API verification, entropy filter, known-example exclusion
- `--only-verified` for triage on confirmed-live credentials
- `--no-verification` for fast offline scans
- `--trufflehog-binary` / `GHOSTTYPE_TRUFFLEHOG_BIN` overrides
- `ghosttype doctor` showing TruffleHog binary + version + detected tools
- Severity derived from (detector × verification state)
- Exit code 1 when findings present (CI/CD integration)
- `--output -` for stdout piping to jq
- `--max-age-days`, `--min-confidence`, `--allow-list`, `--stats-only`, `--quiet`
- 76 tests, including a live integration test against the real TruffleHog binary

---

## v0.2.0 (previous)

- In-tree regex + heuristic pattern engine (30 + 10 patterns)
- All five scanners shipped
- JSON/CSV output, severity, redaction
- 93 tests against the in-tree engine

---

## Planned

### Near term

- Linux and Windows path support (path table already in RESEARCH.md)
- ChatGPT full decryption (verified AES-128-CBC; needs Keychain key extraction research)
- Claude Desktop scanner (storage format needs investigation once installed)
- `--include-cwd` / `--include-git-branch` enrichments — surface the project context from Claude Code JSONL
- Custom detector configuration: pass `--config trufflehog.yaml` through to TruffleHog

### Later

- Cloud conversation sync: ChatGPT export API, Claude.ai export
- SIEM-compatible output (CEF, Splunk HEC)
- `--watch` mode for continuous monitoring
- Per-detector severity overrides in a config file
