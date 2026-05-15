# Architecture

## Overview

ghosttype is a CLI with a two-layer pipeline:

1. **Discovery layer (in-tree):** per-tool scanner modules that know where each AI tool stores conversation history and how to read it (SQLite schemas, JSONL, Electron `safeStorage`).
2. **Detection layer — two complementary engines** driven by the Orchestrator over the same extracted chunks:
   - **TruffleHog subprocess** (`trufflehog_engine.py`): the [TruffleHog](https://github.com/trufflesecurity/trufflehog) binary in `filesystem` mode — 800+ structural detectors with live API verification.
   - **In-tree pattern engine** (`pattern_engine.py` wrapping `patterns.py`): 30 regex + 10 heuristic patterns, offline, unverifiable, catching loose context signals TruffleHog's structural detectors miss.

`--engine` selects `both` (default, merged — TruffleHog wins `(value, file)` overlaps), `trufflehog`, or `patterns` (no binary required). Every `Finding` carries a `source` field. v0.3.0 supplanted the pattern engine with TruffleHog; v0.4.0 restored it as a complement after a real-corpus measurement showed neither engine is a superset of the other (see DECISIONS.md).

## Directory layout

```
ghosttype/
├── cli.py                 # click CLI entry point
├── scanner.py             # Orchestrator: scanner.discover -> extract_text -> trufflehog_engine.scan_chunks
├── trufflehog_engine.py   # TruffleHog subprocess wrapper (NEW in 0.3.0)
├── models.py              # dataclasses: ConversationRecord, TextChunk, Finding
├── report.py              # CSV + JSON writer; source file copier
└── scanners/
    ├── base.py            # Scanner ABC with _base_path, is_available(), discover(), extract_text()
    ├── __init__.py        # SCANNERS registry
    ├── claude_code.py     # Claude Code CLI (~/.claude/projects/**/*.jsonl + history.jsonl + tasks/**/*.json)
    ├── cursor.py          # Cursor IDE (globalStorage/ + workspaceStorage/*/)
    ├── codex.py           # Codex CLI (~/.codex/ SQLite)
    ├── chatgpt.py         # ChatGPT desktop (.data files, macOS Keychain-backed AES-128-CBC)
    └── claude.py          # Claude desktop (stub; SQLite under ~/Library/Application Support/Claude/)
```

## Data flow

```
CLI invocation (--tool, --output, --only-verified, --no-verification, ...)
    |
    v
Orchestrator.run(tool_filter)
    |-- for each registered scanner:
    |       |-- if available: scanner.discover() -> list[ConversationRecord]
    |       |-- filter by max_age_days (if set)
    |       |-- for each record: scanner.extract_text() -> list[TextChunk]
    |       \-- pass all chunks to trufflehog_engine.scan_chunks(...)
    v
trufflehog_engine.scan_chunks(scanner_name, chunks, verify=..., only_verified=..., ...)
    |-- resolve binary (--trufflehog-binary > $GHOSTTYPE_TRUFFLEHOG_BIN > PATH)
    |-- mkdtemp /tmp/ghosttype-th-XXXX/
    |-- for each chunk: write tmpdir/{scanner}__{conv_id}__{position}__{idx:06d}.txt
    |-- subprocess.run([
    |       binary, "filesystem",
    |       "--json", "--no-update",
    |       "--concurrency=10", "--detector-timeout=10s",
    |       "--no-verification" if verify=False,
    |       "--results=verified" if only_verified=True else "--results=verified,unverified,unknown",
    |       tmpdir,
    |   ], timeout=300)
    |-- parse stdout NDJSON line-by-line; skip non-result lines
    |-- for each result:
    |       |-- map SourceMetadata.Filesystem.file -> (ConversationRecord, TextChunk)
    |       |-- extract DetectorName, Verified, Raw/RawV2, ExtraData, VerificationError
    |       |-- emit Finding (with verified, detector_name, verification_error, extra_data)
    |-- shutil.rmtree(tmpdir) in finally
    v
Findings list (verified first, then by detector)
    |
    v
Orchestrator dedup: (secret_value, file_path, secret_type)
    |
    v
CLI filtering: --min-confidence verified, --allow-list, then write JSON/CSV
```

## Scanner interface (base.py)

Each scanner implements the `Scanner` ABC. **Unchanged from 0.2.0.**

```python
class Scanner(ABC):
    name: str                            # tool identifier, e.g. "cursor"
    display_name: str                    # human label, e.g. "Cursor IDE"

    @property
    @abstractmethod
    def _base_path(self) -> Path: ...

    def is_available(self) -> bool:
        return self._base_path.exists()

    @abstractmethod
    def discover(self) -> list[ConversationRecord]: ...

    @abstractmethod
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]: ...
```

`ConversationRecord` carries: `source_path`, `tool`, `conversation_id`, `created_at`, `raw`.

`TextChunk` carries: `text`, `position`, `record` (back-reference).

## TruffleHog engine (`trufflehog_engine.py`)

Public surface:

```python
def resolve_binary(binary: str | None = None) -> str: ...
def trufflehog_version(binary: str | None = None) -> str: ...
def scan_chunks(scanner_name: str, chunks: list[TextChunk], *,
                verify: bool = True,
                only_verified: bool = False,
                binary: str | None = None,
                timeout: int = 300,
                context_window: int = 200,
                concurrency: int = 10,
                detector_timeout: str = "10s") -> list[Finding]: ...

class TruffleHogError(RuntimeError): ...
class TruffleHogNotFoundError(TruffleHogError): ...
class TruffleHogExecutionError(TruffleHogError): ...
```

### Why subprocess, not library bindings

TruffleHog is Go. A Python rewrite re-implements 800+ detectors and verifiers we'd then have to maintain; CGO bindings are platform-fragile and exceed the value of integration. The subprocess boundary (`--json` NDJSON in, parsed results out) is stable, deterministic, and means TruffleHog upgrades flow through with zero ghosttype code changes.

### Mapping results back to records

Each `TextChunk` is written to `tmpdir/{scanner}__{conv_id}__{position}__{idx:06d}.txt`. TruffleHog reports the absolute file path in `SourceMetadata.Data.Filesystem.file`; ghosttype looks up the corresponding `(ConversationRecord, TextChunk)` from a dict keyed by that path. A basename fallback handles symlink-resolution differences (e.g. `/var/folders/...` vs `/private/var/folders/...` on macOS).

### Severity

Verified findings whose detector is in `_CRITICAL_DETECTORS` (AWS, Anthropic, OpenAI, GitHub family, Stripe, PrivateKey, Vault, GCP, Azure, Databricks, Snowflake) are `critical`. Verified anything else is `high`. Unverified critical-detector findings are `high`; unverified anything else is `medium`. This keeps `--severity critical` triage tight even when verification is unavailable.

## Finding model

```python
@dataclass
class Finding:
    tool: str
    secret_type: str            # detector name, lowercased
    secret_value: str
    file_path: Path
    position: str
    confidence: str             # "verified" or "unverified"
    context: str
    discovered_at: datetime
    severity: str = "medium"
    verified: bool = False
    detector_name: str = ""     # TruffleHog DetectorName, e.g. "Github"
    verification_error: str | None = None
    extra_data: dict = field(default_factory=dict)
```

The fields `verified`, `detector_name`, `verification_error`, `extra_data` are new in 0.3.0.

## CLI options

```
ghosttype scan
  --tool {cursor|chatgpt|codex|claude|claude_code}
  --format {json|csv|both}
  --output OUTPUT                     # path or '-' for stdout JSON
  --redact
  --min-confidence {verified|unverified|high|medium}
  --only-verified                     # pass --results=verified to TruffleHog
  --no-verification                   # pass --no-verification to TruffleHog
  --trufflehog-binary PATH
  --trufflehog-timeout SECONDS
  --max-age-days N
  --copy-sources
  --allow-list PATH
  --stats-only
  --quiet / -q
  --context-window N

ghosttype doctor                      # NEW in 0.3.0: show trufflehog binary + version + detected tools
ghosttype list-tools
ghosttype version
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | no findings |
| 1    | at least one finding (CI gating signal, unchanged from 0.2.0) |
| 2    | environment problem (TruffleHog missing, subprocess error) |

## Adding a new scanner

Discovery is still ghosttype's job. To add a new AI tool:

1. Create `ghosttype/scanners/<toolname>.py`
2. Implement the Scanner ABC: define `name`, `display_name`, `_base_path` property, `discover()`, `extract_text()`
3. Register in `ghosttype/scanners/__init__.py` by adding an instance to `SCANNERS`
4. No changes needed to orchestrator, engine, models, or CLI — TruffleHog handles detection on whatever text you extract

## Adding a new credential type

Two paths, depending on the kind:

- **Structural, verifiable credential** (fixed prefix/shape, has a provider API to check against): it belongs in TruffleHog. Upgrade TruffleHog or open a PR against TruffleHog upstream — don't add a structural regex here that just duplicates a detector.
- **Loose context signal** (e.g. a new `*_TOKEN=` style variable name with no fixed value shape, unverifiable): add it to the heuristic layer in `ghosttype/patterns.py` `_HEURISTIC_PATTERNS`, with a test in `tests/test_patterns.py`. This is exactly the niche the in-tree engine exists to cover.
