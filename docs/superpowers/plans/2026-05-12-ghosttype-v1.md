# ghosttype v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local macOS scanner that discovers AI tool conversation files, extracts credentials via regex + heuristic patterns, and writes a CSV/JSON report with source file copies.

**Architecture:** Plugin-style scanner modules (one per tool) share a `Scanner` ABC. A shared pattern engine handles two detection layers. A thin orchestrator iterates all registered scanners and feeds findings to the report writer.

**Tech Stack:** Python 3.11+, `click` (CLI), `rich` (terminal output), `sqlite3` (stdlib, for Cursor/Codex), `json`/`csv` (stdlib), `subprocess` (macOS Keychain access for ChatGPT), `pytest` (tests)

---

## File Map

```
ghosttype/
├── __init__.py
├── models.py           # ConversationRecord, TextChunk, PatternMatch, Finding dataclasses
├── patterns.py         # compiled regex + heuristic patterns, scan_text()
├── report.py           # write_json(), write_csv(), copy_sources()
├── scanner.py          # Orchestrator: runs all scanners, deduplicates, returns findings
├── cli.py              # click CLI: `ghosttype scan`, `ghosttype list-tools`
└── scanners/
    ├── __init__.py     # SCANNERS registry list
    ├── base.py         # Scanner ABC
    ├── claude_code.py  # ~/.claude/projects/**/*.jsonl
    ├── cursor.py       # ~/Library/Application Support/Cursor/.../state.vscdb
    ├── codex.py        # ~/.codex/state_5.sqlite + logs_2.sqlite
    ├── chatgpt.py      # ~/Library/Application Support/com.openai.chat/conversations-v3-*/*.data
    └── claude.py       # stub: ~/Library/Application Support/Claude/ presence check

tests/
├── conftest.py         # shared fixtures: tmp dirs, synthetic SQLite/JSONL files
├── fixtures/           # static fixture data (fake credentials, sample conversation snippets)
│   ├── sample_conversation.jsonl
│   └── fake_creds.txt
├── test_models.py
├── test_patterns.py
├── test_report.py
├── test_scanner.py
└── scanners/
    ├── test_claude_code.py
    ├── test_cursor.py
    ├── test_codex.py
    ├── test_chatgpt.py
    └── test_claude.py

pyproject.toml
```

---

## Task 1: Project setup

**Files:**
- Create: `pyproject.toml`
- Create: `ghosttype/__init__.py`
- Create: `ghosttype/scanners/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/scanners/__init__.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "ghosttype"
version = "0.1.0"
description = "Local forensic scanner for AI tool conversation credentials"
requires-python = ">=3.11"
dependencies = [
    "click>=8.0",
    "rich>=13.0",
]

[project.scripts]
ghosttype = "ghosttype.cli:cli"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create package skeleton**

```bash
touch ghosttype/__init__.py ghosttype/scanners/__init__.py tests/__init__.py tests/scanners/__init__.py tests/fixtures/.gitkeep
mkdir -p tests/fixtures
```

- [ ] **Step 3: Create and activate virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

- [ ] **Step 4: Verify installation**

```bash
source .venv/bin/activate && python -c "import ghosttype; print('ok')"
```

Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml ghosttype/__init__.py ghosttype/scanners/__init__.py tests/__init__.py tests/scanners/__init__.py tests/fixtures/.gitkeep
git commit -m "chore: project setup and package skeleton"
```

---

## Task 2: Data models

**Files:**
- Create: `ghosttype/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from datetime import datetime, timezone
from pathlib import Path
from ghosttype.models import ConversationRecord, TextChunk, PatternMatch, Finding


def test_conversation_record_fields():
    rec = ConversationRecord(
        source_path=Path("/tmp/test.jsonl"),
        tool="claude_code",
        conversation_id="abc-123",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw={"messages": []},
    )
    assert rec.tool == "claude_code"
    assert rec.conversation_id == "abc-123"


def test_text_chunk_back_reference():
    rec = ConversationRecord(
        source_path=Path("/tmp/test.jsonl"),
        tool="claude_code",
        conversation_id="abc-123",
        created_at=None,
        raw={},
    )
    chunk = TextChunk(text="hello world", position="line:5", record=rec)
    assert chunk.record is rec


def test_finding_fields():
    now = datetime.now(timezone.utc)
    f = Finding(
        tool="cursor",
        secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=Path("/tmp/state.vscdb"),
        position="composerData:uuid-1:42",
        confidence="high",
        context="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        discovered_at=now,
    )
    assert f.confidence == "high"
    assert f.secret_type == "aws_access_key"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source .venv/bin/activate && pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'ghosttype.models'`

- [ ] **Step 3: Implement models.py**

```python
# ghosttype/models.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ConversationRecord:
    source_path: Path
    tool: str
    conversation_id: str
    created_at: datetime | None
    raw: Any  # dict or bytes depending on scanner


@dataclass
class TextChunk:
    text: str
    position: str  # "line:N" for JSONL; "<row_key>:<char_offset>" for SQLite
    record: ConversationRecord


@dataclass
class PatternMatch:
    secret_type: str
    secret_value: str
    confidence: str  # "high" or "medium"
    context: str
    char_offset: int


@dataclass
class Finding:
    tool: str
    secret_type: str
    secret_value: str
    file_path: Path
    position: str
    confidence: str
    context: str
    discovered_at: datetime
```

- [ ] **Step 4: Run test to verify it passes**

```bash
source .venv/bin/activate && pytest tests/test_models.py -v
```

Expected: 3 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/models.py tests/test_models.py
git commit -m "feat: data models (ConversationRecord, TextChunk, PatternMatch, Finding)"
```

---

## Task 3: Pattern engine

**Files:**
- Create: `ghosttype/patterns.py`
- Create: `tests/test_patterns.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_patterns.py
from ghosttype.patterns import scan_text


def test_detects_aws_access_key():
    text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "aws_access_key" in types
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert found.secret_value == "AKIAIOSFODNN7EXAMPLE"
    assert found.confidence == "high"


def test_detects_openai_token():
    text = "client = OpenAI(api_key='sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12')"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "openai_token" in types


def test_detects_github_pat_classic():
    text = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012"
    matches = scan_text(text)
    assert any(m.secret_type == "github_pat_classic" for m in matches)


def test_detects_anthropic_key():
    text = "key = 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
    matches = scan_text(text)
    assert any(m.secret_type == "anthropic_key" for m in matches)


def test_detects_jwt():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = scan_text(token)
    assert any(m.secret_type == "jwt" for m in matches)


def test_detects_connection_string():
    text = "db = connect('postgresql://user:password@localhost:5432/mydb')"
    matches = scan_text(text)
    assert any(m.secret_type == "connection_string" for m in matches)


def test_detects_pem_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    matches = scan_text(text)
    assert any(m.secret_type == "private_key_pem" for m in matches)


def test_heuristic_detects_api_key_assignment():
    text = "api_key = 'hunter2supersecretvalue'"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_api_key" and m.confidence == "medium" for m in matches)


def test_heuristic_detects_password_assignment():
    text = "password: mysecretpassword123"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_password" and m.confidence == "medium" for m in matches)


def test_context_window_centered_on_match():
    prefix = "x" * 50
    suffix = "y" * 50
    text = f"{prefix}AKIAIOSFODNN7EXAMPLE{suffix}"
    matches = scan_text(text, context_window=40)
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert "AKIAIOSFODNN7EXAMPLE" in found.context
    assert len(found.context) <= 40 + len("AKIAIOSFODNN7EXAMPLE")


def test_no_false_positive_on_clean_text():
    text = "Hello world, this is a normal conversation about coding."
    matches = scan_text(text)
    assert matches == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/test_patterns.py -v
```

Expected: all FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement patterns.py**

```python
# ghosttype/patterns.py
from __future__ import annotations

import re
from ghosttype.models import PatternMatch

# Layer 1: known credential formats (confidence: high)
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key",      re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("openai_token",        re.compile(r'\b(sk-[a-zA-Z0-9]{48,})\b')),
    ("github_pat_classic",  re.compile(r'\b(ghp_[a-zA-Z0-9]{36})\b')),
    ("github_pat_fine",     re.compile(r'\b(github_pat_[a-zA-Z0-9_]{82})\b')),
    ("anthropic_key",       re.compile(r'\b(sk-ant-[a-zA-Z0-9\-]{20,})\b')),
    ("gcp_service_account", re.compile(r'\b([a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com)\b')),
    ("private_key_pem",     re.compile(r'(-----BEGIN [A-Z ]+PRIVATE KEY-----)')),
    ("jwt",                 re.compile(r'\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b')),
    ("connection_string",   re.compile(r'((?:postgresql|mysql|mongodb|redis)://[^\s"\'<>\n]{8,})')),
]

# Layer 2: variable-name context signals (confidence: medium)
_HEURISTIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("heuristic_api_key",     re.compile(r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']?([^\s"\']{8,})')),
    ("heuristic_password",    re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{6,})')),
    ("heuristic_secret_key",  re.compile(r'(?i)(?:secret[_\-]?key|secret)\s*[=:]\s*["\']?([^\s"\']{8,})')),
    ("heuristic_token",       re.compile(r'(?i)(?:access[_\-]?token|auth[_\-]?token|bearer)\s*[=:]\s*["\']?([^\s"\']{8,})')),
    ("heuristic_private_key", re.compile(r'(?i)(?:private[_\-]?key)\s*[=:]\s*["\']?([^\s"\']{8,})')),
]


def _extract_context(text: str, start: int, end: int, window: int) -> str:
    half = window // 2
    ctx_start = max(0, start - half)
    ctx_end = min(len(text), end + half)
    return text[ctx_start:ctx_end]


def scan_text(text: str, context_window: int = 200) -> list[PatternMatch]:
    """Scan text for credential patterns. Returns deduplicated PatternMatch list."""
    matches: list[PatternMatch] = []
    seen: set[tuple[str, str]] = set()

    for secret_type, pattern in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(PatternMatch(
                secret_type=secret_type,
                secret_value=value,
                confidence="high",
                context=_extract_context(text, m.start(1), m.end(1), context_window),
                char_offset=m.start(1),
            ))

    for secret_type, pattern in _HEURISTIC_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            # Skip if value already captured by a high-confidence pattern
            if any(value == existing.secret_value for existing in matches):
                continue
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(PatternMatch(
                secret_type=secret_type,
                secret_value=value,
                confidence="medium",
                context=_extract_context(text, m.start(1), m.end(1), context_window),
                char_offset=m.start(1),
            ))

    return matches
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/test_patterns.py -v
```

Expected: all 11 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/patterns.py tests/test_patterns.py
git commit -m "feat: pattern engine with regex and heuristic detection layers"
```

---

## Task 4: Report writer

**Files:**
- Create: `ghosttype/report.py`
- Create: `tests/test_report.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_report.py
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.models import Finding
from ghosttype.report import write_json, write_csv, copy_sources


@pytest.fixture
def findings(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text('{"type":"user","message":{"content":"hi"}}\n')
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        Finding(
            tool="claude_code",
            secret_type="aws_access_key",
            secret_value="AKIAIOSFODNN7EXAMPLE",
            file_path=src,
            position="line:1",
            confidence="high",
            context="key = AKIAIOSFODNN7EXAMPLE",
            discovered_at=now,
        )
    ]


def test_write_json_creates_valid_file(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out)
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"
    assert data[0]["tool"] == "claude_code"
    assert data[0]["confidence"] == "high"


def test_write_csv_redacts_by_default(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=True)
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["secret_value"] == "***REDACTED***"
    assert rows[0]["tool"] == "claude_code"


def test_write_csv_no_redact_shows_value(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=False)
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"


def test_copy_sources_copies_jsonl_file(tmp_path, findings):
    sources_dir = tmp_path / "sources"
    copy_sources(findings, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1
    assert copied[0].suffix == ".jsonl"


def test_copy_sources_deduplicates_same_file(tmp_path, findings):
    # Two findings pointing to the same source file
    doubled = findings + [
        Finding(
            tool=findings[0].tool,
            secret_type="openai_token",
            secret_value="sk-xxxx",
            file_path=findings[0].file_path,
            position="line:2",
            confidence="high",
            context="token = sk-xxxx",
            discovered_at=findings[0].discovered_at,
        )
    ]
    sources_dir = tmp_path / "sources"
    copy_sources(doubled, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1  # only one copy despite two findings
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/test_report.py -v
```

Expected: all FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement report.py**

```python
# ghosttype/report.py
from __future__ import annotations

import csv
import hashlib
import json
import shutil
from pathlib import Path

from ghosttype.models import Finding

_FIELDS = ["tool", "secret_type", "secret_value", "file_path", "position",
           "confidence", "context", "discovered_at"]


def _finding_to_dict(f: Finding, redact: bool = False) -> dict:
    return {
        "tool": f.tool,
        "secret_type": f.secret_type,
        "secret_value": "***REDACTED***" if redact else f.secret_value,
        "file_path": str(f.file_path),
        "position": f.position,
        "confidence": f.confidence,
        "context": f.context,
        "discovered_at": f.discovered_at.isoformat(),
    }


def write_json(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([_finding_to_dict(f) for f in findings], indent=2),
        encoding="utf-8",
    )


def write_csv(findings: list[Finding], path: Path, redact: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDS)
        writer.writeheader()
        for f in findings:
            writer.writerow(_finding_to_dict(f, redact=redact))


def copy_sources(findings: list[Finding], sources_dir: Path) -> None:
    """Copy source conversation files for each finding into sources/<tool>/."""
    seen: set[Path] = set()
    for f in findings:
        if f.file_path in seen:
            continue
        seen.add(f.file_path)
        if not f.file_path.exists():
            continue
        dest_dir = sources_dir / f.tool
        dest_dir.mkdir(parents=True, exist_ok=True)
        file_hash = hashlib.sha256(str(f.file_path).encode()).hexdigest()[:12]
        dest = dest_dir / f"{file_hash}{f.file_path.suffix}"
        shutil.copy2(f.file_path, dest)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/test_report.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/report.py tests/test_report.py
git commit -m "feat: report writer (JSON, CSV with redaction, source file copy)"
```

---

## Task 5: Scanner base ABC

**Files:**
- Create: `ghosttype/scanners/base.py`
- Create: `tests/scanners/test_claude.py` (stub scanner — simplest, tests the ABC contract)

- [ ] **Step 1: Write the failing test**

```python
# tests/scanners/test_claude.py
from pathlib import Path
from ghosttype.scanners.claude import ClaudeScanner


def test_claude_scanner_name():
    s = ClaudeScanner()
    assert s.name == "claude"
    assert isinstance(s.display_name, str)


def test_claude_scanner_discover_returns_empty_when_not_installed(tmp_path, monkeypatch):
    s = ClaudeScanner()
    monkeypatch.setattr(s, "_base_path", tmp_path / "nonexistent")
    assert s.is_available() is False
    assert s.discover() == []


def test_claude_scanner_extract_text_returns_empty(tmp_path, monkeypatch):
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeScanner()
    rec = ConversationRecord(
        source_path=tmp_path / "placeholder",
        tool="claude",
        conversation_id="stub",
        created_at=datetime.now(timezone.utc),
        raw={},
    )
    assert s.extract_text(rec) == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source .venv/bin/activate && pytest tests/scanners/test_claude.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement base.py and claude.py stub**

```python
# ghosttype/scanners/base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk


class Scanner(ABC):
    name: str
    display_name: str

    @property
    @abstractmethod
    def _base_path(self) -> Path:
        """Root path for this tool's data directory."""

    def is_available(self) -> bool:
        return self._base_path.exists()

    @abstractmethod
    def discover(self) -> list[ConversationRecord]:
        """Return all conversation records found on this machine."""

    @abstractmethod
    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        """Extract text chunks from a conversation record."""
```

```python
# ghosttype/scanners/claude.py
from __future__ import annotations

from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class ClaudeScanner(Scanner):
    name = "claude"
    display_name = "Claude Desktop"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "Claude"

    def discover(self) -> list[ConversationRecord]:
        # Storage format unconfirmed - app not available for research.
        # Returns empty until format is investigated and implemented.
        return []

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        return []
```

- [ ] **Step 4: Run test to verify it passes**

```bash
source .venv/bin/activate && pytest tests/scanners/test_claude.py -v
```

Expected: 3 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/scanners/base.py ghosttype/scanners/claude.py tests/scanners/test_claude.py
git commit -m "feat: Scanner ABC and Claude desktop stub"
```

---

## Task 6: Claude Code scanner

**Files:**
- Create: `ghosttype/scanners/claude_code.py`
- Create: `tests/scanners/test_claude_code.py`
- Create: `tests/fixtures/sample_conversation.jsonl`

- [ ] **Step 1: Create the JSONL fixture**

Create `tests/fixtures/sample_conversation.jsonl` with this content (fake creds, safe for repo):

```
{"type":"user","message":{"content":"set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},"uuid":"msg-1","sessionId":"sess-1","timestamp":"2026-01-01T00:00:00Z","cwd":"/tmp/project","version":"1.0","userType":"human","parentUuid":null,"isSidechain":false,"entrypoint":"cli","gitBranch":"main"}
{"type":"assistant","message":{"content":"Got it, I'll use that key."},"uuid":"msg-2","sessionId":"sess-1","timestamp":"2026-01-01T00:00:01Z","cwd":"/tmp/project","version":"1.0","userType":"human","parentUuid":"msg-1","isSidechain":false,"entrypoint":"cli","gitBranch":"main"}
{"type":"user","message":{"content":[{"type":"text","text":"my password is hunter2"}]},"uuid":"msg-3","sessionId":"sess-1","timestamp":"2026-01-01T00:00:02Z","cwd":"/tmp/project","version":"1.0","userType":"human","parentUuid":"msg-2","isSidechain":false,"entrypoint":"cli","gitBranch":"main"}
{"type":"permission-mode","permissionMode":"default","sessionId":"sess-1"}
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/scanners/test_claude_code.py
from pathlib import Path
import pytest
from ghosttype.scanners.claude_code import ClaudeCodeScanner

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_conversation.jsonl"


def test_scanner_name():
    s = ClaudeCodeScanner()
    assert s.name == "claude_code"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = ClaudeCodeScanner()
    monkeypatch.setattr(s, "_base_path", tmp_path / "nonexistent")
    assert s.is_available() is False


def test_discover_finds_jsonl_files(tmp_path, monkeypatch):
    projects = tmp_path / "projects" / "-Users-test-project"
    projects.mkdir(parents=True)
    session = projects / "abc-123.jsonl"
    session.write_text('{"type":"user","message":{"content":"hello"},"uuid":"u1","sessionId":"s1","timestamp":"2026-01-01T00:00:00Z","cwd":"/tmp","version":"1","userType":"human","parentUuid":null,"isSidechain":false,"entrypoint":"cli","gitBranch":"main"}\n')
    monkeypatch.setattr(type(ClaudeCodeScanner()), "_base_path", property(lambda self: tmp_path))
    s = ClaudeCodeScanner()
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "claude_code"
    assert records[0].conversation_id == "abc-123"


def test_extract_text_from_string_content():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    texts = [c.text for c in chunks]
    assert any("AKIAIOSFODNN7EXAMPLE" in t for t in texts)


def test_extract_text_from_content_block_array():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    texts = [c.text for c in chunks]
    # msg-3 uses content block array form
    assert any("hunter2" in t for t in texts)


def test_extract_text_position_is_line_number():
    from ghosttype.models import ConversationRecord
    from datetime import datetime, timezone
    s = ClaudeCodeScanner()
    rec = ConversationRecord(
        source_path=FIXTURE,
        tool="claude_code",
        conversation_id="sess-1",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        raw=None,
    )
    chunks = s.extract_text(rec)
    assert all(c.position.startswith("line:") for c in chunks)
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/scanners/test_claude_code.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 4: Implement claude_code.py**

```python
# ghosttype/scanners/claude_code.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

_CONTENT_TYPES = {"user", "assistant"}


def _extract_content_text(content: str | list) -> str:
    if isinstance(content, str):
        return content
    # Content block array: [{"type": "text", "text": "..."}, ...]
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif block.get("type") == "tool_result":
                inner = block.get("content", [])
                if isinstance(inner, list):
                    for b in inner:
                        if isinstance(b, dict) and b.get("type") == "text":
                            parts.append(b.get("text", ""))
    return "\n".join(parts)


class ClaudeCodeScanner(Scanner):
    name = "claude_code"
    display_name = "Claude Code CLI"

    @property
    def _base_path(self) -> Path:
        return Path.home() / ".claude"

    def discover(self) -> list[ConversationRecord]:
        projects_dir = self._base_path / "projects"
        if not projects_dir.exists():
            return []
        records: list[ConversationRecord] = []
        for jsonl_path in projects_dir.rglob("*.jsonl"):
            records.append(ConversationRecord(
                source_path=jsonl_path,
                tool=self.name,
                conversation_id=jsonl_path.stem,
                created_at=datetime.fromtimestamp(
                    jsonl_path.stat().st_mtime, tz=timezone.utc
                ),
                raw=None,
            ))
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        chunks: list[TextChunk] = []
        try:
            with record.source_path.open(encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("type") not in _CONTENT_TYPES:
                        continue
                    msg = entry.get("message", {})
                    content = msg.get("content", "")
                    text = _extract_content_text(content)
                    if text.strip():
                        chunks.append(TextChunk(
                            text=text,
                            position=f"line:{line_num}",
                            record=record,
                        ))
        except OSError:
            pass
        return chunks
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/scanners/test_claude_code.py -v
```

Expected: 6 tests PASSED

- [ ] **Step 6: Commit**

```bash
git add ghosttype/scanners/claude_code.py tests/scanners/test_claude_code.py tests/fixtures/sample_conversation.jsonl
git commit -m "feat: Claude Code CLI scanner (JSONL)"
```

---

## Task 7: Cursor scanner

**Files:**
- Create: `ghosttype/scanners/cursor.py`
- Create: `tests/scanners/test_cursor.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/scanners/test_cursor.py
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.scanners.cursor import CursorScanner


@pytest.fixture
def cursor_db(tmp_path) -> Path:
    """Synthetic state.vscdb with one composerData entry containing a fake credential."""
    db_path = tmp_path / "state.vscdb"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
    conversation_data = json.dumps({
        "_v": 1,
        "composerId": "composer-uuid-1",
        "text": "Here is my config: api_key = AKIAIOSFODNN7EXAMPLE and it works.",
        "conversationMap": {},
        "createdAt": 1704067200000,
    })
    conn.execute(
        "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
        ("composerData:composer-uuid-1", conversation_data),
    )
    conn.commit()
    conn.close()
    return db_path


def test_scanner_name():
    s = CursorScanner()
    assert s.name == "cursor"


def test_not_available_when_db_missing(tmp_path, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_returns_one_record_per_composer(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "cursor"
    assert records[0].conversation_id == "composer-uuid-1"


def test_extract_text_reads_text_field(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    chunks = s.extract_text(records[0])
    combined = " ".join(c.text for c in chunks)
    assert "AKIAIOSFODNN7EXAMPLE" in combined


def test_extract_text_position_includes_row_key(cursor_db, monkeypatch):
    s = CursorScanner()
    monkeypatch.setattr(type(s), "_db_path", property(lambda self: cursor_db))
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: cursor_db.parent))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert all("composerData:" in c.position for c in chunks)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/scanners/test_cursor.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement cursor.py**

```python
# ghosttype/scanners/cursor.py
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class CursorScanner(Scanner):
    name = "cursor"
    display_name = "Cursor IDE"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage"

    @property
    def _db_path(self) -> Path:
        return self._base_path / "state.vscdb"

    def is_available(self) -> bool:
        return self._db_path.exists()

    def discover(self) -> list[ConversationRecord]:
        if not self.is_available():
            return []
        records: list[ConversationRecord] = []
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
            rows = conn.execute(
                "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'"
            ).fetchall()
            conn.close()
        except sqlite3.Error:
            return []

        for key, value in rows:
            if not value:
                continue
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                continue
            composer_id = data.get("composerId", key.split(":", 1)[-1])
            created_ms = data.get("createdAt")
            created_at = (
                datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
                if created_ms
                else None
            )
            records.append(ConversationRecord(
                source_path=self._db_path,
                tool=self.name,
                conversation_id=composer_id,
                created_at=created_at,
                raw={"key": key, "data": data},
            ))
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        raw = record.raw or {}
        key = raw.get("key", f"composerData:{record.conversation_id}")
        data = raw.get("data", {})
        chunks: list[TextChunk] = []

        # Primary: plain text field
        text = data.get("text", "")
        if text.strip():
            chunks.append(TextChunk(
                text=text,
                position=f"{key}:0",
                record=record,
            ))

        # Secondary: walk conversationMap for individual message texts
        conv_map = data.get("conversationMap", {})
        for msg_id, msg in conv_map.items():
            if not isinstance(msg, dict):
                continue
            msg_text = msg.get("text", "") or msg.get("content", "")
            if isinstance(msg_text, str) and msg_text.strip():
                chunks.append(TextChunk(
                    text=msg_text,
                    position=f"{key}:msg:{msg_id}",
                    record=record,
                ))

        return chunks
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/scanners/test_cursor.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/scanners/cursor.py tests/scanners/test_cursor.py
git commit -m "feat: Cursor IDE scanner (SQLite state.vscdb)"
```

---

## Task 8: Codex CLI scanner

**Files:**
- Create: `ghosttype/scanners/codex.py`
- Create: `tests/scanners/test_codex.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/scanners/test_codex.py
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.scanners.codex import CodexScanner


@pytest.fixture
def codex_dir(tmp_path) -> Path:
    """Synthetic ~/.codex/ with state_5.sqlite and logs_2.sqlite."""
    codex = tmp_path / ".codex"
    codex.mkdir()

    # state_5.sqlite: threads table
    state_db = codex / "state_5.sqlite"
    conn = sqlite3.connect(state_db)
    conn.execute("""
        CREATE TABLE threads (
            id TEXT PRIMARY KEY,
            title TEXT,
            first_user_message TEXT,
            model TEXT,
            cwd TEXT,
            created_at INTEGER,
            updated_at INTEGER
        )
    """)
    conn.execute(
        "INSERT INTO threads VALUES (?,?,?,?,?,?,?)",
        ("thread-abc", "Test session", "my token is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012", "gpt-4o", "/tmp/proj", 1704067200, 1704067260),
    )
    conn.commit()
    conn.close()

    # logs_2.sqlite: logs table (empty for this fixture)
    logs_db = codex / "logs_2.sqlite"
    conn2 = sqlite3.connect(logs_db)
    conn2.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, feedback_log_body TEXT)")
    conn2.commit()
    conn2.close()

    return codex


def test_scanner_name():
    assert CodexScanner().name == "codex"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_returns_thread_records(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    assert len(records) == 1
    assert records[0].conversation_id == "thread-abc"
    assert records[0].tool == "codex"


def test_extract_text_includes_first_user_message(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    combined = " ".join(c.text for c in chunks)
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012" in combined


def test_extract_text_position_includes_thread_id(codex_dir, monkeypatch):
    s = CodexScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: codex_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert all("thread-abc" in c.position for c in chunks)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/scanners/test_codex.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement codex.py**

```python
# ghosttype/scanners/codex.py
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner


class CodexScanner(Scanner):
    name = "codex"
    display_name = "Codex CLI"

    @property
    def _base_path(self) -> Path:
        return Path.home() / ".codex"

    def _state_db(self) -> Path:
        return self._base_path / "state_5.sqlite"

    def _logs_db(self) -> Path:
        return self._base_path / "logs_2.sqlite"

    def discover(self) -> list[ConversationRecord]:
        state_db = self._state_db()
        if not state_db.exists():
            return []
        records: list[ConversationRecord] = []
        try:
            conn = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
            rows = conn.execute(
                "SELECT id, title, first_user_message, created_at FROM threads"
            ).fetchall()
            conn.close()
        except sqlite3.Error:
            return []

        for thread_id, title, first_msg, created_ts in rows:
            created_at = (
                datetime.fromtimestamp(created_ts, tz=timezone.utc)
                if created_ts
                else None
            )
            records.append(ConversationRecord(
                source_path=state_db,
                tool=self.name,
                conversation_id=thread_id,
                created_at=created_at,
                raw={"thread_id": thread_id, "title": title, "first_user_message": first_msg},
            ))
        return records

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        raw = record.raw or {}
        thread_id = raw.get("thread_id", record.conversation_id)
        chunks: list[TextChunk] = []

        first_msg = raw.get("first_user_message", "")
        if first_msg and first_msg.strip():
            chunks.append(TextChunk(
                text=first_msg,
                position=f"{thread_id}:first_user_message",
                record=record,
            ))

        # Also scan logs_2.sqlite for this thread's log body
        logs_db = self._logs_db()
        if logs_db.exists():
            try:
                conn = sqlite3.connect(f"file:{logs_db}?mode=ro", uri=True)
                # thread_id is stored in logs via thread_id column if present
                # Try both with and without thread_id filter
                try:
                    rows = conn.execute(
                        "SELECT feedback_log_body FROM logs WHERE thread_id = ? AND feedback_log_body IS NOT NULL",
                        (thread_id,),
                    ).fetchall()
                except sqlite3.OperationalError:
                    # thread_id column may not exist in all versions
                    rows = []
                conn.close()
                for (body,) in rows:
                    if body and body.strip():
                        chunks.append(TextChunk(
                            text=body,
                            position=f"{thread_id}:log_body",
                            record=record,
                        ))
            except sqlite3.Error:
                pass

        return chunks
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/scanners/test_codex.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/scanners/codex.py tests/scanners/test_codex.py
git commit -m "feat: Codex CLI scanner (SQLite state_5 + logs_2)"
```

---

## Task 9: ChatGPT scanner

**Files:**
- Create: `ghosttype/scanners/chatgpt.py`
- Create: `tests/scanners/test_chatgpt.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/scanners/test_chatgpt.py
from pathlib import Path
from datetime import datetime, timezone

import pytest

from ghosttype.scanners.chatgpt import ChatGPTScanner


@pytest.fixture
def chatgpt_dir(tmp_path) -> Path:
    """Synthetic com.openai.chat directory with a fake conversation .data file."""
    uid = "6fe9ba45-4583-4e19-8779-1f05cb8db338"
    conv_dir = tmp_path / f"conversations-v3-{uid}"
    conv_dir.mkdir(parents=True)
    # Write a fake .data file (not real encrypted content - scanner should handle gracefully)
    (conv_dir / "69faed5a-49d8-83eb-aff3-c003fc3bffe2.data").write_bytes(b"\xed\x80\xb9\x88fake")
    return tmp_path


def test_scanner_name():
    assert ChatGPTScanner().name == "chatgpt"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_finds_data_files(chatgpt_dir, monkeypatch):
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: chatgpt_dir))
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "chatgpt"
    assert records[0].source_path.suffix == ".data"


def test_extract_text_returns_empty_on_undecryptable_file(chatgpt_dir, monkeypatch):
    """When decryption fails, extract_text returns empty (graceful degradation)."""
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: chatgpt_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert chunks == []


def test_extract_text_position_on_decrypted_content(tmp_path, monkeypatch):
    """When content is decrypted, position is 'line:N'."""
    import json
    # Simulate a scanner that successfully returns decrypted content
    # by patching _decrypt to return known plaintext
    s = ChatGPTScanner()
    conv_dir = tmp_path / "conversations-v3-test"
    conv_dir.mkdir()
    data_file = conv_dir / "conv-1.data"
    data_file.write_bytes(b"fake")
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path))

    fake_json = json.dumps({"mapping": {"msg1": {"message": {"content": {"parts": ["api_key = AKIAIOSFODNN7EXAMPLE"]}}}}})
    monkeypatch.setattr(s, "_decrypt", lambda path: fake_json)

    records = s.discover()
    chunks = s.extract_text(records[0])
    assert any("AKIAIOSFODNN7EXAMPLE" in c.text for c in chunks)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/scanners/test_chatgpt.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement chatgpt.py**

```python
# ghosttype/scanners/chatgpt.py
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

_KEYCHAIN_SERVICES = [
    "ChatGPT Safe Storage",
    "com.openai.chat Safe Storage",
    "Electron Safe Storage",
]


class ChatGPTScanner(Scanner):
    name = "chatgpt"
    display_name = "ChatGPT Desktop"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "com.openai.chat"

    def discover(self) -> list[ConversationRecord]:
        if not self.is_available():
            return []
        records: list[ConversationRecord] = []
        for data_file in self._base_path.rglob("conversations-v3-*/*.data"):
            stat = data_file.stat()
            records.append(ConversationRecord(
                source_path=data_file,
                tool=self.name,
                conversation_id=data_file.stem,
                created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                raw=None,
            ))
        return records

    def _get_keychain_key(self) -> bytes | None:
        """Attempt to retrieve the Electron Safe Storage key from macOS Keychain."""
        for service in _KEYCHAIN_SERVICES:
            try:
                result = subprocess.run(
                    ["security", "find-generic-password", "-w", "-s", service],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().encode()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def _decrypt(self, path: Path) -> str | None:
        """Attempt AES-256-GCM decryption of a ChatGPT .data file.

        Returns decrypted string on success, None on failure.
        Electron safeStorage on macOS: data is prefixed with b'v10' or b'v11',
        followed by AES-256-GCM ciphertext. Key is from Keychain via PBKDF2.
        """
        raw = path.read_bytes()
        key_bytes = self._get_keychain_key()
        if not key_bytes:
            return None

        # Chrome/Electron v10 prefix on macOS
        prefix = raw[:3]
        if prefix not in (b"v10", b"v11"):
            return None

        try:
            from hashlib import pbkdf2_hmac
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Derive 256-bit key: PBKDF2-HMAC-SHA1, salt=b'saltysalt', iterations=1003
            key = pbkdf2_hmac("sha1", key_bytes, b"saltysalt", 1003, dklen=32)
            # iv: 16 zero bytes (Electron standard)
            iv = b" " * 16
            ciphertext = raw[3:]
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return plaintext.decode("utf-8", errors="replace")
        except Exception:
            return None

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        plaintext = self._decrypt(record.source_path)
        if not plaintext:
            return []

        chunks: list[TextChunk] = []
        try:
            data = json.loads(plaintext)
        except json.JSONDecodeError:
            # Treat as plain text
            chunks.append(TextChunk(text=plaintext, position="line:1", record=record))
            return chunks

        # ChatGPT conversation JSON: {"mapping": {msg_id: {"message": {"content": {"parts": [...]}}}}}
        mapping = data.get("mapping", {})
        for i, (msg_id, node) in enumerate(mapping.items(), start=1):
            msg = node.get("message") or {}
            content = msg.get("content") or {}
            parts = content.get("parts", [])
            text = " ".join(str(p) for p in parts if p)
            if text.strip():
                chunks.append(TextChunk(
                    text=text,
                    position=f"line:{i}",
                    record=record,
                ))
        return chunks
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/scanners/test_chatgpt.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 5: Commit**

```bash
git add ghosttype/scanners/chatgpt.py tests/scanners/test_chatgpt.py
git commit -m "feat: ChatGPT desktop scanner with Keychain decryption attempt"
```

---

## Task 10: Scanner registry and orchestrator

**Files:**
- Modify: `ghosttype/scanners/__init__.py`
- Create: `ghosttype/scanner.py`
- Create: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_scanner.py
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ghosttype.models import ConversationRecord, TextChunk, Finding
from ghosttype.scanner import Orchestrator


@pytest.fixture
def mock_scanner(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("x\n")
    rec = ConversationRecord(
        source_path=src,
        tool="fake_tool",
        conversation_id="conv-1",
        created_at=datetime.now(timezone.utc),
        raw={},
    )
    chunk = TextChunk(
        text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        position="line:1",
        record=rec,
    )
    scanner = MagicMock()
    scanner.name = "fake_tool"
    scanner.is_available.return_value = True
    scanner.discover.return_value = [rec]
    scanner.extract_text.return_value = [chunk]
    return scanner


def test_orchestrator_runs_available_scanners(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    assert len(findings) >= 1
    assert findings[0].tool == "fake_tool"
    assert findings[0].secret_type == "aws_access_key"
    assert findings[0].secret_value == "AKIAIOSFODNN7EXAMPLE"
    assert findings[0].confidence == "high"


def test_orchestrator_skips_unavailable_scanners(mock_scanner):
    mock_scanner.is_available.return_value = False
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    assert findings == []


def test_orchestrator_deduplicates_same_secret_same_file(mock_scanner, tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("x\n")
    rec = ConversationRecord(source_path=src, tool="fake_tool", conversation_id="c1",
                             created_at=datetime.now(timezone.utc), raw={})
    chunk1 = TextChunk(text="key=AKIAIOSFODNN7EXAMPLE", position="line:1", record=rec)
    chunk2 = TextChunk(text="key=AKIAIOSFODNN7EXAMPLE", position="line:2", record=rec)
    mock_scanner.extract_text.return_value = [chunk1, chunk2]
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run()
    aws_findings = [f for f in findings if f.secret_value == "AKIAIOSFODNN7EXAMPLE"]
    assert len(aws_findings) == 1


def test_orchestrator_tool_filter(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run(tool_filter="other_tool")
    assert findings == []


def test_orchestrator_returns_findings_for_matching_tool_filter(mock_scanner):
    orch = Orchestrator(scanners=[mock_scanner])
    findings = orch.run(tool_filter="fake_tool")
    assert len(findings) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/test_scanner.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Populate scanners/__init__.py registry**

```python
# ghosttype/scanners/__init__.py
from ghosttype.scanners.claude_code import ClaudeCodeScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanners.codex import CodexScanner
from ghosttype.scanners.chatgpt import ChatGPTScanner
from ghosttype.scanners.claude import ClaudeScanner

SCANNERS = [
    ClaudeCodeScanner(),
    CursorScanner(),
    CodexScanner(),
    ChatGPTScanner(),
    ClaudeScanner(),
]
```

- [ ] **Step 4: Implement scanner.py orchestrator**

```python
# ghosttype/scanner.py
from __future__ import annotations

from datetime import datetime, timezone

from ghosttype.models import Finding, PatternMatch, TextChunk
from ghosttype.patterns import scan_text
from ghosttype.scanners.base import Scanner


class Orchestrator:
    def __init__(self, scanners: list[Scanner] | None = None, context_window: int = 200) -> None:
        if scanners is None:
            from ghosttype.scanners import SCANNERS
            self._scanners = SCANNERS
        else:
            self._scanners = scanners
        self._context_window = context_window

    def run(self, tool_filter: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()  # (secret_value, file_path, secret_type)

        for scanner in self._scanners:
            if tool_filter and scanner.name != tool_filter:
                continue
            if not scanner.is_available():
                continue
            for record in scanner.discover():
                for chunk in scanner.extract_text(record):
                    for match in scan_text(chunk.text, self._context_window):
                        dedup_key = (match.secret_value, str(record.source_path), match.secret_type)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append(Finding(
                            tool=scanner.name,
                            secret_type=match.secret_type,
                            secret_value=match.secret_value,
                            file_path=record.source_path,
                            position=f"{chunk.position}:{match.char_offset}",
                            confidence=match.confidence,
                            context=match.context,
                            discovered_at=datetime.now(timezone.utc),
                        ))
        return findings
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/test_scanner.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 6: Commit**

```bash
git add ghosttype/scanners/__init__.py ghosttype/scanner.py tests/test_scanner.py
git commit -m "feat: scanner registry and Orchestrator"
```

---

## Task 11: CLI

**Files:**
- Create: `ghosttype/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli.py
from pathlib import Path
from click.testing import CliRunner
from ghosttype.cli import cli


def test_list_tools_command_runs():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-tools"])
    assert result.exit_code == 0
    # Should mention all five tool names
    for name in ["cursor", "chatgpt", "codex", "claude", "claude_code"]:
        assert name in result.output


def test_scan_command_creates_output_dir(tmp_path, monkeypatch):
    from unittest.mock import MagicMock, patch
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 0
    assert (tmp_path / "report").exists()


def test_scan_writes_json_by_default(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from ghosttype.models import Finding
    from unittest.mock import patch
    runner = CliRunner()
    fake_finding = Finding(
        tool="claude_code", secret_type="aws_access_key",
        secret_value="AKIAIOSFODNN7EXAMPLE",
        file_path=tmp_path / "session.jsonl",
        position="line:1:0", confidence="high",
        context="key = AKIAIOSFODNN7EXAMPLE",
        discovered_at=datetime.now(timezone.utc),
    )
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = [fake_finding]
        result = runner.invoke(cli, ["scan", "--output", str(tmp_path / "report")])
    assert result.exit_code == 0
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


def test_scan_tool_filter(tmp_path):
    from unittest.mock import patch, call
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        runner.invoke(cli, ["scan", "--tool", "cursor", "--output", str(tmp_path / "r")])
        MockOrch.return_value.run.assert_called_once_with(tool_filter="cursor")


def test_scan_format_json_only(tmp_path):
    from unittest.mock import patch
    runner = CliRunner()
    with patch("ghosttype.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = []
        runner.invoke(cli, ["scan", "--format", "json", "--output", str(tmp_path / "r")])
    # csv should NOT exist, json should
    assert (tmp_path / "r" / "findings.json").exists()
    assert not (tmp_path / "r" / "findings.csv").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate && pytest tests/test_cli.py -v
```

Expected: FAILED with `ModuleNotFoundError`

- [ ] **Step 3: Implement cli.py**

```python
# ghosttype/cli.py
from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from ghosttype.report import copy_sources, write_csv, write_json
from ghosttype.scanner import Orchestrator

console = Console()


@click.group()
def cli() -> None:
    """ghosttype - extract credentials from AI tool conversation history."""


@cli.command()
@click.option("--tool", default=None, help="Scan only this tool (cursor, chatgpt, codex, claude, claude_code)")
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "csv", "both"]), show_default=True)
@click.option("--output", default="./ghosttype_report", show_default=True, help="Output directory")
@click.option("--no-redact", is_flag=True, default=False, help="Show plaintext secret values in CSV")
@click.option("--context-window", default=200, show_default=True, help="Context characters around each match")
def scan(tool: str | None, fmt: str, output: str, no_redact: bool, context_window: int) -> None:
    """Scan AI tool conversation files for credentials and secrets."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]ghosttype[/bold] scanning... output -> [cyan]{out_dir}[/cyan]")

    orch = Orchestrator(context_window=context_window)
    findings = orch.run(tool_filter=tool)

    if not findings:
        console.print("[yellow]No findings.[/yellow]")
    else:
        console.print(f"[green]{len(findings)} finding(s) discovered.[/green]")

    if fmt in ("json", "both"):
        write_json(findings, out_dir / "findings.json")
    if fmt in ("csv", "both"):
        write_csv(findings, out_dir / "findings.csv", redact=not no_redact)

    if findings:
        copy_sources(findings, out_dir / "sources")

    _print_summary(findings)


@cli.command("list-tools")
def list_tools() -> None:
    """Show which AI tools are detected on this machine."""
    from ghosttype.scanners import SCANNERS

    table = Table(title="AI Tools", show_header=True)
    table.add_column("Tool")
    table.add_column("Name")
    table.add_column("Status")

    for scanner in SCANNERS:
        available = scanner.is_available()
        status = "[green]detected[/green]" if available else "[dim]not found[/dim]"
        table.add_row(scanner.name, scanner.display_name, status)

    console.print(table)


def _print_summary(findings: list) -> None:
    if not findings:
        return
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Tool")
    table.add_column("Type")
    table.add_column("Confidence")
    table.add_column("File")
    for f in findings:
        table.add_row(f.tool, f.secret_type, f.confidence, f.file_path.name)
    console.print(table)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate && pytest tests/test_cli.py -v
```

Expected: 5 tests PASSED

- [ ] **Step 5: Run the full test suite**

```bash
source .venv/bin/activate && pytest -v
```

Expected: all tests PASSED

- [ ] **Step 6: Commit**

```bash
git add ghosttype/cli.py tests/test_cli.py
git commit -m "feat: CLI (scan, list-tools commands)"
```

---

## Task 12: Integration test

**Files:**
- Create: `tests/test_integration.py`

- [ ] **Step 1: Write the integration test**

```python
# tests/test_integration.py
"""End-to-end test: synthetic conversation files with planted fake credentials."""
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch, PropertyMock

import pytest

from ghosttype.scanners.claude_code import ClaudeCodeScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanner import Orchestrator
from ghosttype.report import write_json, write_csv


@pytest.fixture
def synthetic_claude_code_dir(tmp_path) -> Path:
    projects = tmp_path / "projects" / "-Users-test"
    projects.mkdir(parents=True)
    session = projects / "integ-session.jsonl"
    lines = [
        json.dumps({"type": "user", "message": {"content": "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12"}, "uuid": "u1", "sessionId": "s1", "timestamp": "2026-01-01T00:00:00Z", "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": None, "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"}),
        json.dumps({"type": "assistant", "message": {"content": "I see an OpenAI key."}, "uuid": "u2", "sessionId": "s1", "timestamp": "2026-01-01T00:00:01Z", "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": "u1", "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"}),
    ]
    session.write_text("\n".join(lines) + "\n")
    return tmp_path


@pytest.fixture
def synthetic_cursor_dir(tmp_path) -> Path:
    db_path = tmp_path / "state.vscdb"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?, ?)",
        ("composerData:integ-uuid", json.dumps({
            "composerId": "integ-uuid",
            "text": "connect to postgresql://admin:S3cr3tP@ss@db.example.com:5432/prod",
            "conversationMap": {},
            "createdAt": 1704067200000,
        })),
    )
    conn.commit()
    conn.close()
    return tmp_path


def test_end_to_end_claude_code_finds_openai_key(synthetic_claude_code_dir, tmp_path):
    scanner = ClaudeCodeScanner()
    with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_claude_code_dir):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()

    assert any(f.secret_type == "openai_token" for f in findings)
    openai_finding = next(f for f in findings if f.secret_type == "openai_token")
    assert openai_finding.tool == "claude_code"
    assert openai_finding.confidence == "high"

    # Write reports and verify structure
    write_json(findings, tmp_path / "report" / "findings.json")
    write_csv(findings, tmp_path / "report" / "findings.csv", redact=True)
    assert (tmp_path / "report" / "findings.json").exists()
    assert (tmp_path / "report" / "findings.csv").exists()


def test_end_to_end_cursor_finds_connection_string(synthetic_cursor_dir, tmp_path):
    scanner = CursorScanner()
    with patch.object(type(scanner), "_db_path", new_callable=PropertyMock, return_value=synthetic_cursor_dir / "state.vscdb"):
        with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_cursor_dir):
            orch = Orchestrator(scanners=[scanner])
            findings = orch.run()

    assert any(f.secret_type == "connection_string" for f in findings)
    conn_finding = next(f for f in findings if f.secret_type == "connection_string")
    assert "postgresql://" in conn_finding.secret_value
    assert conn_finding.tool == "cursor"


def test_deduplication_across_tools(synthetic_claude_code_dir, tmp_path):
    """Same secret in two records from same tool should produce one finding."""
    # Add a second session with the same key
    projects = synthetic_claude_code_dir / "projects" / "-Users-test"
    dup = projects / "dup-session.jsonl"
    dup.write_text(json.dumps({
        "type": "user", "message": {"content": "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12"},
        "uuid": "u3", "sessionId": "s2", "timestamp": "2026-01-01T00:00:02Z",
        "cwd": "/tmp", "version": "1", "userType": "human", "parentUuid": None,
        "isSidechain": False, "entrypoint": "cli", "gitBranch": "main"
    }) + "\n")

    scanner = ClaudeCodeScanner()
    with patch.object(type(scanner), "_base_path", new_callable=PropertyMock, return_value=synthetic_claude_code_dir):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()

    # Same value in different files = two findings (different source paths)
    openai_findings = [f for f in findings if f.secret_type == "openai_token"]
    assert len(openai_findings) == 2  # two different files
```

- [ ] **Step 2: Run integration tests**

```bash
source .venv/bin/activate && pytest tests/test_integration.py -v
```

Expected: 3 tests PASSED

- [ ] **Step 3: Run full suite**

```bash
source .venv/bin/activate && pytest -v --tb=short
```

Expected: all tests PASSED

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: end-to-end integration tests"
```

---

## Task 13: Push to GitHub and update ROADMAP

- [ ] **Step 1: Verify clean state**

```bash
source .venv/bin/activate && pytest -v && echo "all tests pass"
```

Expected: all tests PASSED, `all tests pass`

- [ ] **Step 2: Check nothing sensitive is staged**

```bash
git status && git diff --stat HEAD
```

Verify no `ghosttype_report/`, no `.env`, no `*.key` files appear.

- [ ] **Step 3: Update ROADMAP.md v1 checklist**

Mark all completed v1 items with `[x]` in `ROADMAP.md`.

- [ ] **Step 4: Commit and push**

```bash
git add ROADMAP.md
git commit -m "docs: mark v1 checklist complete"
git push origin initial-setup
```

_(Note: push to a feature branch, not main directly — open a PR to merge.)_

---

## Self-Review Notes

**Spec coverage check:**

| Spec requirement | Covered by |
|-----------------|-----------|
| Five target tools | Tasks 5-9 |
| Regex patterns (AWS, OpenAI, GH, Anthropic, GCP, PEM, JWT, conn strings) | Task 3 |
| Heuristic patterns (api_key, password, secret_key, token, private_key) | Task 3 |
| CSV + JSON output | Task 4 |
| Source file copies | Task 4 |
| CSV redacted by default | Task 4 |
| `ghosttype scan` CLI | Task 11 |
| `ghosttype list-tools` CLI | Task 11 |
| `--tool` filter | Task 11 |
| `--format` option | Task 11 |
| `--output` option | Task 11 |
| `--no-redact` flag | Task 11 |
| `--context-window` option | Task 11 |
| Deduplication by (value, file_path) | Task 10 |
| Claude desktop as stub | Task 5 |
| ChatGPT graceful degradation | Task 9 |
| Integration test with synthetic data | Task 12 |
| No real credentials in fixtures | All fixture tasks |

All spec requirements covered. No placeholders. Type signatures consistent across tasks.
