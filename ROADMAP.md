# Roadmap

## v1.0 - Local macOS Scanner (current)

**Goal:** Working end-to-end scan on macOS. All five tools. CSV + JSON output with source file copies.

### Scope

- [x] Scanner framework (`base.py`, orchestrator, pattern engine, report writer)
- [x] Cursor scanner (SQLite `state.vscdb` - `cursorDiskKV` table)
- [x] ChatGPT scanner (`.data` file discovery; Keychain decryption attempt)
- [x] Codex CLI scanner (`~/.codex/` SQLite databases)
- [x] Claude desktop scanner (`~/Library/Application Support/Claude/` - pending install/research)
- [x] Claude Code scanner (`~/.claude/projects/**/*.jsonl`)
- [x] Regex pattern engine (AWS, OpenAI, GitHub, Anthropic, GCP, JWT, connection strings, PEM)
- [x] Heuristic pattern engine (variable name context signals)
- [x] CSV + JSON report writer with source file copy
- [x] CLI (`ghosttype scan [--tool X] [--format Y] [--output Z]`)
- [x] `ghosttype list-tools` command (show which tools are detected on this machine)
- [x] Basic test suite (pattern engine unit tests, scanner unit tests with fixtures)
- [x] pyproject.toml with entry point

### Out of scope for v1

- Linux / Windows support
- Cloud/network enumeration
- LLM-assisted detection
- Automatic credential rotation
- GUI

---

## v2.0 - Multi-platform + Cloud

- Linux and Windows path support for all scanners
- ChatGPT full decryption (research Chrome safeStorage key derivation)
- Claude desktop confirmed storage format (once installed and researched)
- Optional: cloud conversation fetch via API (ChatGPT export, Claude.ai export)
- Pattern: Slack tokens, Azure credentials, generic SSH keys

---

## v3.0 - Active Response Integrations

- Integration with BLACKBEARD for red team workflows (loot staging)
- Integration with credential rotation APIs (rotate found keys automatically - blue team mode)
- SIEM-compatible output (CEF, Splunk HEC)
- Configurable custom pattern files

---

## Deferred / Backlog

- Support for Copilot (GitHub Copilot chat history in VS Code)
- Support for Codeium / Windsurf
- Support for JetBrains AI Assistant
- Support for Gemini CLI (`~/.gemini/`)
- Memory extraction (Codex memories, Claude memory files)
- Pattern false-positive reduction (entropy scoring, context window expansion)
- `--watch` mode for continuous monitoring

---

## v2.0 - Pattern Expansion (MERGED)

- [x] 14 new credential patterns (Stripe, Slack, SendGrid, GitHub App/User, Vault, Linear, Databricks, npm, Telegram, Azure heuristic)
- [x] AWS Secret Access Key heuristic (variable-name context)
- [x] JWT signing secret heuristic
- [x] Entropy-based FP filtering (3.0 bits/char threshold, industry standard)
- [x] Known-example exclusion list (AWS doc keys, jwt.io examples)
- [x] Placeholder stem/suffix pattern filters
- [x] Unredacted output by default; `--redact` flag for safe sharing
- [x] `--min-confidence` filter (high/medium)
- [x] `files_scanned` counter in CLI output
- [x] Skip empty output files when no findings
- [x] Realistic test fixtures (5 JSONL scenarios + Cursor SQLite)
- [x] 66 tests

---

## v3.0 - Coverage Expansion (in progress)

### Scope

- [ ] Apply known-example filter to regex matches (AKIAIOSFODNN7EXAMPLE etc.)
- [ ] `severity` field on Finding (critical/high/medium)
- [ ] Sort findings: high severity first, then by type
- [ ] Claude Code: scan history.jsonl (command history with credential args)
- [ ] Cursor: scan workspaceStorage/*.vscdb (not just globalStorage)
- [ ] More token patterns: Hugging Face, DigitalOcean, GitHub OAuth/Refresh
- [ ] `ghosttype version` command
- [ ] Rich summary breakdown (by type + by tool)
- [ ] `--allow-list` file for suppressing reviewed FPs
- [ ] `--stats-only` flag

