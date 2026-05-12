# Roadmap

## v1.0 - Local macOS Scanner (current)

**Goal:** Working end-to-end scan on macOS. All five tools. CSV + JSON output with source file copies.

### Scope

- [ ] Scanner framework (`base.py`, orchestrator, pattern engine, report writer)
- [ ] Cursor scanner (SQLite `state.vscdb` - `cursorDiskKV` table)
- [ ] ChatGPT scanner (`.data` file discovery; Keychain decryption attempt)
- [ ] Codex CLI scanner (`~/.codex/` SQLite databases)
- [ ] Claude desktop scanner (`~/Library/Application Support/Claude/` - pending install/research)
- [ ] Claude Code scanner (`~/.claude/projects/**/*.jsonl`)
- [ ] Regex pattern engine (AWS, OpenAI, GitHub, Anthropic, GCP, JWT, connection strings, PEM)
- [ ] Heuristic pattern engine (variable name context signals)
- [ ] CSV + JSON report writer with source file copy
- [ ] CLI (`ghosttype scan [--tool X] [--format Y] [--output Z]`)
- [ ] `ghosttype list-tools` command (show which tools are detected on this machine)
- [ ] Basic test suite (pattern engine unit tests, scanner unit tests with fixtures)
- [ ] pyproject.toml with entry point

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
