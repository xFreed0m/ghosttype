# Roadmap

## Current: v0.2.0

Working local scanner on macOS. All five AI tools. 40+ credential patterns. JSON/CSV output.

**Shipped:**
- Claude Code, Cursor, Codex, ChatGPT, Claude Desktop scanners
- 30 regex patterns + 10 heuristic patterns with FP reduction (entropy filtering, known-example exclusions, placeholder filter)
- Severity field: `critical` / `high` / `medium`
- Exit code 1 when findings present (CI/CD integration)
- `--output -` for stdout piping to jq
- `--max-age-days`, `--min-confidence`, `--allow-list`, `--stats-only`, `--quiet`
- 93 tests

---

## Planned

### Near term

- Linux and Windows path support (path table already in RESEARCH.md)
- ChatGPT full decryption (verified AES-128-CBC; needs Keychain key extraction research)
- Claude Desktop scanner (storage format needs investigation once installed)
- Pattern verification mode: optionally test if detected credentials are live (AWS, GitHub)

### Later

- Cloud conversation sync: ChatGPT export API, Claude.ai export
- Additional patterns: Cloudflare, Vercel, Firebase, Twilio, Azure SAS tokens
- SIEM-compatible output (CEF, Splunk HEC)
- `--watch` mode for continuous monitoring
