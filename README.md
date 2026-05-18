# ghosttype

[![CI](https://github.com/xFreed0m/ghosttype/actions/workflows/ci.yml/badge.svg)](https://github.com/xFreed0m/ghosttype/actions/workflows/ci.yml)
[![coverage ≥95%](https://img.shields.io/badge/coverage-%E2%89%A595%25-brightgreen)](https://github.com/xFreed0m/ghosttype/actions/workflows/ci.yml)
[![Scorecard supply-chain](https://github.com/xFreed0m/ghosttype/actions/workflows/scorecard.yml/badge.svg)](https://github.com/xFreed0m/ghosttype/actions/workflows/scorecard.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/BESTPRACTICES_ID/badge)](https://www.bestpractices.dev/projects/BESTPRACTICES_ID)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

<!--
SSCS decorators — REAL, KNOWN badges only. None are fabricated.
  CI / Scorecard supply-chain : native GitHub Actions workflow-status badges; live once the workflow runs on the default branch.
  coverage ≥95%               : NOT a fabricated number. It states the ENFORCED invariant — CI runs `pytest --cov-fail-under=95`, so a green build provably means coverage ≥95% (actual is higher, ~98%, but the guaranteed claim is the floor). A static "97%" would rot/become false; a live exact-% badge needs Codecov (excluded) or a CI self-publish job (offered separately). This gate badge is truthful, FOSS (shields.io static), zero-infra.
  OpenSSF Scorecard (score)   : REMOVED. The api.securityscorecards.dev score badge is structurally impossible on a fork — the OpenSSF webapp rejects fork publishing (HTTP 400, "Fork repository: true") and `publish_results: true` then FAILS the scorecard workflow. It is NOT "pending activation"; it can only ever work if this stops being a fork. The Scorecard *workflow* still runs (SARIF → code-scanning); the "Scorecard supply-chain" workflow-status badge above reflects that truthfully. Removed rather than show a permanently-broken "invalid repo path" badge.
  OpenSSF Best Practices      : official bestpractices.dev badge; the URL needs a numeric project ID from registering the project. BESTPRACTICES_ID is a placeholder, NOT a fabricated value — replace after registering (SSCS-USER-ACTIONS.md). Until then this badge intentionally shows as broken rather than show a fake score.
  pre-commit                  : the project's own recognized badge; live immediately.
The gitleaks badge was REMOVED because gitleaks is no longer used anywhere — the pre-commit cred scanner is now TruffleHog (broader detector coverage + active verification). Keeping a "protected by gitleaks" badge would be a false claim.
Deliberately NOT added — no canonical project decorator exists, so adding one would be inventing it (the user explicitly forbade fabricated badges): Opengrep, OSV-Scanner, pip-audit, Dependabot, CodeQL, TruffleHog (TruffleHog has no canonical README badge — not added rather than fabricated).
SLSA: slsa.dev publishes a Build-Level badge, but ghosttype has no provenanced release yet (release.yml is dormant). Claiming "SLSA 3" now would be false — add only after the first provenanced release (SSCS-USER-ACTIONS.md).
-->

Local forensic scanner that extracts **and verifies** credentials from AI tool conversation history. Detection + verification powered by [TruffleHog](https://github.com/trufflesecurity/trufflehog).

> Read the original blog post: [**ghosttype — finding secrets in AI conversation history**](https://betheadversary.com/posts/ghosttype)

> **Authorized use only.** For licensed penetration testers, red teams, and DLP/blue teams operating under explicit written authorization. See [THREAT-MODEL.md](THREAT-MODEL.md).

---

## What it does

ghosttype scans AI tool conversation files for exposed credentials, then asks TruffleHog whether each one is **actually live** by hitting the issuing provider's verification endpoint. Findings are emitted as JSON + CSV, each linked back to the source conversation.

**Two complementary detection engines** (since v0.4.0):

- **TruffleHog** — 800+ structural detectors with live API verification, entropy filtering, known-example exclusion. The only engine that can prove a credential is *live*.
- **In-tree pattern engine** — 30 regex + 10 heuristic patterns. Offline, never verified, but catches loose variable-name context signals (`api_key=`, `password=`, `JWT_SECRET=`) that TruffleHog's structural detectors don't match.

By default both run and results are merged (`--engine both`); on a `(secret_value, file)` overlap the TruffleHog finding wins because it carries verification. Choose one with `--engine {both,trufflehog,patterns}`. ghosttype always owns the discovery layer — where each AI tool stores conversations and how to decode them. Every finding carries a `source` field so you know which engine produced it.

**Supported AI tools:**

| Tool | Data source |
|------|------------|
| Claude Code CLI | `~/.claude/projects/**/*.jsonl` + history |
| Cursor IDE | `state.vscdb` (SQLite, global + workspace) |
| Codex CLI | `~/.codex/state_5.sqlite` + logs |
| ChatGPT Desktop | Keychain-backed `.data` files (AES-128-CBC) |
| Claude Desktop | Stub (path detected; extraction in progress) |

**Detected credential types:** the full TruffleHog detector catalog (800+), including AWS, GitHub PATs, OpenAI / Anthropic, Stripe, Slack, HashiCorp Vault, Snowflake, Databricks, Linear, GCP service accounts, Azure, Twilio, Cloudflare, npm, Telegram, Hugging Face, DigitalOcean, Docker Hub, Pulumi, Doppler, PyPI, SendGrid, JWT, PEM private keys, and database connection strings. Each finding is marked `verified: true` if TruffleHog confirmed it live against the provider's API, or `verified: false` if the structure matched but verification was skipped, declined, or failed.

---

## Requirements

- Python 3.11+
- TruffleHog 3.x installed and on `PATH` (or set `GHOSTTYPE_TRUFFLEHOG_BIN`)
  - macOS: `brew install trufflehog`
  - Linux: see [installation docs](https://github.com/trufflesecurity/trufflehog#installation)
- macOS for full tool coverage (Linux/Windows paths: roadmap)

Check your install:

```bash
ghosttype doctor
```

---

## Quick start

```bash
git clone https://github.com/p4gs/ghosttype
cd ghosttype
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Scan all detected AI tools (verifies every credential against its provider)
ghosttype scan

# Triage rotation work: only TruffleHog-verified live credentials
ghosttype scan --only-verified

# Fast offline pass: detect without hitting any provider APIs
ghosttype scan --no-verification

# Pipe to jq, filter by detector
ghosttype scan --no-verification --format json --output - --quiet \
  | jq '.[] | select(.detector_name == "Github")'

# Show which AI tools and TruffleHog are present
ghosttype doctor
```

---

## Output

Default: `./ghosttype_report/findings.json` + `findings.csv`

Each finding includes:

| Field | Description |
|-------|-------------|
| `tool` | Source AI tool (e.g. `claude_code`) |
| `detector_name` | TruffleHog detector name (e.g. `Github`, `AWS`) |
| `secret_type` | Detector name, lowercased |
| `severity` | `critical` / `high` / `medium` — derived from detector + verification state |
| `verified` | `true` if TruffleHog confirmed live against the provider, else `false` |
| `verification_error` | Verifier error message if verification was attempted and errored |
| `secret_value` | Plaintext value (use `--redact` to mask) |
| `file_path` | Source conversation file |
| `position` | Chunk position + line within the chunk |
| `confidence` | `verified` or `unverified` |
| `context` | Window of surrounding text |
| `extra_data` | TruffleHog detector extras (e.g. `rotation_guide` URLs) |

---

## All scan options

```
ghosttype scan [OPTIONS]

  --tool TEXT                  Scan one tool: cursor, chatgpt, codex, claude, claude_code
  --format [json|csv|both]     Output format (default: both)
  --output TEXT                Output dir, or - for stdout JSON (default: ./ghosttype_report)
  --engine [both|trufflehog|patterns]
                               Detection engine (default: both). 'patterns'
                               needs no TruffleHog binary.
  --redact                     Mask secret values in output
  --min-confidence             verified | unverified (default: unverified)
                               'verified' = TruffleHog-verified only;
                               'high' (legacy) also keeps regex pattern hits
  --only-verified              Pass --results=verified to TruffleHog
  --no-verification            Skip live verifier calls (fast, offline)
  --trufflehog-binary PATH     Override the TruffleHog binary
  --trufflehog-timeout SECONDS Outer timeout for the TruffleHog subprocess (default: 300)
  --max-age-days N             Only scan files modified within last N days
  --copy-sources               Copy source conversation files to output/sources/
  --allow-list PATH            Suppress known-safe values (one value per line)
  --stats-only                 Print summary statistics only
  --quiet / -q                 Suppress banner for scripting
  --context-window N           Context chars around match (default: 200)

ghosttype list-tools           Show detected AI tools on this machine
ghosttype doctor               Show TruffleHog binary, version, and detected tools
ghosttype version              Print version
```

### Environment variables

- `GHOSTTYPE_TRUFFLEHOG_BIN` — explicit path to TruffleHog binary (overridden by `--trufflehog-binary`)

### Exit codes

- `0` — no findings
- `1` — at least one finding (enables CI/CD gating)
- `2` — environment problem (TruffleHog missing, subprocess failed, etc.)

---

## Detection design

ghosttype is two layers stitched together:

```
[AI tool storage] --(scanner module)--> TextChunks --(trufflehog filesystem)--> Findings
   .jsonl/SQLite/encrypted         (extracted text)        (verified or unverified)
```

The **discovery layer** is the per-tool code under `ghosttype/scanners/` — one module each for Claude Code, Cursor, Codex, ChatGPT, Claude Desktop. They know SQLite schemas, Electron `safeStorage` decryption, JSONL message shapes.

The **detection + verification layer** is a TruffleHog subprocess. ghosttype writes each extracted text chunk to a temp file with a deterministic name, runs `trufflehog filesystem --json --no-update [...] <tmpdir>`, parses NDJSON results, and maps each one back to the originating conversation record via the temp filename. The temp dir is deleted in a `finally` block; nothing persists.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full pipeline diagram.

---

## Security & threat model

ghosttype is forensic — it reads files you already have access to and runs detectors locally. The only network traffic is TruffleHog's own verification calls to credential issuers (AWS, GitHub, Stripe, etc.) and only when verification is enabled.

Use `--no-verification` if any of the following apply:
- You're operating in an air-gapped environment
- You don't want to risk lighting up provider audit logs on red-team engagements
- You just want fast triage

See [THREAT-MODEL.md](THREAT-MODEL.md) for intended-use and abuse considerations.

---

## License

See [LICENSE](LICENSE).
