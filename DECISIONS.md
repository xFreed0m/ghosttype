# Technical Decisions

Log of key decisions made during ghosttype development. Each entry explains what was decided, why, and what was considered but rejected.

---

## 2026-05-12 - Plugin-style scanner architecture over single-script

**Decision:** One module per target tool (`scanners/cursor.py`, etc.) with a shared `Scanner` ABC.

**Why:** Each tool stores conversations differently - SQLite with custom schemas (Cursor, Codex), encrypted binary files (ChatGPT), JSONL (Claude Code). The discovery and extraction logic is meaningfully different per tool. Keeping them isolated makes each scanner independently testable and auditable. Adding a new tool means one new file with no changes to the core.

**Rejected:** Single script with a dict of lambdas - simpler initially but hard to test, hard to read as complexity grows.

---

## 2026-05-12 - Both regex + heuristic detection layers

**Decision:** Two-layer pattern engine: (1) regex for known credential formats, (2) heuristic context signals for variable name patterns.

**Why:** Regex alone misses secrets stored in non-standard formats (e.g., a password set as `my_db_password = "correcthorsebattery"`). Heuristic alone produces too many false positives. Combining both with separate confidence levels (`high` vs `medium`) gives operators the choice of how much noise to accept.

**Rejected:** LLM-assisted detection - too slow, adds an external dependency, overkill for v1.

---

## 2026-05-12 - Output to directory with source file copies

**Decision:** Report output writes `findings.json`, `findings.csv`, and a `sources/` directory with copies of the source conversation files.

**Why:** The source file copy is the core value-add over a plain regex scanner. Red teamers need the full conversation for simulation/replay. Blue/DLP teams need it for evidence and to understand what was exposed. A finding with just a path is insufficient if the operator can't trust the path will still be there.

**Rejected:** Path references only - insufficient for offline use and breaks the audit chain.

---

## 2026-05-12 - CSV redacts by default; JSON does not

**Decision:** In CSV output, `secret_value` is redacted to `***REDACTED***` by default (use `--no-redact` to disable). JSON output always shows full values.

**Why:** CSV files are commonly opened in Excel and shared. JSON is typically consumed by tooling that handles sensitive data appropriately. Redaction by default reduces accidental exposure in the CSV workflow.

---

## 2026-05-12 - macOS first, local-only for v1

**Decision:** v1 targets macOS only, local filesystem only.

**Why:** All five target tools are confirmed present on macOS. Linux and Windows support is straightforward to add via the platform path table in RESEARCH.md. Cloud/network enumeration (e.g., synced ChatGPT history via API) is a separate concern with different auth requirements - defer to v2.

---

## 2026-05-12 - ChatGPT .data files: attempt decryption, fall back to path-only

**Decision:** For ChatGPT, attempt Keychain-backed decryption. If it fails (e.g., not running as the user, Keychain prompt denied), report the file path and metadata only rather than failing the whole scan.

**Why:** Failing loudly on one tool would break scans on all other tools. Path-only results are still useful (evidence of the file's existence, count, timestamps).

---

## 2026-05-12 - Unredacted output by default

**Decision:** Both `write_json` and `write_csv` default to `redact=False`. Use `--redact` to mask values.

**Why:** Red team operators need to see credential values immediately without extra flags. DLP teams running automated pipelines can add `--redact` when generating shareable reports. The tool is run explicitly under authorization, so seeing plaintext is the expected default.

---

## 2026-05-12 - Known-example exclusion applied to both regex and heuristic

**Decision:** `_KNOWN_EXAMPLE_VALUES` is checked in both the regex loop AND the heuristic filter, preventing well-known documentation examples (AKIAIOSFODNN7EXAMPLE, etc.) from ever appearing as findings.

**Why:** These values appear in AWS docs, tutorial repos, and test fixtures worldwide. Reporting them would be noise in any real scan. The exclusion set is maintained in code; future additions can reference official doc sources.

---

## 2026-05-12 - Entropy threshold 3.0 bits/char for heuristic matches

**Decision:** Heuristic (medium-confidence) matches are filtered if Shannon entropy < 3.0 bits/char.

**Why:** Industry standard from gitleaks and detect-secrets. Real API keys and passwords cluster above 3.5; common placeholder strings cluster below 3.0. Raises the signal-to-noise ratio for medium-confidence findings significantly.

---

## 2026-05-12 - Exit code 1 when findings present

**Decision:** `ghosttype scan` exits with code 1 if any findings are discovered, 0 if clean.

**Why:** Enables CI/CD integration. Operators can add `ghosttype scan --quiet` as a pre-commit or CI step and gate on non-zero exit. Standard convention for security scanner CLIs (truffleHog, gitleaks both do this).

---

## 2026-05-12 - Severity field on Finding

**Decision:** Each Finding has a `severity` field: `critical` (highest-value keys like AWS, OpenAI, private keys), `high` (other regex matches), `medium` (heuristic).

**Why:** Operators need to triage. Critical findings warrant immediate action; medium findings warrant review. Severity is based on credential type, not detection confidence - a Vault token (critical) is more dangerous than a Doppler token (high) regardless of how it was detected.

---

## 2026-05-13 - Heuristic cross-pattern deduplication via captured_values set

**Decision:** `scan_text` maintains a `captured_values` set that grows as heuristics fire, preventing later heuristics from re-reporting a value already captured by an earlier heuristic.

**Why:** Without this, `heuristic_aws_secret` and `heuristic_generic_secret` both matched the same 40-char AWS secret key value when `ACCESS_KEY` appeared in `SECRET_ACCESS_KEY`. The `captured_values` set is updated after each heuristic match, so subsequent patterns skip already-seen values regardless of pattern type.

