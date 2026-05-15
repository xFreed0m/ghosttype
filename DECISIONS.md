# Technical Decisions

Key design decisions with rationale. Useful for contributors evaluating trade-offs.

---

## Plugin-style scanner architecture

**Decision:** One module per target tool, each implementing the `Scanner` ABC.

**Why:** Each tool stores conversations differently (SQLite with custom schemas, encrypted binary, JSONL). Discovery and extraction logic is meaningfully distinct per tool. Isolated modules are independently testable and auditable. Adding a new tool means one new file with no changes to the core.

**Rejected:** Single script with a dict of lambdas — simpler initially, but hard to test and maintain as complexity grows.

---

## Output: unredacted by default, `--redact` to mask

**Decision:** Both JSON and CSV output show plaintext credential values by default.

**Why:** Red team operators need to see values immediately to verify and use findings. The tool is run explicitly under authorization. Use `--redact` when generating shareable reports for non-operator audiences.

---

## Exit code 1 when findings present

**Decision:** `ghosttype scan` exits 1 if any findings are discovered, 0 if clean.

**Why:** Enables CI/CD integration as a blocking check. Standard convention for security scanner CLIs (truffleHog, gitleaks). Operators can gate pipelines on `ghosttype scan --quiet --min-confidence high`.

---

## Entropy threshold 3.0 bits/char for heuristic matches

**Decision:** Heuristic (medium-confidence) matches are filtered out if Shannon entropy < 3.0 bits/char.

**Why:** Industry standard from gitleaks and detect-secrets. Real API keys and passwords cluster above 3.5 bits/char; common placeholder strings like `your-key-here` cluster below 3.0. This eliminates the majority of heuristic false positives without touching high-confidence regex matches.

---

## Known-example exclusion applied to all matches

**Decision:** `_KNOWN_EXAMPLE_VALUES` (AWS docs keys, jwt.io examples, common tutorial values) is checked in both the regex loop and the heuristic filter.

**Why:** These values appear in AWS documentation, tutorial repos, and test suites worldwide. Reporting them produces noise in every real scan. The exclusion set is maintained in code with source references.

---

## Severity field on Finding

**Decision:** `critical` (AWS, private keys, OpenAI/Anthropic tokens, Stripe, Vault, GitHub PATs), `high` (other regex matches), `medium` (heuristic patterns).

**Why:** Operators need to triage. Critical findings warrant immediate rotation; medium findings warrant review. Severity is based on credential type, not detection method — a Vault service token is more dangerous than a Doppler token regardless of how it was detected.

---

## ChatGPT decryption: attempt Keychain, fall back to path-only

**Decision:** For ChatGPT, attempt AES-128-CBC decryption (Chrome OSCrypt, Keychain key via `security find-generic-password`). If it fails, report the file path and metadata only rather than failing the scan.

**Why:** Failing loudly on one tool would break scans on all other tools. Path-only results are still useful (file count, timestamps) as evidence of conversation history volume.

---

## Heuristic cross-pattern deduplication via `captured_values` set

**Decision:** `scan_text` maintains a `captured_values` set that grows as heuristics fire, preventing later heuristics from re-reporting a value already captured by an earlier one.

**Why:** Without this, overlapping heuristics (e.g., `heuristic_aws_secret` and `heuristic_generic_secret`) both matched the same 40-char AWS secret key when `ACCESS_KEY` appeared in `SECRET_ACCESS_KEY`. The set is updated after each heuristic match so subsequent patterns skip already-seen values.

---

## Copy sources: opt-in with `--copy-sources`

**Decision:** Source conversation files are only copied to the output directory when `--copy-sources` is explicitly passed.

**Why:** Source files may contain far more sensitive content than the extracted credentials — entire conversation histories. Copying them should be a deliberate choice by the operator, not a default.
