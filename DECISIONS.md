# Technical Decisions

Key design decisions with rationale. Useful for contributors evaluating trade-offs.

---

## Dual complementary engines (v0.4.0) — supersedes the v0.3.0 "THE engine" decision

**Decision:** Restore the in-tree regex/heuristic pattern engine and run it
*alongside* TruffleHog, not instead of it. New `--engine {both,trufflehog,patterns}`
flag, default `both`. Findings carry a `source` field (`trufflehog` |
`ghosttype-pattern`). When both engines hit the same `(secret_value, file_path)`,
the TruffleHog finding wins (it carries verification + detector metadata);
pattern-only hits are kept.

**Why the v0.3.0 "supplant" decision was reversed:** The two engines catch
different things, measured on a real 1464-file corpus:

- TruffleHog alone: 14 findings — detectors ghosttype never had (Box, Dockerhub,
  UnifyID, URI) plus live verification.
- Patterns alone: 71 findings — dominated by the **heuristic layer**
  (`heuristic_token`, `heuristic_api_key`, `heuristic_password`,
  `heuristic_jwt_secret`): loose variable-name context signals
  (`api_key=`, `password=`) that TruffleHog's structural detectors do not match.
- Both: 79 findings (14 + 65, with 6 overlapping GitHub PATs deduped to the
  verifiable TruffleHog hit).

Neither is a superset of the other. Supplanting lost the heuristic safety net;
keeping only patterns loses verification and 800+ detectors. Complementary is
strictly better for the red-team / DLP use case where a missed credential is
the expensive failure.

**Trade-off acknowledged:** `both` is noisier (79 vs 14). The heuristic layer
is medium-confidence by design. Operators who want signal-only run
`--engine trufflehog --only-verified`; operators doing exhaustive sweeps run
`both`. The `--min-confidence` filter is now dual-engine aware: `verified`
keeps only TruffleHog-verified, `high` keeps verified + regex-high and drops
medium heuristics.

---

## TruffleHog as THE detection + verification engine (v0.3.0 — SUPERSEDED by v0.4.0)

**Decision:** Replace the in-tree regex/heuristic pattern engine with a TruffleHog subprocess invoked in `filesystem` mode. ghosttype writes extracted text chunks to a temp directory, runs `trufflehog filesystem --json --no-update ...`, and parses NDJSON results back into `Finding`s.

**Why:** Two reasons that don't overlap.

1. **Verification was the missing feature.** v0.2.0 had structure-only detection — it would flag a credential shape but couldn't say whether the credential was still live. TruffleHog ships 800+ verifiers that hit the actual provider API; that's the value of the integration.
2. **Maintaining 40 patterns in-tree is duplicative work.** TruffleHog already has a much larger detector catalog, an entropy filter, a known-example exclusion list, and ongoing maintenance. ghosttype's value-add is the discovery layer (where each AI tool stashes conversation history), not pattern catalogs.

**Subprocess over library bindings:** TruffleHog is Go. CGO bindings or a Python rewrite both wildly exceed the integration value. The subprocess boundary is stable: NDJSON in stdout, structured argv, deterministic exit codes. TruffleHog upgrades flow through with zero ghosttype code changes.

**Rejected alternatives:**
- Keep both engines side-by-side — surface area without payoff; ghosttype's regex catalog was a strict subset of TruffleHog's.
- Use TruffleHog purely for verification of existing regex hits — would require translating ghosttype's `secret_type` → TruffleHog's detector name and re-implementing the chunking; engine-replacement is simpler.

---

## TruffleHog-missing behavior is engine-dependent (v0.4.0; refines v0.3.0)

**Decision:**
- `--engine trufflehog`: missing binary is a hard failure — exit 2 with the
  install URL, env var, and CLI flag (unchanged from v0.3.0).
- `--engine both` (default): missing binary degrades to patterns-only with a
  **visible yellow warning**, then continues. Not silent, not exit 2.
- `--engine patterns`: the binary is never resolved at all.

**Why the v0.3.0 hard-fail was relaxed for `both`:** v0.3.0 had no other
engine, so "no TruffleHog" meant "no scanning" — failing loud was correct.
v0.4.0 has a real second engine. When the user asked for `both` and TruffleHog
is absent, refusing to run at all is worse than running the pattern engine and
saying so. The principle ("never a *silent* downgrade") is preserved by the
mandatory warning; only the response to it changed.

---

## Verification ON by default (v0.3.0)

**Decision:** `ghosttype scan` verifies every detected credential against its provider unless `--no-verification` is passed.

**Why:** Verification is the new value proposition. Operators running ghosttype are explicitly authorized; making them pass an opt-in flag to get the headline feature is friction without benefit.

**Trade-off acknowledged:** Verification calls hit real provider APIs and may show up in audit logs (CloudTrail, GitHub audit, etc.). Red-team operators who want to stay quiet should use `--no-verification`. This is documented in the README and threat model.

---

## `--only-verified` for triage workflows (v0.3.0)

**Decision:** A first-class `--only-verified` flag (passes `--results=verified` to TruffleHog) suppresses every finding TruffleHog could not actively confirm.

**Why:** During credential rotation work, the operator wants to act on what's live, not the long tail of historical pastes that may already be revoked. `--only-verified` gives that triage view directly without post-processing JSON.

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

## Entropy threshold and known-example exclusion (delegated to TruffleHog in v0.3.0)

**Historical decisions (v0.2.0):** ghosttype maintained its own Shannon entropy filter (≥3.0 bits/char) and a `_KNOWN_EXAMPLE_VALUES` set covering AWS docs keys, jwt.io examples, etc.

**Current state (v0.3.0):** Both responsibilities live in TruffleHog now. TruffleHog ships `--filter-entropy` (default 3.0) and a per-detector known-example list that is far broader than ghosttype's. We surface `--context-window` and let TruffleHog own the math.

---

## Severity field on Finding

**Decision:** `critical` for verified hits of high-impact detectors (AWS, Anthropic, OpenAI, GitHub family, Stripe, PrivateKey, Vault, GCP, Azure, Databricks, Snowflake). `high` for verified hits of anything else and for unverified hits of those high-impact detectors. `medium` for unverified hits of everything else.

**Why:** Operators need to triage. A verified live AWS key is the highest-impact finding ghosttype can produce; an unverified Doppler token is lower-priority work. Severity is a function of (detector × verification state).

---

## ChatGPT decryption: attempt Keychain, fall back to path-only

**Decision:** For ChatGPT, attempt AES-128-CBC decryption (Chrome OSCrypt, Keychain key via `security find-generic-password`). If it fails, report the file path and metadata only rather than failing the scan.

**Why:** Failing loudly on one tool would break scans on all other tools. Path-only results are still useful (file count, timestamps) as evidence of conversation history volume.

---

## Cross-pattern deduplication (delegated to TruffleHog in v0.3.0)

**Historical decision (v0.2.0):** ghosttype maintained a `captured_values` set to prevent overlapping heuristics (e.g. `heuristic_aws_secret` vs `heuristic_generic_secret`) from double-reporting the same value.

**Current state (v0.3.0):** TruffleHog runs detectors with its own conflict resolution; ghosttype dedups at the orchestrator level on `(secret_value, file_path, secret_type)`. The narrow detector overlap that motivated the heuristic-level dedup is gone with the heuristics themselves.

---

## Copy sources: opt-in with `--copy-sources`

**Decision:** Source conversation files are only copied to the output directory when `--copy-sources` is explicitly passed.

**Why:** Source files may contain far more sensitive content than the extracted credentials — entire conversation histories. Copying them should be a deliberate choice by the operator, not a default.
