# SSCS User Actions — Manual Repo-Admin Steps

The software-supply-chain-security (SSCS) hardening in this repo is now wired
into code and CI. The following items **cannot** be done from inside the repo —
they require GitHub repo-admin access. Complete each one; check it off when done.

> Repo: `p4gs/ghosttype`. All UI paths below are relative to the repo on
> github.com.

---

## [ ] 1. Branch protection / Ruleset on `main`

**Why:** Without enforced review and required checks, a single compromised or
mistaken push reaches `main` and ships to users — and "admin bypass" is exactly
the door real incidents (insider mistake, token theft) walk through. Required
signed commits and linear history defend against history rewriting and
unattributable commits.

**GitHub UI path:** `Settings → Rules → Rulesets → New branch ruleset`
(or `Settings → Branches → Add branch protection rule`).

Target branch: `main`. Enable:

- ✅ Require a pull request before merging — require at least **1 approving review**.
- ✅ Require status checks to pass before merging, and require branches to be
  up to date. Add these required checks once they have run at least once:
  - `CI / test` (both matrix legs: `3.11`, `3.13`)
  - `CI / codeql`
  - `CI / sca`
  - `Scorecard supply-chain security / analysis`
- ✅ Require signed commits.
- ✅ Require linear history.
- ✅ **Do NOT allow administrators to bypass** (uncheck "Allow specified actors
  to bypass" / disable "Do not require status checks ... for administrators").
  Admin bypass defeats every control above.

---

## [ ] 2. Enable Secret Scanning + Push Protection

**Why:** Defends the committed-secret leak class (the same class the
`gitleaks` pre-commit hook and the CI self-scan defend locally). Push
Protection blocks a secret *before* it lands in history, where it is
effectively permanent.

**GitHub UI path:** `Settings → Code security and analysis`:

- ✅ Enable **Secret scanning**.
- ✅ Enable **Push protection** (under Secret scanning).

---

## [ ] 3. Configure a PyPI Trusted Publisher (OIDC) before first publish

**Why:** A long-lived PyPI API token stored as a repo secret is a high-value
exfiltration target (token-theft incidents like the chalk/debug npm
maintainer-token compromise). OIDC Trusted Publishing issues a short-lived,
audience-scoped token per release run — nothing long-lived to steal.

**Steps:**

1. On PyPI: `Your projects → ghosttype → Settings → Publishing → Add a new
   pending publisher` (or, pre-creation, `Account → Publishing → Add`).
   - Owner: `p4gs`
   - Repository: `ghosttype`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
2. In this repo: `Settings → Environments → New environment` named `pypi`
   (add required reviewers if desired).
3. In `.github/workflows/release.yml`: uncomment the `publish-pypi` job and
   pin `actions/download-artifact` and `pypa/gh-action-pypi-publish` to
   current release SHAs.

Do **not** enable the publish job until the Trusted Publisher exists, or the
release run will fail at the OIDC exchange.

---

## [ ] 4. Enable Dependabot alerts and security updates

**Why:** `.github/dependabot.yml` already schedules *version* update PRs.
Alerts + security updates additionally surface and auto-PR fixes for newly
disclosed CVEs in the existing dependency closure between scheduled runs —
defending the known-CVE-dependency-lingering class.

**GitHub UI path:** `Settings → Code security and analysis`:

- ✅ Enable **Dependabot alerts**.
- ✅ Enable **Dependabot security updates**.
- (Optional) Enable **Dependabot version updates** — already configured by
  `.github/dependabot.yml`; this toggle just confirms it is active.

---

## [ ] 5. Activate the README SSCS badges (registration-gated)

The README badges are real OpenSSF/tooling decorators — none are fabricated.
Two need a one-time external step before they render correctly:

- **OpenSSF Scorecard score badge** — NOT POSSIBLE on a fork. Tested on
  the runner: `publish_results: true` makes the OpenSSF webapp return
  HTTP 400 ("Fork repository: true") and fails the scorecard workflow, so
  it was reverted to `false` and the score badge removed from the README.
  The score badge is only achievable if this repo stops being a fork
  (becomes standalone). The Scorecard *workflow* (SARIF → code-scanning)
  works regardless; that's the "Scorecard supply-chain" badge.
- **OpenSSF Best Practices badge** — register the project at
  `https://www.bestpractices.dev` → you get a numeric project ID → replace
  the `BESTPRACTICES_ID` placeholder in `README.md` (two occurrences).
  Not pre-filled with a guessed ID by design.

## [ ] 6. Enable the GitHub **Dependency Graph** (for the dependency-review CI job)

`Settings → Code security → Dependency graph`. The `dependency-review` CI
job (PR gate) no-ops without it.

## [ ] 7. (After first release) add the SLSA badge

Once `release.yml` has produced a provenanced release, add the slsa.dev
Build-Level badge to `README.md`. Not added now — asserting a SLSA level
with no provenanced artifact would be a false claim.

---

# Code-Scanning Dashboard — Full Disposition (2026-05-16)

Snapshot of every alert that was open on
`https://github.com/p4gs/ghosttype/security/code-scanning` and exactly how
each was handled. Three honest dispositions: **fixed in code**,
**documented dismissal** (the constitutional carve-out — the scanner
*fundamentally cannot model* the pattern, paired with a real residual-risk
fix; never bare suppression), and **repo-admin / external** (cannot be fixed
from code; faking it would be dishonest).

| # | Tool | Rule | Location | Disposition |
|---|------|------|----------|-------------|
| 4,3,2 | Scorecard | PinnedDependenciesID | ci.yml:80,224,259 | **Fixed in code — runner-confirmed `fixed`.** Dropped unpinned `pip install --upgrade pip`; pip-audit/zizmor installed via `--require-hashes -r requirements-citools.lock` (lock + consuming jobs pinned to Python 3.13 for hash determinism) |
| 6,5 | Scorecard | PinnedDependenciesID | release.yml:49,125 | **Fixed in code — runner-confirmed `fixed`.** Dropped `--upgrade pip`; cyclonedx-bom installed via `--require-hashes -r requirements-citools.lock` |
| 13 | Opengrep | crypto-mode-without-authentication | chatgpt.py:96 | **Documented dismissal (needs your approval)** — see B-1 |
| 14 (was 12) | CodeQL | py/clear-text-storage-sensitive-data | report.py (~55) | **Code-hardened + documented dismissal (needs approval)** — see B-2. CodeQL re-keyed #12→#14 when the write sink moved (now race-free `_secure_opener`) |
| 11 | CodeQL | py/clear-text-logging-sensitive-data | cli.py:314 | **Documented dismissal (needs your approval)** — see B-3 |
| 1 | Scorecard | BranchProtectionID | main | **Repo-admin** — Action #1 (branch protection / ruleset) |
| 7 | Scorecard | CIIBestPracticesID | — | **External** — Action #5 (register bestpractices.dev) |
| 8 | Scorecard | CodeReviewID | — | **Process** — see C-note below |
| 9 | Scorecard | FuzzingID | — | **Scope decision** — see C-note below |
| 10 | Scorecard | MaintainedID | — | **Time-based / no action** — see C-note below |

## Class B — by-design true-positives: full dismissal justification

These are real code patterns, but the flagged behavior is the authorized
tool's core function or an immutable third-party-format interop constraint
the scanner cannot model. Per the zero-suppression rule, each dismissal is
**evidence-based, documented, and paired with a real residual-risk code
fix** — not a bare "safe in practice" hand-wave. Inline annotations are
retained, and this doc re-surfaces the exception if the code path changes.

**Default posture (applies to B-2 and B-3):** ghosttype emits the raw
`secret_value` **by default**; `--redact` is opt-in. That default is
deliberate and justified — ghosttype runs under explicit written
authorization (THREAT-MODEL.md; "Authorized use only"), and the licensed
pentest/DLP operator *needs* the plaintext to locate and rotate the exposed
credential; a redacted-by-default forensic scanner cannot do its job. The
**named compensating control** for the raw-emission path is owner-only
(`0600`) at-rest permissions on the report files (shipped in code, below);
`--redact` is the documented control for non-authorized / shareable
contexts, not a standalone rationale for the raw path.

**B-1 — alert #13, `chatgpt.py:96`, AES-128-CBC (Opengrep):**
*Named external format:* Chromium/Electron **OSCrypt** (the `"v10"`/`"v11"`
prefix scheme used by the ChatGPT desktop app). Its on-disk encryption is
**fixed by Chromium's design**: AES-128-CBC, key = `PBKDF2-HMAC-SHA1(pw,
"saltysalt", 1003, 16)`, and a **fixed 16-byte space IV** — none of these are
chosen by ghosttype. *Decrypt-only, not produce-new:* the flagged line is a
`decryptor()` path; ghosttype never encrypts and never emits CBC ciphertext,
so there is no IV-reuse exposure of *our* making (the static IV is a property
of the external format we must match byte-for-byte or decryption fails).
*No oracle:* this is a one-shot local decrypt of files the operator already
owns; decrypted output goes into the operator's local report, never back to
an attacker, and a malformed/bit-flipped file simply fails PKCS7 unpad
(caught, debug-logged, returns `None`) — none of the repeated
attacker-chosen-ciphertext + pad-validity-feedback conditions for a padding
oracle exist. *No compensating MAC is possible:* ghosttype cannot author an
authentication tag over ciphertext a third party wrote; forensic integrity
is provided out-of-band by the report + `--copy-sources` chain-of-custody.
An AEAD mode would simply fail to read real ChatGPT data. Opengrep cannot
model "match an external immutable format" vs "choose a weak mode." Inline
`# nosemgrep:` + the explanatory comment remain at `chatgpt.py:96`.

**B-2 — alert #14 (was #12), `report.py`, clear-text storage (CodeQL):**
The discovered `secret_value` *is* the pentest/DLP report deliverable (see
*Default posture* above). A credential scanner's report inherently contains
credentials; CodeQL cannot model this authorized intent. **Real residual-risk
fix shipped in code:** `report.py` writes both JSON and CSV reports
owner-only (`0600`) via `_secure_opener`, which `fchmod`s the fd to `0600`
*before any bytes are written* — race-free for both the new-file and
prior-run-left-a-0644-file cases (no write-then-chmod TOCTOU window where
secret content sits world-readable). Removing the value would neuter the
tool's core function.

**B-3 — alert #11, `cli.py:314`, clear-text logging (CodeQL):**
The same authorized deliverable, reached via the documented `--output -`
stdout path (pipelining, e.g. `| jq`). CodeQL's clear-text-logging sink
cannot model authorized forensic output. The default-posture justification
and the `--redact` control framing above apply identically. Documented
evidence-based carve-out, not suppression of an exploitable defect. (Note:
the stdout path is operator-chosen and transient; the `0600` at-rest control
applies to the file-output path, which is the default.)

> **Action required (you / repo-admin):** dismissing alerts is an external
> GitHub write, deliberately gated. Approve, then either dismiss in the
> Security UI (Dismiss → "Won't fix", paste the matching B-note), or run:
>
> ```
> gh api -X PATCH repos/p4gs/ghosttype/code-scanning/alerts/13 \
>   -f state=dismissed -f dismissed_reason="won't fix" \
>   -f dismissed_comment="By-design forensic interop; full rationale: SSCS-USER-ACTIONS.md B-1"
> gh api -X PATCH repos/p4gs/ghosttype/code-scanning/alerts/14 \
>   -f state=dismissed -f dismissed_reason="won't fix" \
>   -f dismissed_comment="By-design authorized deliverable; report files now race-free 0600; full rationale: B-2"
> gh api -X PATCH repos/p4gs/ghosttype/code-scanning/alerts/11 \
>   -f state=dismissed -f dismissed_reason="won't fix" \
>   -f dismissed_comment="Same authorized deliverable via --output -; full rationale: B-3"
> ```

## Class C — posture findings (repo-admin / external / time-based)

Not code defects. Fixing them from code is impossible; faking them would be
dishonest. Mapped to the actions above plus:

- **#1 BranchProtectionID** → **Action #1** (branch protection / no-admin-bypass
  ruleset on `main`). The single highest-value remaining item.
- **#7 CIIBestPracticesID** → **Action #5** (register at bestpractices.dev →
  numeric ID → replace `BESTPRACTICES_ID` in README).
- **#8 CodeReviewID** ("0/15 approved changesets") → resolves once changes
  land via **reviewed pull requests** instead of direct pushes. This is a
  process change, not a code change; it improves automatically as PR-merged
  history accumulates. (The solo-maintainer hardening pushes so far are the
  cause; no code can retroactively add reviews.)
- **#9 FuzzingID** ("not fuzzed") → **scope decision:** ghosttype is a
  forensic file/SQLite/JSONL parser — a fuzz harness (e.g. Atheris over the
  scanner decoders) has genuine value and is a reasonable *future* feature,
  but adding it is net-new feature work, not a security *remediation*, and
  is deliberately **not faked** here. Tracked as a future enhancement.
- **#10 MaintainedID** ("repository created in last 90 days") → **no action
  possible or needed**: purely time-based. It clears automatically as the
  project ages and accrues commit history; nothing in code influences it.

Ownership: every Class-C item is an *owned, tracked* line — Actions #1–#7
in this file (checkbox-tracked, owner = repo-admin), not merely prose. They
are "done" only when the action is applied; until then they correctly
remain open on the dashboard rather than being faked.

## Egress policy — `block` everywhere (PR #8 review item #7)

Every `step-security/harden-runner` step in `ci.yml`, `scorecard.yml`, and
`release.yml` runs `egress-policy: block` with an explicit per-job
`allowed-endpoints` allowlist. `block` actually prevents an unlisted
outbound connection; the previous `audit` only *observed* it (the inline
comment that claimed `audit` "defends post-install data exfiltration" was an
overclaim — corrected). Allowlists for the live CI jobs (`test`, `codeql`,
`sca`, `workflow-security`, `scorecard`) were **derived empirically from
real harden-runner audit runs**, not guessed.

**`test` job self-scan is detection-only by design.** The repo-self secret
scan previously ran `trufflehog filesystem . --results=verified --fail`,
which depends on TruffleHog's live verifier reaching an open set of
credential-provider hosts (≈750 distinct static endpoints, verified by
extracting them from TruffleHog v3.94.3's own detector source, plus ≈60
parametric/custom-domain detectors that cannot be statically pinned at
all). That is fundamentally incompatible with an egress-blocked runner.
Rather than (a) keep `audit` and overclaim, or (b) inline a ~750-host,
version-fragile, still-incomplete allowlist, the self-scan now runs
`trufflehog filesystem ghosttype/ --no-verification --no-update --fail
--exclude-paths=.github/th-selfscan-exclude.txt` — a **detection-only**
gate scoped to the shipped package, skipping the files that embed
credential *shapes* by design (the pattern catalog, `__pycache__`).
Verified locally: clean on current shipped code, and a planted structural
secret in shipped code still fails the build (not security theater).
**End-user runtime verification is unaffected** — this governs CI's own
self-scan only; `ghosttype` still verifies for users by default.

## Residual follow-ups (advisor-surfaced, not silently dropped)

- **Hashed-lock currency.** `requirements-citools.lock` (like the existing
  `requirements.lock`) is hash-pinned and will rot into unpatched-dep risk
  if never regenerated. Dependabot's `pip` ecosystem (`.github/dependabot.yml`,
  dir `/`) tracks the `*.in`; regenerate the lock with
  `pip-compile --generate-hashes --allow-unsafe` **under Python 3.13** (the
  version the consuming CI jobs now pin — required for hash determinism).
  Wiring fully-automated lock regeneration is a reasonable future
  enhancement, deliberately not faked as done here.
- **Dismissal exceptions re-surface on change.** B-1..B-3 live in this
  in-repo durable doc *and* (once approved) in the code-scanning platform,
  so the exception is re-reviewed if the flagged code path materially
  changes — not a fire-and-forget suppression.
- **`release.yml` egress allowlist is reasoned, not live-audited.**
  `release.yml` is dormant (runs only on a pushed `v*` tag), so its
  `build`/`sbom` allowlists were derived from each step's network
  operations rather than a captured audit run. First real tagged release:
  watch the harden-runner insights and tighten/extend the two allowlists
  if anything essential was blocked. The live CI allowlists (`ci.yml`,
  `scorecard.yml`) carry no such caveat — they are audit-derived.
- **Egress allowlists are version/infra-coupled.** GitHub Actions backing
  hosts (artifact/cache `*.blob.core.windows.net`, setup-python asset
  hosts) and tool registries drift. A newly-blocked *essential* endpoint
  surfaces as a harden-runner block annotation (non-destructive, easy to
  add); review the insights link on the first maintainer-run CI and adjust
  if needed.
