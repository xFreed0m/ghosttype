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
