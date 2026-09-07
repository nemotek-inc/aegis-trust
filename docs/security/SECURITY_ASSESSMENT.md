# Security Assessment — aegis-trust

- **Assessment date:** 2026-06-10 (S002 baseline); **re-assessed 2026-06-11 (S1005 — since renumbered to S006, §5 status + §6 delta)**
- **Executor:** sprint S002 executor agent (Claude Code), recorded in the
  maintainer's private sprint ledger as `sprint_002.md`; the S1005 re-assessment
  is recorded there as `sprint_006.md` (formerly `sprint_1005.md`: the T-040
  sprint renumber on 2026-06-11 mapped aegis-trust S1002–S1005 → S003–S006, with
  the renumber receipt held in the same ledger; S002 ids in this document are
  unchanged. "S1005" below is kept as the historical label of the sprint now
  filed as S006)
- **Scope:** dependency supply chain (Python + Node), secrets hygiene
  (full git history), CI/CD pipeline controls, access-control implementation
  inventory
- **Method:** every claim below is backed by a tool run with the exact
  command, tool version, and exit code. Raw logs are committed under
  [`evidence/`](evidence/). No claim in this document is hand-asserted.

## 1. Results summary

| Layer | Tool (version) | Command | Before | After | Exit (after) |
|---|---|---|---|---|---|
| Python deps | pip-audit 2.10.0 | `python/.venv/bin/pip-audit --strict` | 2 vulnerabilities | **0** | 0 |
| Node deps | npm audit (npm 10.9.4, node 22.22.1) | `npm audit --audit-level=low` (in `node/`) | 4 vulnerabilities | **0** | 0 |
| Secrets (git history) | gitleaks 8.30.1 | `gitleaks detect --config .gitleaks.toml --no-banner --redact` | 0 leaks (131 commits) | 0 leaks | 0 |

Raw logs: [`evidence/s002-pip-audit-before.log`](evidence/s002-pip-audit-before.log),
[`evidence/s002-pip-audit-after.log`](evidence/s002-pip-audit-after.log),
[`evidence/s002-npm-audit-before.log`](evidence/s002-npm-audit-before.log),
[`evidence/s002-npm-audit-after.log`](evidence/s002-npm-audit-after.log),
[`evidence/s002-gitleaks.log`](evidence/s002-gitleaks.log).

## 2. Findings and dispositions

| ID | Severity | Component | Finding | Disposition |
|---|---|---|---|---|
| S002-DEP-1 | medium | python (transitive: idna 3.11 via httpx/requests/anyio) | CVE-2026-45409, fix ≥3.15 | **Fixed** — dev env upgraded to idna 3.18; consumers resolve fresh (no upper pin in `pyproject.toml`); CI `audit.yml` re-resolves and fails closed on regression |
| S002-DEP-2 | medium | python tooling (pip 26.1.1) | PYSEC-2026-196, fix 26.1.2 | **Fixed** — dev env pip 26.1.2; CI audit env is built by pinned `uv==0.5.30` + `uv.lock` (no ambient pip resolution on the audit path) |
| S002-DEP-3 | **critical** | node devDependency (vitest ≤3.2.5, direct) | GHSA-5xrq-8626-4rwp — Vitest UI server arbitrary file read/execute | **Fixed** — vitest `^1.6.0` → `^4.1.8` (`node/package.json` + lockfile); full suite green after upgrade: 17 files / 222 tests passed (runtime output: [`evidence/s002-node-tests.log`](evidence/s002-node-tests.log)) |
| S002-DEP-4 | moderate ×3 | node transitive (esbuild GHSA-67mh-4wv8-2f99, vite GHSA-4w7w-66w2-5vf9, vite-node) | dev-server request/path-traversal class issues, all reachable only through the vitest chain | **Fixed** — eliminated by the vitest 4.1.8 upgrade (audit after: 0) |
| S002-CI-1 | high (process) | CI/CD | `SECURITY.md` claimed "dependency audit on every CI build" but `ci.yml` ran none — control existed in the M4-era workflow (`python/CHANGELOG.md` M4 entry) and was lost in a refactor | **Fixed** — [`.github/workflows/audit.yml`](../../.github/workflows/audit.yml) added (push/PR + weekly schedule, fail-closed, SHA-pinned); `SECURITY.md` wording aligned to the verifiable control |
| S002-CI-2 | medium (process) | CI/CD | A second workflow file could silently reopen the supply-chain surface the S018 adversarial tests close for `ci.yml` only | **Fixed** — `python/tests/adversarial/test_redteam_S002_audit_workflow.py` (13 tests) enforces the same invariants on `audit.yml`: no `pull_request_target`, branch restrictions, `permissions: contents: read` only, no `id-token`, no secrets, 40-char SHA pins, no `\|\| true` / `continue-on-error`, aggregator present |
| S002-CI-3 | medium (process) | CI/CD | YAML-shape tests alone would stay green if the audit *commands* were gutted (`--strict` dropped, `npm install` swapped in, audit level raised, gate `if: always()` removed → skipped-as-green). Found by cross-review round-2 (P1) | **Fixed** — command-invariant tests added (invariant 7): `uv run pip-audit --strict` in the uv.lock-synced env, `npm ci` (and never `npm install`), `npm audit --audit-level=low`, gate `if: always()` each individually pinned |
| S002-CI-4 | medium (process) | CI/CD | audit.yml originally audited a pip-resolved env while ci.yml tests run against the `uv.lock` env — audited set ≠ tested set; unpinned `pip install --upgrade pip` was also non-deterministic. Found by cross-review round-2 (P2) | **Fixed** — audit.yml now mirrors ci.yml resolution: `pip install 'uv==0.5.30'` → `uv sync --extra dev` → `uv run pip-audit --strict` |

## 3. Access-control implementation inventory (NIST 800-171 AC substance)

The repository implements access control in product code; this section is the
auditable index of where (verifier note: src-layout — implementation lives
under `python/src/aegis_trust/`):

| Mechanism | Implementation | Verifying tests |
|---|---|---|
| Purpose-based policy gate | `python/src/aegis_trust/config.py` `get_purpose_policy()`; consumed in `shield.py` policy sync | `python/tests/test_shield_full.py`, `python/tests/test_plugin.py` |
| Authoritative principal = JWT subject (server-side), never client-asserted | `python/src/aegis_trust/client.py` (`/check-access` contract, CSR-03) | `python/tests/test_check_access_enforcement.py`, `python/tests/test_client_boundary.py` |
| Fail-closed multi-scope deny (no silent purpose-level widening) | `python/src/aegis_trust/client.py` `authorize`/`aauthorize` (Review finding B) | `python/tests/test_check_access_enforcement.py`, `python/tests/adversarial/test_redteam_S018_scope_bypass.py` |
| Field-level minimum disclosure | `@shield` filtering in `python/src/aegis_trust/shield.py`; conversion failures fail closed (`_ConversionFailed` sentinel, S018 D1) | `python/tests/test_clear_sensitive.py`, `python/tests/adversarial/test_redteam_S018_exception_leak.py` |
| Token lifecycle | rotation core `python/src/aegis_trust/client.py:707` `set_token()`; module-level helper `python/src/aegis_trust/shield.py:1614` `refresh_token()`; exchange via generated gateway client (`_generated/.../api/auth/`) | `python/tests/test_token_rotation.py` |
| Transport lock | TLS prod-lock `_resolve_verify_ssl()` in `python/src/aegis_trust/shield.py:142` (`client.py` passes `verify_ssl` through); node parity `resolveVerifySsl()` in `node/src/client.ts` | `python/tests/test_verify_ssl_prod_lock.py` |

## 4. Delta vs prior assessment (S017)

S017 (recorded in `python/CHANGELOG.md`: "Security Sprint S017: systematic
OWASP Top 10 + STRIDE coverage audit of v0.4–v0.6.4… CRITICAL=0, HIGH=0")
was a manual code-review pass. This S002 pass adds:

1. machine-verified dependency layer (pip-audit/npm audit, before/after logs);
2. machine-verified secrets layer over full history (gitleaks, 131 commits);
3. restoration of the CI dependency-audit control lost since the M4-era
   workflow, now mechanically protected against regression (S002-CI-2);
4. this committed, evidence-linked assessment format itself.

New code-level findings this pass: none (no product-code vulnerabilities
identified; all findings were dependency- or process-level).

## 5. Accepted risks (with owner and review deadline)

| ID | Risk | Why accepted now | Review by | Status |
|---|---|---|---|---|
| S002-AR-1 | **Merge-time fail-open**: `audit-gate` is not part of the `ci-gate` required status check, so a red audit does not block merges until the operator adds `audit-gate` to branch protection. The workflow itself is fail-closed at *build* level only (cross-review round-2 P1) | Branch-protection changes are an operator (repo-admin) action outside agent authority and outside this sprint's no-push boundary; workflow + weekly schedule already surface findings | next security-family sprint after S006 (this deadline pre-dated the T-040 renumber as "S003"; the first security-family sprint ran as S1005, now filed S006) — operator adds `audit-gate` to required checks | **S1005: reviewed — still open, operator action queued.** Branch protection at review time (`gh api .../branches/main/protection`): `required_status_checks.contexts=["ci-gate"]`, `strict=false`, `enforce_admins=true`. `audit-gate` confirmed absent. Concrete PATCH command packaged for the operator (exception `ex-20260611T014004Z-…-1ee18443`); execution remains repo-admin, outside agent authority. |
| S002-AR-2 | Node/TypeScript sources are outside the org-level ship-readiness AC verifier glob patterns (`.rs`/`.py` only) | Verifier-side limitation, not a repo defect; node parity is covered in-repo by tests and `version-parity.yml` | resolved in S1005 (now S006; deadline pre-dated the T-040 renumber as "S003") | **S1005: resolved as a verifier-side decision.** The org ship-readiness AC glob (`**/src/*.rs`, `**/api/*.py`, `**/src/*.py`, `**/src/**/*.py`) structurally cannot see `.ts`. Node AC substance is real (`node/src/client.ts`, `shield.ts`) and exercised by `node/tests/{shield,client,fullGate}.test.ts` in `ci.yml` node-test; THREAT_MODEL §2.5 records the Python/Node parity suites. Extending the glob to `.ts` is an org-level governance change (panel-gated, cross-project) handed off as a follow-up; not a repo defect. |
| S002-AR-3 | `python/.venv` fixes (idna/pip) are dev-machine-local state, not committed artifacts | The package declares no vulnerable pin (`httpx>=0.23,<1.0`); CI `audit.yml` resolves fresh on every run and fails closed, covering both consumers and CI | continuous (audit.yml) | **S1005: hardened.** The committed `python/uv.lock` was found pinning the vulnerable `idna 3.11` and `pip 26.1.1`; the fix is now a committed lockfile upgrade (idna→3.18, pip→26.1.2), not dev-local state. The `httpx>=0.23,<1.0` consumer-side argument still holds; AR-3 remains continuous via `audit.yml`. |

## 6. S1005 security-family delta (re-assessment)

- **Assessment date:** 2026-06-11 (sprint S1005 — now filed as S006 after the T-040 renumber — aegis-trust's first security-family sprint)
- **Method:** identical evidence discipline to §1 — command + tool version + exit code + committed raw log under `evidence/`.

### 6.1 Dependency / secrets re-scan (README rule: every security-family sprint)

| Layer | Tool (version) | Command | Before | After | Exit (after) |
|---|---|---|---|---|---|
| Python deps | pip-audit 2.10.0 | `python/.venv/bin/pip-audit --strict` | 1 (idna 3.11, CVE-2026-45409) → then `uv sync` from the stale lockfile re-surfaced pip 26.1.1 (PYSEC-2026-196) | **0** | 0 |
| Node deps | npm audit (npm 10.9.4, node 22.22.1) | `npm audit --audit-level=low` (in `node/`) | 0 | **0** | 0 |
| Secrets (git history) | gitleaks 8.30.1 | `gitleaks detect --config .gitleaks.toml --no-banner --redact` | 0 leaks (139 commits) | 0 leaks | 0 |

Raw logs: [`evidence/s1005-pip-audit-before.log`](evidence/s1005-pip-audit-before.log),
[`evidence/s1005-pip-audit-after.log`](evidence/s1005-pip-audit-after.log),
[`evidence/s1005-npm-audit.log`](evidence/s1005-npm-audit.log),
[`evidence/s1005-gitleaks.log`](evidence/s1005-gitleaks.log).

### 6.2 New finding this pass

| ID | Severity | Component | Finding | Disposition |
|---|---|---|---|---|
| S1005-DEP-1 | medium | python (committed `uv.lock`) | The committed lockfile pinned `idna 3.11` (CVE-2026-45409) and `pip 26.1.1` (PYSEC-2026-196), and was **stale** vs `pyproject.toml` (declared `jsonschema>=4.21` was unlocked; `uv 0.5.30 lock --locked` failed at HEAD). S002-AR-3 assumed only dev-local drift; the *committed artifact* itself carried vulnerable pins. | **Fixed** — `uv.lock` regenerated (idna→3.18, pip→26.1.2, jsonschema + transitive deps locked). `pip-audit --strict` exit 0 after; `uv 0.5.30 lock --locked` exit 0 (lockfile now consistent with `pyproject.toml`, matching the `audit.yml` resolution path). |

### 6.3 @shield LITE-mode boundary — adversarial pass

THREAT_MODEL §1's four LITE-boundary statements were mechanically exercised by
[`python/tests/adversarial/test_redteam_S1005_lite_boundary.py`](../../python/tests/adversarial/test_redteam_S1005_lite_boundary.py)
(6 tests, all passing): three positive protections (minimum-disclosure
filtering; exception-payload fail-closed; conversion-failure fail-closed) and
two documentation-honesty guards proving the *negative* non-claims still hold —
the unwrapped handler is reachable via `__wrapped__` and the decorator is
monkey-patchable in-process. The latter two confirm the documented "LITE does
not defend a hostile host; use FULL" boundary remains truthful. No over-claim
found in README / SECURITY.md / THREAT_MODEL relative to the tested behaviour.

### 6.4 THREAT_MODEL re-validation (cadence)

THREAT_MODEL.md §2 mitigation→test rows were checked for test-file existence
(all present) and the model re-validated per its §4 cadence. No new enforcement
point was added this sprint and no gateway contract (`schemas/v0`) changed, so
the STRIDE structure is unchanged; the model's "Last updated" stamp is advanced
to S1005 and the §2.x test references re-confirmed live.

## 7. Maintenance rule

This document is regenerated only from real tool runs (command + version +
exit code + committed raw log). Hand-written claims without a matching
evidence file are prohibited — see `docs/security/README.md`.
