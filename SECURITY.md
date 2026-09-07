# Security Policy

`aegis-trust` is built around a **fail-closed** principle: data should be unable
to leak even when the system fails. We treat security findings as first-class
issues. This policy covers both SDKs in this repository — the Python package
([`python/`](python/)) and the TypeScript / Node package ([`node/`](node/)).

> Preview status: `aegis-trust` is a pre-GA Alpha preview. There is no SLA. The
> guarantees below describe the project's security *intent and process*, not a
> contractual commitment. See the root [README](README.md) for the full
> preview-state posture.

## Reporting a vulnerability

**Do not file a public issue for a suspected vulnerability. Report it privately
first.**

- **Preferred:** GitHub private vulnerability reporting —
  [open a draft advisory](https://github.com/nemotek-inc/aegis-trust/security/advisories/new).
- **Email:** `contact@aegisagentcontrol.com` with subject `[security] aegis-trust`.

Include:

- Affected SDK and version (`pip show aegis-trust` / `npm ls aegis-trust`)
- Reproduction steps (a minimal example)
- Expected vs actual behavior
- Which guarantee is violated, if applicable (see "Disclosure baselines" below)

We will acknowledge receipt within **48 hours** and provide a remediation
timeline within **7 days**.

## Disclosure timeline

- **Day 0** — Report received and acknowledged
- **Day 1–7** — Triage, severity assessment, fix planning
- **Day 7–30** — Fix developed, tested, released as a patch version
- **Day 30+** — Public disclosure via `CHANGELOG.md` and a GitHub Security Advisory

For high-severity issues (CVSS ≥ 7.0) the timeline is compressed: fix within
**7 days**, disclosure within **14**.

## Disclosure baselines

| Type | Severity baseline |
|---|---|
| `shield()` / `@shield` returns more data than `scope` allows | **CRITICAL** (Minimum Disclosure violation) |
| `shield()` / `@shield` propagates exceptions containing user data | **HIGH** (fail-closed violation) |
| API keys or secrets readable from logs / error messages | **HIGH** (secrets hygiene violation) |
| Denial of service via unbounded resource consumption | **MEDIUM** |
| Dependency CVE in a direct dependency | **MEDIUM** to **CRITICAL** depending on exposure |

## Out of scope

- Vulnerabilities in user code that wraps `shield()` (we cannot enforce policy
  outside our boundary)
- Issues that require local code execution on the host to exploit
- Issues in dependencies that are already publicly tracked (handled via
  dependency updates)

## Supported versions

Only the latest pre-release line receives security fixes during the preview
period.

| Version | Supported |
|---|---|
| `0.9.0-rc*` (current preview) | ✅ |
| `0.8.x` and earlier | ❌ |

## Memory posture (SDK-side limits)

Neither CPython nor Node.js offers deterministic, prompt zeroization of
in-memory secrets: `str` / `bytes` / `string` / `Buffer` references may persist
in caches, tracebacks, interpreter internals, or garbage-collector generations
after an explicit `del`. The SDK therefore follows a **split-responsibility**
model: the SDK provides best-effort clearing (overwrite mutable buffers, drop
references, force a collection cycle), while authoritative deterministic memory
lifetime for cryptographic material is a property of the `aegis-core` gateway,
not of the SDK process. For deployments where the SDK handles raw secrets on an
untrusted host, keep the SDK process short-lived and treat the gateway — not the
SDK — as the trust anchor.

## Supply chain

- Deterministic dependency resolution (lockfiles per package)
- Dependency audit (`pip-audit --strict` / `npm audit --audit-level=low`) on
  every push/PR plus a weekly scheduled run, via
  [`.github/workflows/audit.yml`](.github/workflows/audit.yml). Fail-closed at
  build level: a finding fails the workflow. Merge-blocking requires the
  operator to add `audit-gate` to branch protection (tracked as accepted risk
  S002-AR-1 in
  [`docs/security/SECURITY_ASSESSMENT.md`](docs/security/SECURITY_ASSESSMENT.md)).
  Workflow and command invariants enforced by
  `python/tests/adversarial/test_redteam_S002_audit_workflow.py`
- CI Actions are SHA-pinned
- Release artifacts (npm tarball, Python wheel + sdist) are signed with Sigstore
  cosign (keyless OIDC, Rekor public log) and attached to the GitHub Release.
  Customer-side integrity is verifiable with `cosign verify-blob` against the
  release assets.

## Security documentation

- [`docs/security/SECURITY_ASSESSMENT.md`](docs/security/SECURITY_ASSESSMENT.md)
  — latest tool-verified security assessment (commands, exit codes, findings,
  raw logs under `docs/security/evidence/`)
- [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md) — trust
  boundaries (LITE vs FULL), per-component STRIDE, threat→mitigation→test map

## Contact

- Security reports: `contact@aegisagentcontrol.com`
- Commercial / enterprise / licensing inquiries: `contact@aegisagentcontrol.com`
