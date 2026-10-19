# Threat Model — aegis-trust

- **Last updated:** 2026-06-11 (sprint S1005 re-validation — that sprint is now
  filed as S006 after the 2026-06-11 T-040 sprint renumber; first authored S002)
- **Companion:** [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md) (tool-verified
  state), root [`SECURITY.md`](../../SECURITY.md) (policy and disclosure)

## 1. What this SDK is, in threat terms

`aegis-trust` controls **what data AI agents can see**, based on declared
purpose and scope. It ships two enforcement postures with different trust
boundaries; conflating them produces a wrong threat model, so they are kept
explicit here.

### LITE (local-first, default)

```
┌──────────────── host process (single trust domain) ───────────────┐
│  caller code ──▶ @shield-wrapped function ──▶ field filtering      │
│                      (python/src/aegis_trust/shield.py,           │
│                       node/src parity)                            │
└────────────────────────────────────────────────────────────────────┘
```

- Enforcement runs **in-process**. The boundary protected is *accidental*
  disclosure: an LLM/agent receiving more fields than its declared purpose
  allows, exception payload leaks, conversion-failure leaks.
- **Explicitly NOT defended in LITE:** a malicious or compromised host
  process. Code in the same interpreter can read memory, monkey-patch the
  decorator, or call the unwrapped function. This is by design and documented
  (SECURITY.md "Out of scope": issues requiring local code execution).
  The defense against a hostile host is FULL mode. These non-claims are
  mechanically held truthful by `python/tests/adversarial/test_redteam_S1005_lite_boundary.py`
  (S1005): the `__wrapped__` escape hatch and decorator monkey-patch are
  asserted to remain reachable, alongside the positive LITE protections below.

### FULL (enterprise gateway)

```
┌── host (untrusted for secrets) ──┐        ┌── aegis-core gateway (trust anchor) ─┐
│ caller ─▶ SDK client ────────────┼─TLS───▶│ JWT subject + purpose gate            │
│  (python/src/aegis_trust/        │        │ /check-access  /check-boundary        │
│   client.py)                     │        │ audit event log (canonical schema)     │
└──────────────────────────────────┘        └────────────────────────────────────────┘
```

- The authoritative principal is the **JWT subject resolved server-side**;
  the SDK never sends a client-asserted identity (`client.py` CSR-03 note).
- Deterministic memory lifetime for cryptographic material is a **gateway**
  property, not an SDK property (SECURITY.md "Memory posture").

## 2. Per-component STRIDE

Severity baselines follow SECURITY.md "Disclosure baselines". Every
mitigation maps to a test that runs in CI (`.github/workflows/ci.yml`
python-test / node-test jobs).

### 2.1 `shield.py` (field filtering, LITE core)

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| Information disclosure | Filter returns more fields than `scope` allows (CRITICAL baseline) | minimum-disclosure filtering; deny-unknown | `python/tests/test_shield_full.py`, `python/tests/test_clear_sensitive.py`, `python/tests/adversarial/test_redteam_S1005_lite_boundary.py` (claim 1) |
| Information disclosure | Record→dict conversion raises and the exception carries user data (HIGH baseline) | `_ConversionFailed` sentinel: fail closed without re-attributing, raw cause withheld by default (S018 D1) | `python/tests/adversarial/test_redteam_S018_exception_leak.py`, `python/tests/adversarial/test_redteam_S1005_lite_boundary.py` (claims 2–3) |
| Tampering | ORM/pydantic objects that lie about their shape | real-framework conversion paths exercised (pydantic v2 `model_dump`, v1 `.dict`, SQLAlchemy `__table__` walk) | `python/tests/test_orm_pydantic.py` |
| Elevation of privilege | deny-rule bypass via crafted field names / nesting | adversarial deny-bypass suite | `python/tests/adversarial/test_redteam_S018_deny_bypass.py` |

### 2.2 `client.py` (gateway client, FULL boundary)

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| Spoofing | client-asserted principal | principal = JWT subject server-side, never sent by client | `python/tests/test_client_boundary.py` |
| Elevation of privilege | multi-scope request silently evaluated at broader purpose level (fail-open regression, "Review finding B") | `authorize`/`aauthorize` DENY >1-scope requests outright instead of widening | `python/tests/test_check_access_enforcement.py`, `python/tests/adversarial/test_redteam_S018_scope_bypass.py` |
| Tampering | TLS verification disabled in production | `_resolve_verify_ssl()` prod-lock (`python/src/aegis_trust/shield.py:142`; `client.py` only passes the resolved flag; node parity `resolveVerifySsl()` in `node/src/client.ts`) | `python/tests/test_verify_ssl_prod_lock.py` |
| Information disclosure | malformed gateway responses leaking through error paths | error envelope parity + malformed-ingest handling | `python/tests/test_error_envelope_parity_S018.py`, `python/tests/test_malformed_ingest_response.py` |
| Spoofing | stale/rotated credentials | token exchange + rotation lifecycle | `python/tests/test_token_rotation.py` |
| Repudiation | unverifiable REST boundary behavior | REST boundary adversarial suite | `python/tests/adversarial/test_redteam_S018_rest_boundary.py` |

### 2.3 `mcp_proxy.py` (MCP tool-call boundary)

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| Elevation of privilege / Information disclosure | tool calls crossing the proxy without purpose enforcement | proxy applies the same purpose/scope gate to MCP traffic | `python/tests/test_mcp_proxy.py` |
| Information disclosure | excluded values reaching the host through a server→host line the filter does not parse (embedded resource, prefixed text, error data, server log, sampling request, a second reply with the same id, `_meta`, completions) | every server→host line is rebuilt from a projection; what the field rule cannot inspect is withheld by default; unknown lines and server requests other than `ping` / `roots/list` are dropped | `conformance/mcp_relay.v0.json` (both SDKs), `python/tests/test_mcp_proxy.py` |
| Repudiation | an event saying `protected` for a result that was not inspected | `protected` only when every carrier was inspected; withheld carriers are named `<withheld:path>`; `--uninspected pass` names `<unfiltered:path>` and never writes `protected` | `conformance/mcp_relay.v0.json` |
| Elevation of privilege | the host's model widening its own access by writing `arguments.purpose` | the purpose comes from the policy's `tools` map; a different declared purpose is refused unless the operator passes `--allow-declared-purpose` | `conformance/mcp_relay.v0.json` |
| Information disclosure (named limit) | a server writing data values into its own interface metadata (tool descriptions, `instructions`), or signalling through numbers and timing | not closed: listings are narrowed to mapped tools and families and projected to spec keys; the limit is stated in `schemas/v0/mcp-hosts.md` and measured by a corpus case | `conformance/mcp_relay.v0.json` (`interface-metadata-named-limit`) |
| Tampering | SQL injection via tool arguments | injection adversarial suite | `python/tests/adversarial/test_redteam_S018_sqli.py` |

### 2.4 `canonical.py` + `schemas/v0` (contract v0)

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| Tampering / Repudiation | enforcement points drifting to incompatible policy/audit shapes (audit trail loses meaning) | single canonical policy schema + single audit event schema across all enforcement points; schema harness runs (not skips) in CI | `python/tests/test_canonical.py`, `python/tests/test_canonical_schemas.py`, `python/tests/test_contract_gate.py` |
| Tampering | hash drift on canonical material | SHA-3 known-answer vectors | `python/tests/test_sha3_known_vector.py` |

### 2.5 Node SDK parity (`node/`)

| STRIDE | Threat | Mitigation | Test |
|---|---|---|---|
| Tampering | Python/Node behavior divergence (one SDK weaker than the other) | parity suites + single version source of truth; `npm run parity` is the canonical version-parity check, enforced by `.github/workflows/version-parity.yml` | `python/tests/test_rc4_parity.py`, `python/tests/test_version_ssot.py`, `node/tests/` (222 tests) |

### 2.6 CI/CD + supply chain

| STRIDE | Threat | Mitigation | Test / control |
|---|---|---|---|
| Elevation of privilege | fork-PR token theft (`pull_request_target`), OIDC abuse, secret exfiltration from CI | read-only CI: no `pull_request_target`, no `id-token: write`, no secrets, SHA-pinned actions | `python/tests/adversarial/test_redteam_S018_ci_attack.py` (ci.yml), `python/tests/adversarial/test_redteam_S002_audit_workflow.py` (audit.yml) |
| Tampering | malicious/vulnerable dependency enters either package | lockfiles + fail-closed `pip-audit --strict` / `npm audit --audit-level=low` on push/PR + weekly (`.github/workflows/audit.yml`) | `SECURITY_ASSESSMENT.md` §1–2 (evidence-linked) |
| Tampering | dependency confusion / typosquat in install scripts | `npm ci` (lockfile-exact) and `uv sync` (uv.lock-exact) in CI; lockfile/pyproject integrity covered by the S018 supply-chain suite (`uv.lock` + `pyproject.toml` scope), audit-command integrity by the S002 suite | `python/tests/adversarial/test_redteam_S018_supply_chain.py`, `python/tests/adversarial/test_redteam_S002_audit_workflow.py` |
| Information disclosure | committed secrets in history | gitleaks over full history in CI with the default rules (since 2026-10-19), after a positive control proves the same binary + config detects a synthetic token; the earlier S002 scan ran with a rule-less config and is not evidence (`SECURITY_ASSESSMENT.md` §1 correction) | ci.yml `gitleaks` job; `python/tests/test_gitleaks_config_has_rules.py` |

## 3. Assurance claims vs non-claims (README alignment)

**Claimed:** minimum disclosure for declared purpose/scope; fail-closed on
filter/conversion/transport errors; JWT-subject-authoritative access checks in
FULL mode; supply-chain controls above.

**Not claimed:** protection against a hostile process in LITE mode (same
trust domain); deterministic secret zeroization inside the SDK process
(gateway property); any compliance certification (none held — see
ship-readiness "never_claim" discipline).

## 4. Review cadence

Re-validate this model in every security-family sprint, or immediately when: a
new enforcement point is added, the gateway contract changes (`schemas/v0`), or
a HIGH/CRITICAL disclosure-baseline finding lands.

- **S1005 (2026-06-11, now filed as S006 after the T-040 renumber):** re-validated. §2 mitigation→test rows confirmed
  present and live; no new enforcement point and no `schemas/v0` change, so the
  STRIDE structure is unchanged. LITE §1 boundary statements exercised
  adversarially (see `test_redteam_S1005_lite_boundary.py`). Next: the
  subsequent security-family sprint.
