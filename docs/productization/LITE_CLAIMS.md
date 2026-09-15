# aegis-trust LITE — Claims and Non-Claims

This document states exactly what aegis-trust **LITE mode** does and — just as
importantly — what it does **not** do. Every claim links to the code, test, or
command that backs it. Classification follows the project's four-bucket
discipline: **implemented** (verifiable in this repo), **customer-side** (your
environment, your responsibility), **roadmap** (documented gap), and
**never-claim** (things we will not say because they are not true today).

The one-line LITE claim ceiling is:

> *"Filtered locally by aegis-trust LITE. No gateway required."*

LITE is **cooperative, in-process hygiene** — a same-process filter. It is not
a separate trust boundary. Enforcement, tamper-evident audit, and decision
evidence belong to FULL (gateway/Core) and are never attributed to LITE here.

---

## 1. Embed parity (in-process `shield` contract, Python ↔ Node)

**What it is.** The same in-process shielding contract is embedded in both
SDKs: wrap a data accessor with a declared `purpose` and `scope`, and the SDK
returns only the fields the purpose allows.

**Implemented (claims we make):**

| Claim | Evidence |
|---|---|
| The mode set is identical: `LITE` / `FULL` / `AUTO`, with Python as the canonical definition | `python/src/aegis_trust/types.py` (`Mode` enum); `node/src/types.ts:31` ("parity with Python types.py") |
| A `shield()`-wrapped accessor returns the **filtered value directly** (not a wrapper object) in both SDKs | `node/src/index.ts` quickstart (`u → { name, email }`); repo root `README.md` Python example |
| The minimum-disclosure rule is shared: an empty spec (no `scope`, no deny list) is refused rather than passing data through | `node/src/shield.ts:625-632` ("parity with shield()/Python") |
| Deny-path edge cases fail closed the same way in both SDKs (e.g. scalar where a deny path was expected, prototype-member handling) | `node/src/filter.ts:129`, `node/src/filter.ts:228` (parity comments bind the Node behavior to the Python reference); test suites `node/tests/shield.test.ts`, `python/tests/` |
| AUTO does not silently degrade: with FULL intent configured but the gateway unreachable, `shield()` denies rather than falling back to LITE | `node/src/client.ts:761-795` and the Python `shield.py` parity (fail-closed FULL) |
| `wrap(value, options)` exists in **both** SDKs: a direct value filter returning a `ShieldResult` (`data`, `mode`, `purpose`, `scope`, removed-key list — Node `filteredKeys` / Python `filtered_keys`) | Node `node/src/shield.ts:612`; Python `python/src/aegis_trust/shield.py` (`wrap`) → `python/src/aegis_trust/types.py` `ShieldResult` |
| The LITE filtering of `wrap()` produces **identical output across SDKs** (same `data` and same removed-key SET), guaranteed by a shared conformance corpus rather than hand-mirrored tests: both SDKs run the same vectors | `conformance/filter_parity.v0.json`, run by `node/tests/filterParityCorpus.test.ts` and `python/tests/test_filter_parity_corpus.py` (a divergence fails CI in both ecosystems) |

(Previously `wrap()`/`ShieldResult` was a Node-only named parity gap. Closed:
Python now ships `wrap()` returning the `ShieldResult` dataclass, and the shared
conformance corpus pins both SDKs to identical filtering. The only intentional
difference is `filtered_keys` ordering — Node returns encounter order, Python
sorted; both report the same SET, so it is compared order-independently.)

**Customer-side:** choosing purposes/scopes that match your data model;
deciding which accessors to wrap.

**Never-claim:** LITE "enforces" anything against a hostile caller. The filter
runs in your process; code in the same process can bypass it. That is why the
vocabulary ceiling above exists.

---

## 2. Node parity (npm SDK tracks the PyPI SDK)

**What it is.** The Node package `aegis-trust` (npm) is a deliberate port of
the Python package of the same name (PyPI), kept at version and behavior
parity.

**Implemented (claims we make):**

| Claim | Evidence |
|---|---|
| Both packages are versioned together (0.9.3 at the time of writing) | `node/package.json`, `node/VERSION`, `node/src/index.ts`, `python/pyproject.toml` |
| Version parity is machine-checked across local sources, the git tag, and the live registries by one command | `npm run parity` (from `node/`; `scripts/version-parity.mjs`); offline form: `npm run parity -- --offline` |
| Framework adapters exist on both sides where the ecosystem exists (LangChain, CrewAI; plus Vercel AI SDK / MCP / streaming on Node) | `node/examples/` (`langchainExample.ts`, `crewaiExample.ts`, `vercelAiExample.ts`, `mcpTool.ts`, `streamExample.ts`); `python/examples/` (`langchain_example.py`, `crewai_example.py`, `stream_example.py`) |
| Versioning follows a written doctrine (SemVer + schema versions + stability levels + deprecation policy) | `node/docs/VERSIONING.md` |

**Roadmap:** any surface that exists in one SDK but not the other is treated
as a parity gap and tracked; it is not silently claimed as present on both.
The `wrap()`/`ShieldResult` full-result helper was the last named gap and is now
closed — present on **both** sides and pinned by a shared conformance corpus
(see §1). The boundary-receipt passthrough also exists on both sides (see §3).
No named LITE API parity gap remains at the time of writing.

**Named asymmetry (not a LITE gap, but stated here because this section
promises that any one-sided surface is tracked rather than silently claimed on
both):** the Python package ships a generated gateway client, and Node does not.
One consequence is customer-facing: `destroy_capsule` is importable from an
installed `aegis-trust` (PyPI) and reaches `POST /capsules/{id}/destroy` — an
irreversible transition, behind Admin authorization server-side, with no second
step. The npm package has no such surface at all. This is FULL-mode territory
rather than the LITE API the rest of this section is about, which is why it is
not counted as a LITE parity gap — but "no LITE gap remains" should not be read
as "the two packages can cause the same things." Tracked in
`conformance/invariants.v0.json` (INV-7, `asymmetry`: *structural and severe*)
and classified in `conformance/irreversible_ops.v0.json`; the Node side is held
by `node/tests/irreversibleOps.test.ts`, which fails if an irreversible surface
is ever added there.

**Never-claim:** "the SDKs are identical byte-for-byte." Parity means the
public contract and deny semantics track each other, with Python canonical.

**Never-claim:** "the two packages have the same reachable effect." They do not:
see the named asymmetry above.

---

## 3. Boundary receipt (typed decision view surface)

**What it is.** Both SDKs expose a typed, 1:1 passthrough surface for the
gateway's boundary decision: Node `checkBoundary(args)` and Python
`check_boundary()` / `acheck_boundary()` return the wire
`BoundaryDecisionView` (`outcome`, `allowed_fields`, `withheld_fields`,
`reason_code`/`reason_label`, `evidence`).

**Implemented (claims we make):**

| Claim | Evidence |
|---|---|
| Node: `checkBoundary()` is a typed passthrough of `POST /check-boundary`; the SDK adds no client-side decision logic | `node/src/client.ts` — `BoundaryDecisionView`, `CheckBoundaryArgs`, `checkBoundary` (symbol anchors; line numbers drift) |
| Python: `check_boundary()` / async `acheck_boundary()` with the same wire shape, parsed fail-closed (malformed views are rejected, not coerced) | `python/src/aegis_trust/client.py` — `BoundaryDecisionView`, `_parse_boundary_view`, `check_boundary`; `python/tests/test_client_boundary.py` |
| Field **names** are surfaced, never field **values** | `BoundaryDecisionView` doc comment in `node/src/client.ts`; projection tests in `node/tests/` |
| The decision view carries evidence pointers (`decision_id`, `integrity_checkable_at`, `recorded_at`) **when produced by the gateway** | `CoreDecisionEvidence` in `node/src/client.ts` and in `python/src/aegis_trust/client.py` |

**The LITE boundary, stated plainly (never-claim for LITE):**

- In LITE there is **no** `decision_id`, **no** evidence link, and **no**
  third-party-checkable receipt. The local in-process result — the filtered
  value itself, or Node's `wrap()` `ShieldResult` with `filteredKeys` (§1) —
  is not evidence.
- A `BoundaryDecisionView` with `source: "CORE"` only exists when a gateway
  produced it (FULL). We do not attribute it to LITE.

**Customer-side / upgrade path:** running a gateway (self-hosted) is what
turns boundary receipts on; the SDK call site stays the same.

---

## 4. Usage metering (pluggable metrics hook)

**What it is.** Both SDKs expose a pluggable callback that receives
`(endpoint, duration, status)` for SDK-issued calls, so you can wire your own
metrics system.

**Implemented (claims we make):**

| Claim | Evidence |
|---|---|
| Python: `set_metrics_hook(hook)` | `python/src/aegis_trust/client.py` — `set_metrics_hook` |
| Node: `setMetricsHook(hook)` with the same shape (`endpoint`, `durationMs`, `status`) | `node/src/client.ts` — `setMetricsHook`, exported from `node/src/index.ts` |
| The SDK does not bundle or auto-register a metrics backend (no global registry pollution); the hook is the integration point | `python/tests/test_metrics_hook.py` (records the design decision and pins the behavior) |

**Customer-side:** the metrics backend itself (Prometheus, statsd, Datadog,
…) and any billing/quota logic built on top of it.

**Never-claim:** "usage metering = billing" or "metering is enforced." The
hook observes SDK calls in your process; it is an observability surface.

---

## What this document is not

- Not a compliance statement. aegis-trust holds no certification (no SOC 2,
  ISO 27001, CMMC, FedRAMP, FIPS, or HIPAA certification), and this document
  claims none.
- Not a pricing document. The SDK is MIT-licensed and public; commercial
  arrangements are out of scope here.
- Not a FULL-mode datasheet. Enforcement, chain-hashed audit, and decision
  evidence are FULL (gateway/Core) properties and are documented there.

*Verification commands for everything time-dependent in this file (versions,
artifact list) are collected in `LITE_ARTIFACTS_AND_METADATA.md`.*
