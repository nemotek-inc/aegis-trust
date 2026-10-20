# Aegis Canonical Contract v0 — Policy + Audit Event + Identity Schemas

Status: **draft v0**

## What this is

One policy schema, one audit event schema, and one principal-identity schema,
shared by every Aegis enforcement point (PEP). The product line is the *same
contract at three enforcement strengths*:

| Form factor | Boundary | Strength | Target hosts |
|---|---|---|---|
| trust SDK (in-process) | inside the agent process | cooperative / hygiene | any Python/Node agent (embedded) |
| MCP proxy | process boundary, host unmodified | intermediate | Claude Code, codex, agy, Claude Desktop, any MCP-speaking agent |
| core gateway | host/network boundary + key separation | cryptographic enforcement | regulated environments |

A deployment upgrades enforcement strength **without rewriting policy**: the
same policy document drives all three forms, and all three emit the same
audit event shape.

Files:
- `aegis-policy.v0.schema.json` — the policy document contract (what operators write)
- `aegis-audit-event.v0.schema.json` — the audit event contract (what every PEP emits)
- `aegis-identity.v0.schema.json` — the principal identity contract (WHO a PEP resolved, and HOW strongly that identity is bound)
- `examples/` — valid sample documents, exercised by the validation tests
- `validate.py` — schema harness (positive examples + invariant-violation negatives)
- `project_gateway_audit.py` — projects gateway audit records into canonical v0 events
- `mcp-hosts.md` — registering the MCP proxy with Claude Code / codex / agy

## Binding requirements for v0

1. `enforcement_point` is REQUIRED on every audit event
   (`sdk | mcp_proxy | gateway`). One audit stream must remain interpretable
   across the enforcement-strength upgrade path.
2. Egress is part of v0, not a later addition. Policy has per-purpose
   `destinations.allow|deny`; audit events with `event_type=egress` must
   carry `destination`.

## Principal identity contract (aegis-identity.v0)

`aegis-identity.v0.schema.json` is the identity analog of the audit event's
`principal` block: the same `agent_id` / `auth_sub` shape, lifted into a
standalone cross-PEP record so identity stays consistent across the policy,
audit, and identity contracts. It makes the LITE→FULL identity upgrade path
explicit via `assurance`:

- `static_key` — an api-key→`agent_id` lookup (advisory self-identification, no
  cryptographic subject). This is what the in-process SDK form resolves today.
- `core_issued` — a signed, time-bound token whose `auth_sub` is the
  authoritative subject (`issuer` + `not_after` bound its lifetime).

The record gains `auth_sub` / `issuer` / `not_after` and flips to `core_issued`
with NO schema change the moment the gateway form ships identity issuance — the
genuine cross-form boundary (the gateway issues, the lighter forms verify).
`core_issued` is a contract *shape*, not a live capability today. A record is
never half-bound: all three authoritative fields are present together or not at
all (schema-enforced, exercised by `validate.py`).

## Carried invariants

- `scope` XOR `deny_fields` — exactly one per purpose
- `scope: []` valid (releases nothing); `deny_fields: []` invalid ("hiding nothing")
- unknown purpose / destination / tool ⇒ block. v0 offers no permissive default.
- dot-notation field paths (no leading/trailing/double dots)
- `identity_mismatch: true` on a principal forces `decision: deny`
- `allowed_fields` / `blocked_fields` carry field NAMES only, never values;
  `reason_code` is value-free
- identity `assurance` is all-or-none: `core_issued` REQUIRES `auth_sub` +
  `issuer` + `not_after`; `static_key` carries none of them (no half-bound
  identity)
- an identity record NEVER carries a secret (api key, raw token);
  `key_fingerprint` is the only credential reference and is non-secret (AO-005)

## Version axes (do not conflate)

| Axis | Current | Owner |
|---|---|---|
| canonical `policy_schema_version` | 0 | this contract |
| canonical `audit_schema_version` | 0 | this contract |
| canonical `identity_schema_version` | 0 | this contract |
| trust SDK AUDIT_SCHEMA_VERSION | 1 | local SQLite/JSONL + /shield/ingest |
| gateway audit schema | internal | gateway chain |
| Aegis-Api-Version header | 2026-05-18 | wire/API versioning |

Migration stance: products keep their internal audit/record versions; each PEP
ships an *emitter* that projects its native record into a canonical v0 event.
Emitters stamp the canonical version; readers fail-closed
(treat-as-unverifiable) on a higher major version.

## Implementation status

- SDK: `aegis_trust.canonical` — `load_canonical_policy()` (fail-closed
  loader) + `CanonicalEmitter` (JSONL event writer).
- MCP proxy: `aegis_trust.mcp_proxy` — stdio pass-through; gates
  `tools/call`, `resources/read`, `prompts/get`; rejects JSON-RPC batches;
  drops non-JSON server stdout; minimizes structured payloads; emits
  canonical events.
- Gateway: `project_gateway_audit.py` converts gateway audit JSONL into
  canonical v0 events (integrity chain required; free-text reasons never
  copied).
- All of the above are exercised in CI: schema harness, loader/emitter unit
  tests, and end-to-end proxy subprocess tests.

## Plane-NATIVE union-ledger projection (2026-07-05, extended 2026-07-16)

`project_gateway_audit.py` also recognizes plane-NATIVE union-ledger receipts
(`kind: "receipt"`, or `actor` + a decision in the native vocabulary) and maps
the full five-state `DecisionOutcome` vocabulary into the v0 binary decision
plus the five-state `outcome` refinement:

| native decision | v0 `decision` | v0 `outcome` | rationale |
|---|---|---|---|
| `BLOCKED` | `deny` | `blocked` | denial, final |
| `PROTECTED` | `allow` | `protected` | grant, minimum disclosure applied |
| `ACCESS_REDUCED` | `allow` | `access_reduced` | grant with reduced scope |
| `CHECK_REQUIRED` | `deny` | `check_required` | pending: nothing granted yet |
| `APPROVAL_REQUIRED` | `deny` | `approval_required` | pending: nothing granted yet |

The pending states project to `deny` per the v0 outcome contract ("deny maps
to blocked|check_required|approval_required"): a receipt that requires a check
or an approval has not released any data, and a later grant produces its own
`PROTECTED`/`ACCESS_REDUCED` receipt. Any decision outside this table still
raises `ProjectionError` (fail-closed skip-and-count, never guessed).


## Known v0 limits (documented, not hidden)

- **SDK evidentiary limit**: in-process events have no `integrity` chain; the
  writer is the agent itself ⇒ tamper-evident only after async export. The
  SDK form provides hygiene / blast-radius reduction, NOT enforcement.
- **roles in SDK/proxy**: advisory unless the deployment can resolve a
  principal's role; only the gateway binds identity cryptographically
  (`auth_sub`).
- **field classification**: `max_level` requires a field classification map;
  SDK/proxy skip it when absent.
- **proxy direction**: the proxy minimizes what enters the host's context
  (server→host). Host→server, a `tools/call`'s arguments pass only by the
  tool's rule (`--tool-rules`, every leaf on its allow list); `prompts/get` /
  `completion/complete` arguments are not judged, and `destinations` egress
  policy is enforced by the SDK/gateway forms in v0.
- **uninspected output (proxy)**: only structured payloads can be minimized
  (`structuredContent` / a text that is JSON as a whole / an embedded
  resource's JSON text). Everything else the server sends on a gated call is
  withheld by default; `--uninspected pass` relays it and the event names it
  as unfiltered, never `protected` (`schemas/v0/mcp-hosts.md`). Route
  sensitive data through structured results.
- **interface metadata (proxy)**: tool / resource / prompt descriptions,
  `serverInfo` and `instructions` are server-written and reach the host only
  as the operator pinned them (`--interface-pins`); anything unpinned is
  withheld (a tool keeps its policy-known name). Progress numbers are the
  proxy's own count. The presence and timing of lines remain a named limit.
- **operational decision verbs (gateway projection)**: `project_gateway_audit.py`
  maps monolith gateway records to canonical events only for `ALLOW`/`DENY`
  decisions (plane-NATIVE receipts map the full five-state vocabulary — see
  the projection table above); operational verbs the gateway also writes
  (`LIST`, lifecycle markers) are
  SKIPPED-AND-COUNTED, never guessed into `allow`/`deny` (2026-07-03 ruling:
  keeping v0's decision enum honest beats coverage — a projection that
  reclassifies an operational read as an authorization decision would
  misrepresent the audit trail to a regulator). Verified against BOTH homes:
  the re-homed boundary gateway writes the same vocabulary, so parity holds
  by construction (boundary-core `test_gateway_mount.py` P1). If v1 models
  operational events, it will do so with an explicit `event_type`, not by
  widening the v0 mapping.
