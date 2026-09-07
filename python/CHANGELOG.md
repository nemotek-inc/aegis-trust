# Changelog

## [Unreleased]

### Changed — attribution updated to the current rights holder
- The copyright holder in `LICENSE` (and the byte-identical `python/LICENSE`),
  the vendor of record in `README.md`, the licence line in `node/README.md`, and
  the package author metadata (`pyproject.toml` `authors`) now name
  **NemoTek**. The repository moved to the `nemotek-inc` organisation on
  2026-09-01 and the transfer completed 2026-09-02; the published attribution
  had not been updated to match. No code, API, or licence *terms* change — this
  is the MIT licence with the holder stated correctly.
- Two historical entries asserted that the Aegis IP was held personally. That is
  no longer true, so the assertion is removed; what each release actually
  changed is kept.

### Added — typed, fail-closed reader for the AI-native `decision` object
- `aegis_trust.client.parse_authority_decision(decision)` returns an
  `AuthorityDecisionView` (with `BoundaryPartialView` for its `parts`). It
  exposes what the AI-native wire (`tool_call` / `stream_open` bodies,
  `stream_session().decision`) already returns but the SDK handed back as an
  untyped dict: the **server-derived** `fragment_tags`, the attribution
  trace `parts` (per-boundary field names and labels plus the free-text
  `reason_label`), and the chain pointers `decision_id` /
  `receipt_event_id` / `ledgered`, plus `outcome`, `verb`, `boundary`,
  `reason_code` / `reason_label`, `allowed_fields` / `withheld_fields`,
  `policy_generation` / `policy_digest`, `replayed`.
- Fail-closed for the shapes it checks (listed here and pinned one by one
  in the shared corpus; it is not a proof of authority consistency beyond
  them): a malformed object raises `AegisValidationError`
  (`aegis.aiNative.decisionShape`) instead of parsing into a defaulted view —
  an absent `fragment_tags` is refused, never read as "no tags released"; a
  tag (top-level or inside a partial) outside the value-free label SHAPE is
  refused (the receipt verifier's gate: ASCII label charset, length cap — a
  shape rule, not a semantic classifier; tags are server-derived labels and
  a label-shaped string is surfaced as-is); every member the frozen wire
  declares is required; the chain witness is two-way — a decision that
  claims `ledgered` must carry non-blank `decision_id` / `receipt_event_id`,
  and an unledgered decision is accepted only in its hard-fault form (BLOCKED,
  blank ids, no composed `fragment_tags`, no `allowed_fields` / `withheld_fields`,
  not `replayed`;
  the trace `parts` is preserved verbatim as the diagnostic of what was
  refused — a partial's `allowed_fields` / `fragment_tags` are what that
  boundary computed, never a grant; blank = nothing but ASCII whitespace, the
  same rule in both SDKs); a ledgered decision is also checked against its
  own trace (the composed `outcome` is at least as restrictive as every
  partial's and the composed `fragment_tags` contain every tag a partial
  carries, and the composed `allowed_fields` equal the winning partial's own
  allow set — which is how the authority composes them); `policy_generation`
  must be a non-negative integer no larger than 2**53 - 1 (the range both
  SDKs represent exactly; a whole-number float such as `3.0` is the same JSON
  value as `3` and reads as 3 in both; rounding of over-precise literals
  happens in the JSON decoder, before the reader, identically in both). The view is immutable (frozen dataclass,
  tuple sequences, no defaults for required members). Unknown
  members are ignored (additive-only contract). Shared cross-language corpus:
  `conformance/authority_decision_view.v0.json` (npm runs the same vectors).
- Not added to the flat `check_boundary` view on purpose: `BoundaryDecisionView`
  is unchanged because the flat wire never sends `fragment_tags` / `parts`
  (it already carries the ledgered bit as `evidence_available` and the
  decision id under `evidence`). A field the wire never fills would be a
  claim without a source.

### Deferred — request-side `session_id` / `fragment_tags` on `check_boundary` (not in this version)
- Not added. The decision plane's flat wire accepts neither field today and
  drops unknown request keys silently, and `fragment_tags` are server-derived
  (a caller can only ever add to them, never under-declare). An SDK argument
  that is sent but not received would be a parity claim this SDK cannot
  back. Both fields land together with the plane version whose flat wire
  accepts them, as one pinned SDK/plane pair, and that entry will name the
  pair.

## [0.10.2] - 2026-09-05

### Fixed — package metadata points at the repository's current home (no code change)
- The project URLs in the package metadata (`Homepage`, `Repository`,
  `Issues`, `Changelog`) still named the repository's previous GitHub owner
  after the move to `nemotek-inc`. The npm registry verifies the sibling
  package's `repository.url` against the build provenance and refused the
  0.10.1 upload on that mismatch (HTTP 422), so npm never carried 0.10.1
  while PyPI did. 0.10.2 is 0.10.1 with the URLs corrected — the Python and
  Node packages are identical to 0.10.1 in code and behaviour.

## [0.10.1] - 2026-09-01

### Fixed — release-gate hygiene (no API change)
- Public artifacts are English-only again: two internal-label characters in a
  changelog line and a module docstring were replaced with English.
- `0.10.0` was tagged but never distributed: the pre-release productization
  gate stopped it on exactly these findings (fail-closed), so `0.10.1` is the
  first version of this line on PyPI. Everything listed under `0.10.0` ships
  here.

## [0.10.0] - 2026-09-01

### Added — `check_boundary` carries an optional `destination_resource_id` (npm parity)
- `check_boundary` / `acheck_boundary` accept `destination_resource_id`
  (top-level wire field `destination_resource_id`, string). It is a
  caller-declared label for the concrete resource behind `destination` (for
  example a folder id or a channel id), sent verbatim and ONLY when set — a
  call without it produces a byte-identical body to before. The SDK neither
  validates the label nor changes its own result on it; what the server does
  with it is server-side policy, not a client guarantee.

### Changed — public surfaces no longer cite internal server file paths or internal ticket ids
- Docstrings and comments that pointed at server-side source files and
  internal work-item numbers now describe the wire contract in neutral terms.
  A schema self-test fixture that used a tenant-specific scope token now uses
  `example_ai_ops`. No behavior change.

### Added — `check_boundary` carries the A-1 delegation capability (npm parity)
- `check_boundary` / `acheck_boundary` accept `capability` (top-level wire
  field `capability`), and — the load-bearing half — it defaults to the token
  attached by the enclosing `delegate()` window. Existing call sites are
  unchanged and start carrying the proof automatically: a capability the
  developer must REMEMBER to pass is fail-open by omission, the same
  reasoning that put `guard_tool` in the call path. An explicit value wins;
  explicit `None` opts out for one call (the `_UNSET` sentinel mirrors Node's
  `undefined` vs `null`).
- The delegation store moved to `aegis_trust._delegation_context` so
  `client.py` can read it without closing an import cycle with `ai_native`.
  `current_capability` is still importable from `aegis_trust` and
  `aegis_trust.ai_native` — the public API surface is unchanged. The new
  module is stdlib-only, so LITE-only installs stay zero-dep.
- A `delegate()` window whose mint FAILED now refuses `check_boundary`
  locally (`aegis.boundary.delegationDenied`, `AegisValidationError`) instead
  of asking un-narrowed. Cross-model review caught this: `current_capability()`
  flattens the denied sentinel to `None`, so the query would have been
  answered at the PARENT's full width — and `allowed_fields` on that answer is
  exactly what Doctor hands the agent as authorization (`check_with_core` →
  `BoundaryDecision.allowed_data`). Same local fail-closed as `guard_tool` /
  `stream_session`. An explicit `capability` still works inside a denied
  window: a hand-carried token is not a guess.
- The denied-window refusal now triggers on "no concrete token supplied", not
  on "argument unset". Scoping it to the `_Unset` sentinel left the explicit
  opt-out (`capability=None`, and `""`) as a one-keystroke way past the refusal
  and straight to a parent-width query — the same widening the refusal exists
  to stop. Opting out is meaningful in a GRANTED window; inside a DENIED one it
  is precisely the thing being denied. An explicit `None` outside denial still
  opts out, unchanged. Found by a second cross-review round (codex and cursor
  independently, on the same lines), which also named the test gap: opt-out had
  only ever been exercised after a SUCCESSFUL mint, and denial only with unset
  or an explicit string, never the combination. Node twin: same fix.
- `acheck_boundary` is now a plain `def` returning a coroutine, not an
  `async def`. The ambient token is read when you CALL it, not when the
  coroutine is awaited: `coro = c.acheck_boundary(...)` created inside a
  `delegate()` window and gathered after the window exits would otherwise read
  a reset `ContextVar` and ask at full width, silently. Node captures at the
  call expression; this makes the two SDKs identical. `await
  c.acheck_boundary(...)` is unchanged for callers.
- Known boundary (pinned by test, not fixed): a bare `threading.Thread` does
  not inherit the `ContextVar`, so a call made there goes un-narrowed with no
  signal. Cross a thread with `contextvars.copy_context()` or pass
  `capability` explicitly.
- New error code `aegis.boundary.delegationUnsupported` (`AegisHttpError`,
  `status=501`): a deployment that cannot evaluate a presented capability
  refuses rather than deciding at full width. The generic non-2xx envelope
  read as a transient outage; this one names the deployment. A 501 WITHOUT a
  presented capability stays `aegis.http.nonOk`.
- Wire shape is the flat face's top-level `capability`, never the envelope
  dialect `delegation: {capability}` — the plane refuses that shape with 422
  precisely so a wrong-shape token is not dropped and answered at full width.

  DEPLOYMENT NOTE: only a decide-plane-fronted Core evaluates A-1 delegation
  on `/check-boundary`. Against a monolith-gateway build, a call inside a
  `delegate()` window now fails closed with the coded 501 above. That is the
  correct answer (the alternative is a silent widening), but it is a
  behavior change for non-plane-fronted deployments — confirm the serving
  deployment before relying on delegation here.

### Added — keyless receipt verifier (`aegis_trust.receipt_verify`)
- `session_dag_root` / `verify_session_receipt_structure` /
  `dangling_prior_receipt_refs` / `compute_lineage_root` /
  `verify_lineage_root` / `is_value_free_label` — consumer-side structural
  verification of Aegis boundary receipts without key material; hex vectors
  pinned cross-impl with Aegis Core (`boundary_adapter` / `lineage`) and the
  Node SDK. HONESTY BOUNDARY: authenticity of the keyed `audit_chain_link`
  remains Core-verifiable only — this module checks structure and internal
  consistency, never authenticity.
- Hardening: `verify_session_receipt_structure` reports hostile non-string
  refs/tags as problems (returns-problems contract) instead of raising a
  `TypeError` out of `sorted()`; `dag_root` is never recomputed over
  coerced values.

### Fixed — LITE zero-dep import path (doctor)
- `from aegis_trust.doctor import check` no longer pulls `httpx` into a
  LITE-only install: `check_with_core`'s client imports moved under
  `TYPE_CHECKING` (the doctor package eagerly imports `check_with_core`, so
  the runtime import graph must stay stdlib-only). Subprocess regression
  test added to the zero-dep suite.

### Changed — coded error envelopes on the FULL client (S022 audit remediation)
- `AegisClient` now raises the machine-parseable envelopes the Node SDK
  already raises (the documented cross-SDK error model): non-2xx →
  `AegisHttpError` (`aegis.http.nonOk`, carries `.status`); malformed
  `shield/ingest` body → `AegisIngestError` (`aegis.ingest.responseShape`);
  malformed `audit/verify` body → `AegisAuditError`
  (`aegis.audit.responseShape`); malformed AI-native bodies →
  `AegisValidationError` (`aegis.aiNative.responseShape`).
  Catch-compat: the shape errors still subclass `ValueError`; fail-closed
  wrappers (`tool_allowed`, doctor, `@shield` FULL) behave identically.
  Only code that caught `httpx.HTTPStatusError` specifically must switch to
  `AegisHttpError`.
- `aegis_trust.trace` validation codes are now Node-identical (S018
  doctrine): `aegis.trace.traceId.invalid` / `aegis.trace.parentId.invalid`
  (previously snake_case `trace_id`/`parent_id`).

### Fixed — CLI + proxy hardening (S022 audit remediation)
- `python -m aegis_trust.cli` now runs the CLI (module `__main__` guard);
  previously it exited 0 silently for every subcommand.
- `aegis history`/`aegis stats` print a clean hint instead of a raw
  `sqlite3` traceback when `AEGIS_HISTORY_PATH` points at a non-SQLite file
  (e.g. the Node SDK's `history.jsonl`).
- `aegis-mcp-proxy` exits 2 with a coded one-liner on a missing
  (`aegis.canonical.file.notFound`) or malformed
  (`aegis.canonical.topLevel.notJson`) policy file (Node-parity exit code
  and codes; previously a raw traceback with exit 1), and validates
  `AEGIS_MCP_GATE` env values at startup like the flag form.

### Changed — schemas/v0 projector: full five-state union-ledger vocabulary
- `project_gateway_audit.py` now maps `CHECK_REQUIRED` → `deny`
  (`outcome=check_required`) and `APPROVAL_REQUIRED` → `deny`
  (`outcome=approval_required`) per the v0 outcome contract — previously
  these live Core decision states raised `ProjectionError` and turned the
  projection red on legitimate ledgers. Unknown decisions still fail
  closed.

### Docs — honesty corrections (S022 audit remediation)
- README supply-chain paragraph now states npm provenance is enabled
  (matching the live release workflow; it previously said omitted).
- `check_boundary` witness-claims docstring gains a deployment caveat:
  claims are witnessed only on decide-plane-fronted deployments.
- `_generated/__init__.py` regeneration note describes the real
  openapi-python-client path (the referenced make target does not exist in
  this repo); LITE_CLAIMS.md anchors converted to symbol references.

### Added — AI-native Layer 2: the interposition layer (`aegis_trust.ai_native`)
- `@guard_tool` — the FULL-strength sibling of LITE's `@shield`: every
  invocation of the wrapped tool (sync or async) is decided by the boundary
  (`POST /tool-call`) BEFORE it runs. Deny / outage / malformed / unledgered
  → the tool never runs and the call returns `None` (the `@shield`
  convention — nothing to catch, nothing to forget). Arguments never leave
  the process (INV-6). Owner resolves param → `AEGIS_OWNER` →
  `AEGIS_AGENT_ID`; unresolvable denies locally.
- `delegate()` — a context manager that mints a (narrow-only) child
  capability at the sub-agent spawn boundary and attaches it to every
  guarded call inside the block via `ContextVar` (no hand-carried tokens).
  Nesting carries `parent_capability` automatically; a failed mint DENIES
  the whole window fail-closed (guarded calls return `None`, stream
  sessions refuse to open — running un-narrowed would be a widening); exit
  revokes the token by default (`revoke_on_exit=False` to opt out).
- `stream_session()` — a managed continuous-authz session (`with` /
  `async with`) that owns the background heartbeat and INTERRUPTS the agent
  the moment the boundary revokes: async form cancels the block and raises
  `AegisStreamRevoked`; sync form fires `on_revoke` (or interrupts the main
  thread as a last resort) and `__exit__` raises `AegisStreamRevoked` — a
  revoked session can never look like a clean run. N consecutive heartbeat
  transport failures (default 3) count as revocation
  (`gateway_unavailable`). Open deny / denied delegation window raises
  `AegisStreamDenied` BEFORE the block runs; normal exit closes witnessed.
- New errors: `AegisStreamDenied`, `AegisStreamRevoked` (carries `.reason`).
  New async floor variants: `atool_allowed`, `astream_open`, `astream_close`.
  Node parity: `guardTool` / `delegate` / `streamSession` — identical error
  codes, mirrored tests.

### Added — MCP proxy FULL mode: the in-path gateway gate (third PEP grows teeth)
- `aegis-mcp-proxy` now arms a per-call gateway gate when `AEGIS_MODE=full`
  (or `auto` resolving FULL): every gated call is decided BEFORE forwarding,
  so a deny means the tool never runs and a gateway outage is a deny
  (`gateway_unavailable`), never a pass-through. Gate primitive is explicit
  (`--gate` / `AEGIS_MCP_GATE`): `check-access` (default, @shield-parity,
  works on every live gateway) or `tool-call` (AI-native per-tool-call gate).
  LITE behavior is byte-for-byte unchanged when the mode is unset.

### Added — AI-native v1 wire floor: tool-call / capability lineage / streaming clients
- New `AegisClient` methods against the FROZEN boundary contract
  (`AI_NATIVE_V1_CONTRACT.md`, additive-only): `tool_call` / `atool_call`
  (per-tool-call boundary decision; arguments never leave the caller — refs and
  labels only), `tool_allowed` (fail-closed boolean gate: transport error,
  non-200, malformed body, non-passing outcome, or an UNLEDGERED decision are
  all a deny), `capability_mint` (returns the frozen `CapabilityGrant`
  dataclass; narrow-only lineage is enforced server-side), `capability_revoke`,
  `stream_open`, `stream_heartbeat` / `astream_heartbeat` (returns
  `StreamStatus`; anything but `ok` means STOP), `stream_close`. These are the
  wire FLOOR — the in-path interposition layer (MCP proxy tool-call mode,
  `@guard_tool`, `delegate()`, `stream_session()`) builds on them next.

### Fixed — openapi.json verb inversion + the CI hole that let it survive
- `/audit/verify` was declared `post` (client GETs) and `/audit-log` was
  declared `get` (client POSTs) — inverted since the stub landed; the
  path-only contract gate could not see verbs. Fixed both, added the six
  AI-native paths, and added `test_every_client_call_verb_matches_openapi_spec`
  so any (method, path) the client uses must be DECLARED with that verb.

### Added — `wrap()` reaches Node↔Python parity (closes the last named LITE API gap)
- New public `wrap(value, *, purpose, scope=, deny_fields=)` returning the
  `ShieldResult` dataclass (`data`, `mode`, `purpose`, `scope`, `filtered_keys`).
  It filters a value in-process and reports which dot-notation paths were removed
  — the Python analog of the Node SDK's `wrap()`/`filteredKeys`. Reuses the same
  filtering primitives as `@shield`, so behaviour is identical by construction.
- A **shared cross-SDK conformance corpus** (`conformance/filter_parity.v0.json`)
  is now executed by both SDKs (`python/tests/test_filter_parity_corpus.py`,
  `node/tests/filterParityCorpus.test.ts`). Both must produce the same `data` and
  removed-key set, so a Node↔Python filtering divergence fails CI in both
  ecosystems instead of drifting silently.

### Changed — LITE is now dependency-free (lower adoption friction)
- `pip install aegis-trust` pulls **no runtime dependencies**. The in-process
  `@shield` filtering path (LITE) imports nothing beyond the standard library.
- The gateway/FULL dependencies (`httpx`, `attrs`) moved to an opt-in extra:
  install `pip install 'aegis-trust[full]'` to connect a gateway (FULL/AUTO
  mode). `AegisClient` is imported lazily, so LITE never loads them.
- Driving FULL mode without the extra now raises a machine-parseable
  `AegisConfigError` (`code=aegis.client.gateway_extra_missing`) pointing at
  `pip install 'aegis-trust[full]'`, instead of a raw `ModuleNotFoundError`.
- **Migration:** if you use FULL/AUTO mode (a gateway URL or `AEGIS_TOKEN`),
  add the `[full]` extra. Pure LITE users need no change.

## [0.9.3] - 2026-06-13

### Fixed — live SDK↔gateway integration (found by a real end-to-end against aegis-core)
- `shield()` FULL no longer fail-closes against a live gateway: the SDK now sends the
  required `tool_name` on `/check-access` (previously omitted → HTTP 422 → every FULL
  authorize denied). `tool_name` is an audit label only; the allow/deny decision remains
  the JWT subject + purpose + scope.
- Two fail-open gaps closed. An explicit dev-host `AEGIS_URL` with no `AEGIS_TOKEN` now
  **warns** instead of silently resolving to LITE (the configured gateway was being
  bypassed). The allow-decision cache can be disabled with `AEGIS_ACCESS_CACHE_TTL_S=0`
  to remove the ~30s stale-allow window after a policy change or gateway outage (deny is
  never cached either way).
- Install friction: a pathless base URL (`host:port` with no `/api/v1`) is now
  auto-completed to `…/api/v1` with a one-time warning, instead of returning 404 on
  every call.

### Added — LlamaIndex adapter
- `to_llamaindex_tool` (`aegis_trust.adapters`): binds a `shielded_tool()` to a LlamaIndex
  `FunctionTool` via the injected `FunctionTool.from_defaults` factory (no LlamaIndex
  dependency; the tool's schema maps to LlamaIndex's `fn_schema` key). Runnable example
  `examples/llamaindex_example.py` + `tests/test_adapters.py` coverage. Brings LlamaIndex
  to parity with the existing LangChain / CrewAI adapters.

## [0.9.2] - 2026-06-05

### Added — Doctor v1: Core-backed `check_with_core()` against `/check-boundary` (fail-closed)
A new async Doctor entry point asks Aegis Core for the authoritative boundary
decision instead of deciding locally. `check_with_core(plan, *, client=None,
context=None)` POSTs to `/check-boundary` (Bearer auth, same plumbing as
`check_access`), maps the returned `BoundaryDecisionView` to the SDK
`BoundaryDecision` (`PROTECTED→ALLOW`, `ACCESS_REDUCED→REDUCE_SCOPE`,
`CHECK_REQUIRED→REQUIRE_CHECK`, `APPROVAL_REQUIRED→REQUIRE_APPROVAL`,
`BLOCKED→BLOCK`; `allowed_fields→allowed_data`, `withheld_fields→blocked_data`;
`policy_version="core-v1"`), and returns it so `decision.scope_for_shield()` still
drives `shield(scope=...)` unchanged. Fail-closed: any network error, non-2xx, or
malformed body yields a `BLOCK` with empty `allowed_data` (never raises raw, never
allows on error). The authenticated principal is the JWT subject server-side and is
never sent in the body. The local, deterministic `check()` (v0) is untouched. New
`AegisClient.check_boundary()` / `acheck_boundary()` methods and
`BoundaryDecisionView` wire types added.

#### Fail-closed hardening from 3-model cross-review
- **Partial Core response → BLOCK.** `_parse_boundary_view` now requires the
  **full** `BoundaryDecisionView` shape (`source`, `outcome`, `allowed_fields`,
  `withheld_fields`, `reason_code` all present and correctly typed). A
  partial-but-valid-JSON body like `{"outcome":"PROTECTED"}` no longer parses to
  a trusted view — it raises `ValueError` → `CORE_MALFORMED_RESPONSE` → BLOCK.
- **Own-key outcome lookup.** Outcome membership is resolved via `dict`
  membership in `_OUTCOME_MAP` (own-key only in Python), so attribute-style
  strings (`toString`, etc.) can never be accepted as a valid outcome.
- **Allow set cleared on non-grant outcomes.** Only `ALLOW`/`REDUCE_SCOPE` carry
  an allow set; `REQUIRE_CHECK`/`REQUIRE_APPROVAL`/`BLOCK` force `allowed_data`
  to `[]`, even if the Core body (incorrectly) carries `allowed_fields`.
- **Multi-destination fail-closed.** A plan with >1 destination now sends a
  restrictive sentinel (treated as external/unknown) instead of just the first
  destination, so the decision can only get stricter, never looser.
- **Mapping & client-acquisition inside the fail-closed boundary.** `_get_client()`
  and the view→decision mapping run inside the try, so any error (e.g. a malformed
  `plan`) → BLOCK rather than escaping as a raw exception.

### Fixed — `/check-access` scope contract (CSR-03) + multi-scope fail-closed
`check_access` / `authorize` previously sent `scope` as a JSON **array**, but the
gateway's `CheckAccessRequest.scope` is a single advisory `Option<String>`; an
array deserialized as a type error (non-200 → fail-closed). The SDK now sends a
single string for a one-element scope and omits the field otherwise (`None` =
purpose-level), matching the server. **Fail-closed hardening (cross-review):** a
`>1`-element scope can no longer be expressed faithfully against the single
`Option<String>` contract — `authorize`/`aauthorize` now **deny** a multi-scope
check instead of silently dropping to a purpose-level request the server could
ALLOW more permissively than asked. This restores the pre-CSR-03 fail-closed
direction (array body → server type error → deny). The single-scope (string) and
0-scope (purpose-level) paths and `authorize()`'s public boolean contract are
unchanged. (Note: in FULL mode, `@shield(scope=[...])` with **multiple** scope
fields now fails closed at the gate; use a single gate scope, or `/check-boundary`
via Doctor v1 for multi-field boundary decisions.)

### Docs — surface the shipped record-boundary streaming adapter
`shielded_stream_tool()` ships in 0.9.1 but was absent from the README, while the
"Alpha limitations" section implied streaming was unsupported and "planned for a
later release." Corrected: record-boundary streaming (LITE) is now documented in
the Runnable-integrations table, a dedicated README section, and a runnable
example ([`examples/stream_example.py`](examples/stream_example.py)); the
limitation entry scopes the real remaining gaps (token-level partial-chunk
filtering — not possible by design — and FULL-mode streaming, a tracked
follow-up). No code change; behaviour is unchanged (14 `test_adapters_stream.py`
cases stay green).

### Security — Doctor↔shield trust-boundary hardening (fail-closed by default)
An independent red-team + synthetic-market sweep found that the (unreleased)
`doctor.check()`→`shield(scope=...)` path failed **open** along several axes.
All are now closed by construction:
- **Path-aware, normalized field matching.** `never_fields` / `sensitive_fields`
  / per-purpose `deny` now match any path that **is**, **descends from**, or
  **encloses** a guarded field — `never_fields=["ssn"]` blocks `profile.ssn`;
  `["config"]` blocks `config.api_key`. Comparison is Unicode-NFKC + casefold +
  trimmed, so `SSN` can no longer dodge `ssn`. `allow` whitelists grant a field
  and its descendants only (never a parent).
- **`shield` drops a bare leaf over a record-like value (fail-closed).** A bare
  `scope=["config"]` over a nested mapping/object no longer discloses the whole
  subtree — it drops with a warning pointing at the explicit `'config.<field>'`
  form (previously only collections-of-records were dropped; plain mappings
  leaked). **Behaviour change** to `shield`: enumerate nested fields explicitly.
- **Unknown destinations are treated as external (fail-closed).** A destination
  named but listed in neither `external_destinations` nor the new
  `internal_destinations` no longer bypasses the minimum-disclosure strip.
- **Unknown purpose fails closed by default** (`strict_unknown_purpose=True`):
  a purpose absent from a non-empty `purposes` map yields an empty allow set
  rather than allowing everything. Set `strict_unknown_purpose=False` for the
  prior permissive behaviour.
- **Enforcement coupling:** new `BoundaryDecision.scope_for_shield()` returns the
  scope only for `ALLOW` / `REDUCE_SCOPE`; for `REQUIRE_APPROVAL` / `BLOCK` it
  returns `[]`. Use it (not `allowed_data`) to drive `shield` so nothing flows
  before a required approval. `allowed_data` remains the diagnostic field.
- **Malformed field paths fail closed at the gate** (`MALFORMED_FIELD_PATH`)
  instead of deferring an exception to `shield` construction; this also rejects
  `..`-bearing (path-traversal) field paths.
- **`shield` drops a bare leaf over a `Mapping` / record-like value** (incl. the
  Node `Map` case found by cross-model review) — no whole-subtree disclosure.
- **Prototype-name purposes fail closed** (parity contract): a `purpose` of
  `"__proto__"` / `"constructor"` cannot be treated as a known rule-less purpose.
  Python's `dict.get` is immune by construction; the Node SDK was fixed to use
  own-property lookup (found by the post-fix red-team re-run) and a regression
  test locks the behaviour as a cross-SDK contract.
- **Examples + threat-model:** the `doctor` example now drives `shield` from
  `decision.scope_for_shield()` (not `allowed_data` raw), and the README "Scope
  of these guarantees" section calls out `doctor.check()` as a local, in-process,
  bypassable diagnostic — fail-closed for an honest caller, not a sandbox.
- **Open-direction matches are exact — no normalization confused-deputy.**
  Normalization is one-directional: the never/sensitive/deny *guards* normalize
  (block more, fail-closed), but the two *permissive* matches — the `allow`
  whitelist and `internal_destinations` — match the **literal** token. Loosely
  matching ``"NAME"`` against ``allow=["name"]`` (F-1), or ``"INTERNAL_SINK"``
  against ``internal_destinations=["internal_sink"]`` (F-2), would authorize the
  attacker's token and disclose a *distinct* field / skip the sensitive strip for
  a *different* endpoint. Found by post-fix red-team passes.
- New `LocalPolicy` fields: `internal_destinations`, `strict_unknown_purpose`.

### Added — Doctor: pre-action boundary diagnosis (`aegis_trust.doctor`)
- **`check(plan, policy)`** — a new local Trust Boundary primitive that diagnoses
  an Actor's **action plan before it executes** and returns a deterministic
  `BoundaryDecision`. Where `shield()` filters the data an agent *receives*,
  `doctor` decides — ahead of time — what an agent may *do*: which fields are
  justified for the declared purpose, whether sensitive fields are leaving for an
  external destination, and whether the action needs human approval.
  - Verdicts: `ALLOW` / `REDUCE_SCOPE` / `REQUIRE_APPROVAL` / `BLOCK`
    (`REQUIRE_CHECK` reserved). Maps 1:1 to the planned Trust Signal outcomes.
  - **Feeds `shield` directly:** `shield(scope=decision.allowed_data)` — one
    boundary, diagnosed then enforced.
  - **Deterministic, local, LITE-only:** no network, no LLM, no Aegis Core. The
    rule source is a declarative `LocalPolicy` (per-purpose allow/deny, sensitive
    fields, never-fields, external destinations, action approval rules).
  - **Fail-closed:** a `never`-listed field (e.g. secrets) hard-`BLOCK`s the
    action with an empty allowed set.
  - Versioned shared contracts (`schema_version`), 1:1 with the Node SDK:
    `TrustContext` / `ActionPlan` / `BoundaryDecision` / `BoundaryReceipt`
    (Local Receipt is `evidence_mode="local"`, `core_verified=False` — LITE never
    claims Core's authority).
  - New module `aegis_trust.doctor`; runnable `examples/doctor_example.py`.
    Zero new runtime dependencies. No `shield()` behaviour change; no version bump.
  - Authoritative enforcement, principal/tenant binding, and formal Evidence
    remain Aegis Core's responsibility (not provided by this SDK).

### Added — streaming framework adapter (`aegis_trust.adapters`)
- **`shielded_stream_tool(...)`** — streaming sibling of `shielded_tool()` for a
  data accessor that yields a *sequence* of records. `stream(...)` is an async
  generator that filters each record to the declared `scope` / `deny_fields`
  **at its boundary, as it arrives** — without buffering the whole result first
  (the limitation `shielded_tool()` has today). The streaming unit is one
  fully-formed record, not a token: field-level minimum disclosure needs a
  complete object, so partial-chunk filtering is intentionally out of scope.
  - Reuses the **same `shield()`** per record (pinned LITE) — one trust
    boundary, one fail-closed contract; no second filter implementation. LITE is
    a local, network-free field filter, so per-record cost is negligible.
  - **LITE-only (v1), FULL refused fail-closed.** FULL's `/check-access` gate
    must run *before* the accessor executes; a per-record gate would run the
    accessor first and, on deny, emit one placeholder per matching row —
    leaking result cardinality and breaking the pre-execution guarantee
    `shielded_tool()` gives (and FULL's audit-completeness contract). So
    `mode="full"` raises `aegis.shield.stream.full_unsupported` at construction,
    and `mode="auto"` that resolves to FULL at run time refuses fail-closed
    (empty stream, accessor **never called**) rather than silently downgrade the
    gate. For FULL today, use `shielded_tool()`. FULL streaming
    (open-gate-then-stream + batched audit) is a tracked follow-up.
  - **Fail-closed (stream form):** a handler that raises before producing yields
    an empty stream; an iterator that raises mid-stream stops cleanly (no
    re-raise, the in-flight raw record is never emitted, already-filtered records
    stand). A framework never sees an exception that could carry withheld data.
  - Accepts sync or async iterables/generators (and a coroutine resolving to
    one). Audit records the tool name via `name`, symmetric with
    `shielded_tool()`. Mirror of Node `shieldedStreamTool` (cross-SDK parity).
  - Zero new runtime dependencies; unit-tested in `tests/test_adapters_stream.py`
    without any framework installed.

### Added — framework adapters (`aegis_trust.adapters`)
- **Dedicated agent-framework adapters for LangChain and CrewAI (Python)**,
  matching the Node adapter surface. New module `aegis_trust.adapters`:
  - `shielded_tool(...)` — a framework-neutral primitive that wraps a data
    accessor in `shield()` (filtering + minimum-disclosure fail-closed) and
    exposes `run()` / `call()` (and `arun()` / `acall()` for async handlers).
    The accessor is named from the tool `name`, so the audit log records the
    tool name rather than the handler's incidental `__name__` (e.g. `<lambda>`).
  - `to_langchain_tool(StructuredTool.from_function, tool)` — the factory is
    dependency-injected, so aegis-trust takes no dependency on LangChain.
  - `to_crewai_tool(BaseTool, tool)` — builds a CrewAI `BaseTool` subclass; the
    base class is injected (no dependency on CrewAI).
  - Zero new runtime dependencies; binders unit-tested (`tests/test_adapters.py`)
    without any framework installed. Runnable examples under `examples/`.
  - The shield filters the return value, not the arguments; failures fail closed
    as an empty result (never a raised exception). No core `shield()` change.

### Changed (LITE error-parity remediation)
- **Rich error envelope on the LITE validation/config path (D2).** The Python
  LITE path now raises the already-public `AegisValidationError` /
  `AegisConfigError` envelopes — carrying `.code` / `.remediation` /
  `.docs_url` / `.to_dict()`. The `code` strings match the Node SDK for the
  shared concepts (`aegis.shield.spec.required`, `aegis.shield.mode.invalid`,
  and every `aegis.config.*` code), so a polyglot consumer can switch on the
  same `code` across SDKs. New Python-side codes: `aegis.shield.spec.conflict`,
  `aegis.shield.deny_fields.empty`, `aegis.shield.field_path.invalid`.
  `load_config()` now also wraps YAML parse failures
  (`aegis.config.yamlParseError`) and missing explicit paths
  (`aegis.config.fileNotFound`) with the machine-parseable envelope.
- **Backward compatibility — every natural `except` contract is preserved
  (D2, P1 audit fix).** The rich envelope is layered *onto* the builtin
  exception type each path historically raised, not in place of it:
  - `except ValueError` — validation + config-structure errors
    (`AegisValidationError` / `AegisConfigError` subclass `ValueError`).
  - `except TypeError` — `scope` / `deny_fields` type-shape checks stay raw
    `TypeError` (deliberately not ValueError-family).
  - `except FileNotFoundError` / `except OSError` — a missing config file now
    raises `AegisConfigFileNotFoundError`, which **is a** `FileNotFoundError`
    (hence an `OSError`) as well as an `AegisConfigError` / `ValueError`.
  - `except ImportError` — a missing optional `yaml` dependency now raises
    `AegisConfigImportError`, which **is an** `ImportError` as well as an
    `AegisConfigError` / `ValueError`.

  All of the above simultaneously expose `.code` / `.remediation` /
  `.docs_url` / `.to_dict()`. (An interim S018 build briefly broke
  `except FileNotFoundError` / `except OSError` / `except ImportError` by
  raising only a `ValueError`-based `AegisConfigError`; the adversarial audit
  flagged it and this release restores the natural catches.)
  `get_purpose_policy()` still degrades to `None` for "no config available"
  (missing file / missing `yaml` dep) and still surfaces a malformed
  `aegis.yaml`.
- **Conversion-failure diagnostic — minimum-disclosure by default (D1, P1 + P2
  secret-leak hardening).** When a record→dict conversion (`model_dump` /
  `.dict` / `dataclasses.asdict` / SQLAlchemy `__table__` walk / NamedTuple
  `_asdict`) *raises*, `@shield` emits a developer diagnostic composed of
  **only SDK-controlled fixed strings**: a fixed `conversion_failed` marker, a
  fixed `stage=<label>` enum (`pydantic_model_dump` / `pydantic_dict` /
  `sqlalchemy_conversion` / `dataclass_conversion` / `namedtuple_conversion`),
  and a fixed remediation. It **withholds every application-controlled string**:
  the exception message, the traceback (no `exc_info`), the object's
  `repr`/`str` (dunders never invoked), **the type/exception class names**
  (`type(data).__name__` / `type(cause).__name__`), **and the `trace_id`**.
  Rationale: (P1) a failing record's exception message routinely echoes the
  filtered field values (`customer_ssn=…`, `stripe_secret_key=…`, PHI, internal
  prompts) — the original build logged that + full traceback; (P2-1) the first
  fix still surfaced the type/exception *class names*, and an independent
  re-audit showed a dynamically named class (e.g.
  `type("customer_ssn_…_Error", …)`) leaks its name; (P2-2) a second
  independent CAG review noted the `trace_id` was still surfaced and its
  validator (`^[A-Za-z0-9._:-]{1,128}$`) accepts secret-shaped tokens (e.g.
  `sk_live_…`), so it is now withheld from the diagnostic too (the trace_id
  feature + "never pass secrets as trace_id" contract remain for the audit
  JSONL). No opt-in to dump the raw detail — minimum-disclosure is the only
  mode. The genuinely-unsupported return type gets a distinct fixed
  `unsupported_return_shape` marker (also withholding the type name).
  Fail-closed unchanged.
- **Local-history write-failure visibility — fixed-string diagnostic (D3, P1 +
  P2 hardening).** With `AEGIS_HISTORY=1`, a history store init/write failure no
  longer (a) escapes and breaks the `@shield` data path (store init runs inside
  the guarded block, Node parity), or (b) logs a cause-less line. It emits a
  one-shot diagnostic composed of **only SDK-controlled fixed strings**
  (`history_write_failed local_evidence_not_recorded=true` + fixed remediation +
  the "not an authoritative audit record" disclaimer). It **withholds the
  `AEGIS_HISTORY_PATH` value** (may embed tenant / user / secret path segments),
  the raw exception message + traceback (an `OSError` message echoes the path),
  **and the exception class name** (P2 — an application-controlled identifier).
  Local developer diagnostic only — not an authoritative-audit guarantee.
- Real-framework verification: the conversion-failure leak/fail-closed tests
  now run against the genuine Pydantic v2, Pydantic v1, and SQLAlchemy code
  paths (added to the `dev` / `frameworks` extras), not duck-typed simulations.
- Not a parity item: empty / Unicode `purpose` remains accepted in Python (it
  is a free-text label, not a validated field — Node validates it). No `Actor` /
  `Decision` / `resource_*` / proof / tamper-evidence / Core changes.

### Added (schema_version contract)
- `schema_version` is now stamped on every audit event the SDK emits, from a
  single source (`aegis_trust._constants.AUDIT_SCHEMA_VERSION = 1`, re-exported
  by the package root). Wired to both surfaces consistently: local SQLite
  history (`shield_history.schema_version INTEGER NOT NULL DEFAULT 1`;
  `HistoryStore.record` / `record_idempotent` stamp it from the constant, so the
  caller→store keyword signature is unchanged — this structurally prevents a
  silent-failure drift class) and the `/shield/ingest` wire payload (additive
  field; the aegis-core gateway ignores unknown fields, backward-compatible —
  the gateway does not yet persist/use it).
- Backward compatibility: existing v0.8.x/v0.9.x databases are migrated with an
  idempotent `ALTER TABLE … ADD COLUMN schema_version INTEGER NOT NULL DEFAULT
  1`; rows written before the column read back as `1`.
- `schema_version` is intentionally **excluded** from the idempotency
  `_payload_hash` — cross-language SHA-256 byte parity with the Node SDK is
  unchanged.
- Deferred (not implemented): typed `Actor`, `Decision` enum,
  `resource_id`/`resource_type` (the latter is the schema_version=2 shape, gated
  behind a separate decision).

## [0.9.1] — 2026-06-03 — package author/copyright correction (metadata only)

### Changed
- **Package author/copyright label corrected.**
  The previous label named a company that was not registered at the time, so it
  implied a corporate entity that did not exist. Updates the
  `pyproject.toml` `authors` field and the `LICENSE` copyright line. No code
  change — functionally identical to `0.9.0`; published only to correct the
  immutable package metadata on the registry.

## [0.9.0-rc8] — 2026-05-30 — cross-SDK version-lock (no Python code change)

**No Python API or behavior change.** This SDK
is the fail-closed reference; rc8 reconciled the **Node** SDK to match Python
on four data-path edges (empty-spec rejection, deny-over-non-record, wrapped-fn
exception, FULL-mode audit-completeness) plus a Node-only prototype-name `scope`
bypass. Python was already fail-closed on all of these and is unchanged. Version
bumped to keep the cross-SDK version-lock with npm `aegis-trust@0.9.0-rc8`.

## [0.9.0-rc7] — 2026-05-26 — Pre-publish substrate gate wire + CHANGELOG artifact cleanup

rc7 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). **No public API change**; this release moves the productization 9-verifier gate into the release pipeline so every future tag push is mechanically audited before any artifact is built or published, and cleans sprint-internal Japanese strings out of the shipped `CHANGELOG.md`. Paired with npm `aegis-trust@0.9.0-rc7` (cross-SDK version-lock).

### Changed — release pipeline now runs a fail-closed 9-verifier gate before publish

- `.github/workflows/release-attestation.yml`: a `productization-gate` job runs a fail-closed 9-verifier quality gate (5 P0 + 4 P1) against the workspace before any artifact is built. `sbom-node` + `sbom-python` now `needs: [productization-gate]`; `collect-and-sign` / `pack-and-sign-sdk` / `publish-npm-trusted-publisher` are transitively gated. If any P0 verifier fails on a tag push, **no SBOM is generated and nothing is published**. Pending P1 verifiers (e.g. `top_1_pct_readability` while the 5-oracle survey is queued, or `agent_callable_surface` for JSDoc-incomplete TS exports) do not block.
- The release runner provisions the quality-gate substrate out of band; on a runner without it the gate fails closed (`runner not found` exit 2). This is the first release where the gate is wired into the publish pipeline.

### Changed — `CHANGELOG.md` is now english-first (artifact cleanup, no code change)

- `python/CHANGELOG.md` S023 + S024 entries: drop sprint-internal annotation that was non-english (it referenced the integration sprint's working title in the original ops language). The CHANGELOG is bundled inside the PyPI wheel / sdist (`hatch.build.targets.sdist` includes `CHANGELOG.md`), so customer-facing artifact text must be english-first per `internal-ops/9-verifier #2 english_first_artifact`. The S024 entry now reads "Beta attestation + live Full-mode end-to-end proof"; the S023 entry now reads "Full-mode live wiring". No semantic difference from the prior text — the dropped strings were sprint-internal annotation, never customer-facing claims.
- Same fix on the Node side (`node/CHANGELOG.md` S179 reference line): the non-english sprint annotation is replaced with "mil-spec test-honesty doctrine".

### Added — Python-side idempotency invocation script (closes verifier coverage gap)

- `python/tests/idempotency/invocation.py`: mirrors `node/tests/idempotency/invocation.py` contract. The internal-ops `idempotency_guarantee` verifier copies this script to `python/.productization_idempotency_test.tmp` and exercises `HistoryStore.record_idempotent` under a fixed `idempotency_key` for 1 initial + 100 retries. State is observed via a deterministic JSONL snapshot of audit rows projected to fields that are invariant under idempotent retry (function / purpose / scope / deny_fields / blocked_fields / mode); SQLite row id + timestamp are excluded because they would differ across the initial-vs-retry boundary if the system clock or auto-increment counter advanced. Previously the Python-side verifier ran with no invocation script and reported `ERROR`; rc7 fixes this gap so the gate produces a real PASS/FAIL verdict for both SDKs.

### Routed scenarios (internal review)

- `family_5_ops_ci_release / supply_chain_attestation`: incremental — gate is now invoked by the publish pipeline (was only a maintainer-local dogfood through rc6). Still `closure_candidate` until external oracle walk closes the literal residual.
- `family_5_ops_ci_release / npm_pypi_latest_rc_tag_drift`: unchanged — `dist-tags.latest` intentionally stays on `0.9.0-rc3` per the pre-release-doesn't-promote-to-latest design. `npm install aegis-trust@rc` resolves to rc7.



rc6 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API is additive over rc5 with one **behavioral change** on FULL-mode fail-closed return value (see `shield()` FULL mode entry below: shape-preserving empty → `None`). Paired with npm `aegis-trust@0.9.0-rc6` (cross-SDK version-lock).

This is also the **first release cut from the `aegis-trust` monorepo itself** (rc1–rc5 were published from `aegis-shield`, the historical mirror; see `aegis-shield/README.md` L1 `📍 Source moved`). Provenance attestation (SBOM + cosign keyless signatures + GitHub Release artifact attach) is generated by `.github/workflows/release-attestation.yml` (Block B Phase 2) on the `v0.9.0-rc6` tag push.

### Changed — `_detect_mode` now intent-first (matches AUTO behaviour matrix; Node parity)

- `python/src/aegis_trust/shield.py` `_detect_mode()` checks
  `_user_intends_full()` BEFORE probing the backend, parity with the
  node `detectMode` intent-first fix (same release). Removes the
  opportunistic-upgrade path that called `/check-access` from no-token
  dev environments and contradicted the documented matrix.
- New behaviour:
  - `AUTO + no Full intent` (no `AEGIS_TOKEN`, no non-dev URL) → LITE
    (no probe, no `/check-access`).
  - `AUTO + Full intent + reachable backend` → FULL (opportunistic
    upgrade with intent).
  - `AUTO + Full intent + unreachable backend` → fail-closed FULL +
    warning. Unchanged.
- **Routed scenarios** (internal review verification batch 1):
  `python_node_parity` divergence #2 (AUTO degrade) — resolved.

### Changed — `shield()` FULL mode now performs a real `/check-access` trust gate (T-SDK-FULL-GATE-01 parity)

- **Python `shield()` FULL mode previously executed the wrapped function BEFORE calling `/check-access`** — the gate fired on the already-computed result, so any side effects (DB writes, billing, etc.) had already happened by the time the gate could deny. This release brings the Python SDK to parity with the Node `T-SDK-FULL-GATE-01` fix (landed on `main` 2026-05-22, commit `b687e99`):
  - In `FULL` mode, both the async and sync shield wrappers now `await client.aauthorize(...)` / call `client.authorize(...)` **before** the wrapped function runs. The wrapped function executes **only** after authorization is granted.
  - Deny / `/check-access` raised (network error, gateway unreachable) → wrapped function **never invoked**, call returns a bare `None`. Because the function never ran, there is no return shape to mirror — the fail-closed value is `None`, not the prior `_empty_for(data)` (shape-preserving empty). This is the same contract as the Node SDK.
  - Audit ingest (`/shield/ingest`) runs only **after** authorization succeeds — post-authorization telemetry, never the gate.
  - Filter / freeze exceptions after a granted authorization still fall back to a type-shaped safe empty (`_empty_for(data)`) since the function ran and the data shape is known.
- Internal helpers `_shield_full`, `_shield_full_async`, `_shield_deny`, `_shield_deny_async` gain a keyword-only `pre_authorized: bool = False` parameter. When invoked from the shield wrapper (which now does the pre-call gate), the helpers skip the in-helper `authorize()` call to avoid a double audit. External call sites are unaffected (additive keyword arg, default preserves prior behaviour).
- **Behavioral change**: callers that previously received a shape-preserving empty (`{}` / `[]` / `""`) on FULL deny / unreachable now receive `None`. Test fixtures asserting `result == {}` on fail-closed FULL must be updated to `result is None`; this release updates the in-repo Python tests accordingly.
- **Routed scenarios** (internal review verification batch 1): `async_sync_behavior` (confirmed P0) — resolved. `python_node_parity` divergence #1 (FULL-mode gate timing) — resolved. Remaining parity divergences (AUTO degrade / mode TTL) are tracked separately; `isAsyncFn` `.bind()` mis-classification was refuted by ES §10.4.1.3 (BoundFunctionCreate preserves `AsyncFunction`).

### Changed — README: `FULL mode — gateway trust-boundary guarantees` subsection (CSR 4/4 claim-scoping)

- `README.md`: added a `### FULL mode — gateway trust-boundary guarantees` subsection. It states, in **scoped** wording verified against aegis-core code, the four guarantees the gateway `/check-access` ingress provides after the Core Security Remediation track (CSR 4/4, landed in aegis-core 2026-05-21): identity binding to the auth-middleware identity, ingress denial of unknown purpose / scope / malformed capsule, audit-or-deny (HTTP 503) fail-closed, and `AEGIS_PROFILE=production` boot-time config validation. The subsection also states explicitly what is **not** guaranteed (no gateway-wide audit fail-closed, no purpose × scope field-level minimum-disclosure, not production-ready out of the box, no all-gateway-operations audit-complete claim) and records four tracked follow-ups.

## [0.9.0-rc5] — 2026-05-21 — wheel-packaging fix for legacy `aegis` shim (release-integrity follow-up)

Tier 0 follow-up to the rc3 release-integrity remediation. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API surface is identical to rc4; this release fixes wheel packaging so the documented back-compat shim is actually shipped.

### Fixed — `from aegis import shield` legacy shim now packaged

- `pyproject.toml` `[tool.hatch.build.targets.wheel] packages` updated from `["src/aegis_trust"]` to `["src/aegis_trust", "src/aegis"]`. The rc2 CHANGELOG entry promised the `aegis` back-compat shim would remain until v2.0.0, but the wheel target only included `src/aegis_trust`. `pip install aegis-trust==0.9.0rc4` therefore did not provide `import aegis` compatibility, contradicting the documented migration path.
- Verified post-publish on the live PyPI artifact: wheel contains both `aegis_trust/__init__.py` (canonical) and `aegis/__init__.py` (shim, emits `DeprecationWarning`). `pip install aegis-trust==0.9.0rc5 && python -c "from aegis import shield"` works as documented.

### Release-integrity gate (post-rc3 incident)

The live PyPI `aegis-trust==0.9.0rc5` artifact was originally published from `aegis-shield` (commit `0419f2a`, 2026-05-18; the `e06ac9df` reference recorded at rc5 ship time was a squash-artifact hash that does not resolve in the canonical `aegis-shield` history; `0419f2a` is the actual rc5 source commit, carrying the wheel-packaging fix for the legacy `aegis` shim) via the **Published Artifact Parity Gate** (5-stage: local build → record artifact hash → publish to PyPI → download from registry → verify local hash == registry hash → clean venv install → canonical import + legacy shim import + `AEGIS_BASE_URL` alias all PASS).

> **Hard rule going forward**: No release claim unless source, build config, registry artifact, clean install, and documented compatibility behavior all match.

### Changed

- `VERSION` 0.9.0-rc4 → 0.9.0-rc5
- `pyproject.toml` version bump
- `src/aegis_trust/__init__.py` `__version__` bump

### Refs

- Release-integrity incident (published rc3 source ≠ canonical repo source)
- Wheel-packaging shim drift (rc4 wheel missed `src/aegis`, fixed in rc5)
- Paired with npm `aegis-trust@0.9.0-rc5` (cross-SDK version-lock; npm rc5 is content-identical to rc4 because the wheel-shim issue is Python-specific)
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0) — closed the source ↔ registry drift that surfaced when `aegis-trust@0.9.0rc5` was published to PyPI from `aegis-shield` without committing back to this monorepo.

## [0.9.0-rc4] — 2026-05-21 — pre-GA preview (cross-SDK env-var canonicalisation + AUTO probe-first)

post-canonical-audit cross-SDK parity closure. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API surface is additive over v0.9.0-rc3 with one **breaking-for-direct-callers** semantic change on an exported helper (see Migration below). Paired with npm `aegis-trust@0.9.0-rc4`.

### Added — `AEGIS_URL` canonical, `AEGIS_BASE_URL` npm-parity deprecation alias

- `_resolve_base_url()` in `src/aegis_trust/shield.py` resolves the gateway base URL via a documented precedence order: `AEGIS_URL` (canonical, parity with npm `aegis-trust` `client.ts:resolveBaseUrl`) → `AEGIS_BASE_URL` (npm-parity deprecation alias) → default (`https://localhost:8443/api/v1`).
- The npm SDK historically read `AEGIS_BASE_URL`; from v0.9.0-rc3 onward, both SDKs accept both env vars, with `AEGIS_URL` as the canonical name. `AEGIS_BASE_URL` continues to work but emits a one-shot `logger.warning` per process the first time it is read. The warning is re-armed by `reset()` so test fixtures see one warning per logical reset. **`AEGIS_BASE_URL` will be removed in v1.0.0** per [`docs/VERSIONING.md`](docs/VERSIONING.md) deprecation policy.
- `_user_intends_full()` extended to inspect `AEGIS_URL` / `AEGIS_BASE_URL` (alongside `AEGIS_TOKEN`) when deciding whether the user expects Full mode. Local hosts (`localhost` / `127.0.0.1` / `::1` / `*.local`) are treated as dev regardless of port so dev fixtures keep working.

### Added — Mode detection TTL cache (parity with npm `_DETECT_MODE_TTL_MS = 60_000`)

- The existing `_DETECT_MODE_TTL_S = 60.0` constant in `shield.py` is now mirrored on the npm side so both SDKs re-probe the backend every 60 s under `AEGIS_MODE=auto`. Without this TTL, a stuck `lite` detection survives gateway recovery, and a stuck fail-closed `full` keeps warning even after the backend is healthy.

### Changed — AUTO probe-first behaviour matrix

`_detect_mode()` continues to probe the backend FIRST and consults `_user_intends_full()` only when the probe fails. The full behaviour matrix (now also enforced on the npm side):

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no token AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full.
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `logger.warning`. Previously silently fell back to Lite, which would skip the user-visible warning and provide weaker semantics than the user asked for.

### Added — `[tool.mypy]` strict configuration with documented exemptions

- `pyproject.toml` `[tool.mypy]` block: `files = ["src/aegis_trust"]`, `ignore_missing_imports = true`, and `disable_error_code = ["arg-type", "no-any-return", "no-untyped-def", "attr-defined"]` for pre-existing type-narrowing tech debt in `shield.py` / `config.py` / `history.py`. Documented exemption (no silent bypass; explicit + audit-visible). Tightening is queued for a dedicated sprint.
- Productization gate `type_safety` verifier compatible.

### Changed — `reset()` re-arms deprecation-warning state

- `reset()` now also resets `_base_url_alias_warned` so test fixtures can verify the deprecation-warning contract repeatedly (one warning per logical reset). Mirrors npm `resetModuleClient()`.

### Migration — `_user_intends_full()` breaking-for-direct-callers (semantic)

- **Pre-rc4**: `_user_intends_full()` returned `True` for `AEGIS_MODE=full` alone (no token / URL required).
- **rc4+**: `_user_intends_full()` requires `AEGIS_TOKEN` OR a non-dev URL (via `AEGIS_URL` or `AEGIS_BASE_URL`). `AEGIS_MODE=full` is handled separately in `_detect_mode()` and is no longer a sole intent signal for direct callers.
- **Who is affected**: callers that invoke `_user_intends_full()` directly from `aegis_trust.shield` (or its re-exports) and rely on `AEGIS_MODE=full` returning `True` from it.
- **Migration recipe**: set `AEGIS_TOKEN` or a non-dev `AEGIS_URL` alongside `AEGIS_MODE=full`. Callers that use only `_detect_mode()` (the primary entry point) are unaffected — `AEGIS_MODE=full` continues to produce Full mode via the matrix above.

### Refs

- Paired with npm `aegis-trust@0.9.0-rc4` env-var canonicalisation + AUTO probe-first.
- Mirrors npm `client.ts` `resolveBaseUrl`, `userIntendsFull` extension, and `detectMode` probe-first ordering.
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0).

## [0.9.0-rc2] — 2026-05-18 — Python module rename `aegis` → `aegis_trust`

Phase A. **Breaking-but-shimmed**: the Python module
was renamed from `aegis` to `aegis_trust` to match the PyPI package name. Existing
`from aegis import shield` continues to work via a `DeprecationWarning`-emitting
back-compat shim slated for removal in **v2.0.0**.

### Changed — module rename
- `src/aegis/` → `src/aegis_trust/` (literal directory rename, git history preserved).
- `from aegis_trust import shield` is now the canonical import path.
- `from aegis_trust.client import AegisClient`, `from aegis_trust.types import ...`,
  `from aegis_trust.shield import ...` etc. are the canonical submodule paths.
- `pyproject.toml`: `[project.scripts]` `aegis = "aegis_trust.cli:cli_entry"`;
  `[project.entry-points."pytest11"]` `aegis = "aegis_trust.pytest_plugin"`;
  `[tool.hatch.build.targets.wheel]` `packages = ["src/aegis_trust"]`.

### Deprecated — `import aegis`
- `import aegis` / `from aegis import shield` emits `DeprecationWarning` and
  re-exports the public surface from `aegis_trust`. **Removal: v2.0.0**.
- Migration is a single sed: `sed -i 's/from aegis import/from aegis_trust import/g'`.
  Submodule paths: `aegis.X` → `aegis_trust.X`.

### Added — Aegis-Api-Version dated header registry
- Dated
  API version registry (`Aegis-Api-Version: 2026-05-18` initial), sunset policy
  (18-month notice + 6-month deprecation), stability levels, breaking-change
  classification, migration tooling requirements. SDK header install lands in
  v1.0.0 GA (sprint_003 Phase C).

## [0.9.0-rc1] — 2026-05-18 — pre-GA preview

Build phase Python port. **Preview release**
(`STABILITY_LEVEL = "preview"`). Mirrors `@aegis_trust/sdk@0.9.0-rc1` (npm,
TypeScript port). Public API is additive over v0.8.1; no breaking changes.

### Added — machine-parseable error model (`aegis.errors`)

- `AegisError` base + `AegisValidationError` / `AegisConfigError` /
  `AegisIngestError` / `AegisAuditError` / `AegisHttpError`. Every error
  carries `code` + `remediation` + `docs_url`. All except `AegisHttpError`
  also extend `ValueError` for backward-compat with existing
  `except ValueError` callers.
- `aegis_docs_url(code)` helper.

### Added — trace context propagation (`aegis.trace`)

- `trace_context(trace_id, parent_id=None)` context manager — sets
  ambient `contextvars.ContextVar` for the duration. Asyncio-safe,
  thread-safe.
- `with_trace_context(trace_id, fn, *args, **kwargs)` function-call wrapper.
- `get_trace_context() -> TraceContext | None`.
- `new_trace_id()` — 32-char hex via `secrets.token_hex(16)`.
- traceId regex validation: `^[A-Za-z0-9._:-]{1,128}$` — prevents Bearer
  tokens / secrets being persisted into audit JSONL.

### Added — idempotent local audit (`aegis.history`)

- `HistoryStore.record_idempotent(args, idempotency_key)` — Stripe
  Idempotency-Key model translated to the SQLite store. Cross-run dedup
  via SQL key lookup. Divergent-payload retries with the same key raise
  `AegisAuditError` (`aegis.audit.idempotencyKey.payloadDivergence`).
- SQLite migration: add `trace_id` + `idempotency_key` columns to
  existing v0.8.x databases (idempotent `ALTER TABLE ADD COLUMN`).
- `record()` now accepts optional `trace_id` kwarg.

### Added — versioning doctrine exports

- `AUDIT_SCHEMA_VERSION = 1` — on-disk / on-wire audit event shape version.
- `STABILITY_LEVEL = "preview"` — see npm SDK `docs/VERSIONING.md`.
- `__version__` bumped 0.8.1 → 0.9.0-rc1.

### Test

- 429/430 pytest pass (1 unrelated ci-matrix.sh test, pre-existing infra issue).
- New surface verified via smoke test (trace_context + record_idempotent +
  payload-divergence detection).

### Refs

- npm SDK design decisions + sprint_002 carry-over
- Session 3 scope per kickoff handoff (PyPI port deferred from npm publish day)
- aegis-trust feature parity: npm `@aegis_trust/sdk@0.9.0-rc1` (2026-05-18 JST)

## [0.8.1] — 2026-04-17

Sprint S024 "Beta attestation + live Full-mode end-to-end proof" — closes S023's
"electricity never confirmed" gap. v0.8.0 shipped the Full-mode
wiring but the Tier β workflow had never seen a live green run;
`docker compose up --build` hung on a 40-50 minute Rust rebuild
twice and was cancelled by hand. v0.8.1 rewires the β substrate so
`scripts/aegis-core-dev.sh up` reuses the cached image via a
content-addressed SHA tag, produces a tamper-evident attestation
for every run, fixes a file-descriptor leak in `AegisClient.set_token`,
and records the project's first live all-green Tier β pass
(52 passed / 3 skipped / 0 failed against
`aegis-core-dev@sha256:4dad2fb0…`).

### Fixed

- `AegisClient.set_token()` no longer leaks sockets on JWT rotation.
  The prior implementation dropped both `httpx.Client` and
  `httpx.AsyncClient` references without releasing their connection
  pools. `set_token` now closes the sync client inline and, when
  called from a running event loop, schedules
  `old_async.aclose()` as a task whose reference is held in
  `self._pending_aclose_tasks` until `add_done_callback` clears it
  (bpo-44665 weakref GC). Outside a loop a `ResourceWarning` now
  fires so operators see the leak vector instead of discovering it
  via growing FD counts in production.
- `scripts/pre-push` now invokes `.venv/bin/{ruff,pytest,pip-audit}`
  directly so developers whose shells have not activated the venv
  stop falling through to system tooling (or silently skipping the
  gate). `pip-audit>=2.7` is now part of the `[dev]` extra so the
  gate is reachable from a clean `pip install -e ".[dev]"`.
- `scripts/install-hooks.sh` is idempotent and warns when the
  installed hook drifts from the canonical copy, so re-install is
  safe at any time.
- `tests/test_shield_full.py` scope-filter tests now skip with
  `requires_authed_check_access` instead of spuriously failing on
  the live gateway's (correct) `401` response. The counterpart
  `test_full_mode_unauthed_returns_empty` pins the AO-003
  fail-closed path those tests used to imply.

### Added — β CI substrate

- `scripts/aegis-core-dev.sh` (T-158/T-175):
  - `docker image inspect aegis-core-dev:<sha>` cache hit path —
    rebuilds the Rust gateway image only when the aegis-core source
    SHA has changed, eliminating the ~40-min scratch build on every
    CI run. Warm cache healthcheck clears in <10 s.
  - `sha` / `image` subcommands emit the aegis-core source SHA and
    the image's sha256 digest for attestation.
  - `AEGIS_CORE_DIR` origin remote is checked against an anchored
    allowlist of canonical remote URLs, configured out of band via
    `AEGIS_CORE_REMOTE_ALLOWLIST`. STRIDE spoofing mitigation against
    an attacker-controlled checkout sharing the directory name.
- `scripts/aegis-core.compose.yml` (T-159) is now runtime-only —
  build logic lives in the CLI wrapper — and carries the full dev
  env map (`AEGIS_GATEWAY_AUDIT_PATH`, `AEGIS_CAPSULE_ROOT`,
  `AEGIS_WORKSPACE_ROOT`, `AEGIS_CONFIG_PATH`, `AEGIS_TLS_*`,
  `AEGIS_MTLS_REQUIRED=false`, `AEGIS_SWAGGER_AUTH=false`,
  `AEGIS_METRICS_AUTH=false`, `AEGIS_IP_ALLOWLIST` widened for
  Docker Desktop bridges, `AEGIS_SOCKET_PATH`,
  `AEGIS_RATE_LIMIT_PER_MIN=6000`). A bind-mounted
  `scripts/aegis-core-dev-config/` supplies the minimum
  `purpose_map.yaml` / `policy.yaml` / `rbac.yaml` the gateway
  requires but the production image's `aegis-gateway init` does not
  yet emit.
- `scripts/aegis-attest.sh` (T-171) writes a schema_version=1 JSON
  attestation containing the aegis-shield commit, aegis-core commit
  and remote, the image's SHA-pinned digest, fixture hashes for the
  compose spec, CLI wrapper and workflow, and best-effort cosign +
  syft slots when those tools are installed. JSON is rendered
  through `python3 json.dumps` so shell-unsafe characters in cosign
  failure text cannot corrupt the record.
- `.github/workflows/tier-beta.yml` (T-160) rewired for the
  SHA-tagged cache: cache hit/miss recorded as a workflow output,
  startup poll synced to the compose 60 s healthcheck, 45-minute
  cold-path ceiling, `push: sprint/**` trigger restored, and every
  run emits the attestation JSON as a 90-day retained artifact.

### Documented

- `docs/S024_first_beta_green.md` — first live Tier β green report
  (52 passed / 3 skipped / 0 failed, image digest
  `sha256:4dad2fb0…`, aegis-core source `eb353fec55c4`), plus the
  warm×2 + cold×1 + nightly×3 push-trigger acceptance matrix that
  replaces the original self-referential gate.
- `attestations/tier-beta-first-green-2026-04-17.json` — machine-
  readable companion of the above.

### Deferred to S025 (documented handoff)

- `make generate-sdk` against the live OpenAPI (46 paths, 38
  schemas) — deferred because regenerating `src/aegis/_generated/`
  has a high chance of reshaping symbols that every Lite test
  imports. The live spec has been pulled to `/tmp/live_openapi.json`
  so S025 can diff it cleanly against the checked-in stub.
- `tests/integration/` load harness (100-concurrent-req observation
  of `_detect_mode` thundering herd, `_access_cache` TTL race, and
  async FD growth) — the FD-leak fix from T-172 already removes the
  highest-impact known issue. S025 builds the observation suite
  on top of that and bakes load thresholds into CI.
- GHCR publication + cosign keyless signing — S024 closed the
  non-repudiation gap with a content-addressed local digest; GHCR
  and signing raise the evidence bar further once aegis-core
  itself publishes images.
- `_detect_mode` TTL re-probe lock, `_access_cache` LRU bound, and
  the sync/async 4-way de-duplication refactor — all structural
  follow-ups deferred in S023 whose non-structural halves are
  addressed here.

## [0.8.0] — 2026-04-14

Sprint S023 "Full-mode live wiring" — first end-to-end Full mode integration
sprint. v0.7.x shipped Full mode code paths (`@shield` Full,
`AegisClient.ingest`, audit POST, `_diff_keys`) but they had never been
exercised against a live aegis-core. v0.8.0 closes that gap on the
gateway-uniqueness, fail-secure, and non-repudiation axes called for
by the AO philosophy and the US military fail-secure /
defense-in-depth standards.

### Added — Full mode hardening

- `_resolve_verify_ssl()` (AO-001 + AO-005 fail-secure prod-lock):
  `AEGIS_VERIFY_SSL=false` is now silently overridden to `True` on any
  non-dev host. Local dev (`localhost` / `127.0.0.1` / `::1` / `*.local`)
  requires both `AEGIS_VERIFY_SSL=false` AND a new explicit
  `AEGIS_DEV_INSECURE=1` opt-in.
- `AegisClient.aingest` / `aauthorize` / `acheck_access` /
  `averify_audit_chain` / `averify_inclusion` / `ais_available` /
  `aclose` (async path uses `httpx.AsyncClient` end-to-end so
  `@shield`-decorated coroutines never block the event loop on backend
  I/O).
- `AegisClient.authorize` / `aauthorize` (AO-003 enforcement): every
  Full mode call now hits `/check-access` before filtering. Allow
  decisions cache for 30s keyed by `(token_epoch, purpose, sorted scope)`;
  deny is never cached. Fail-OPEN is closed: the 200 body must contain
  `{"allowed": true}`.
- `AegisClient.set_token` / `aegis.shield.refresh_token` (AO-001 +
  AO-004): rotates the bearer token, bumps `_token_epoch` so any
  in-flight `authorize()` cannot poison the new principal's cache,
  discards cached httpx clients, best-effort zeroizes a `bytearray`
  token in place.
- `AegisClient.verify_audit_chain` / `verify_inclusion` (AO-004
  per-call non-repudiation): SDK retains the highest seq returned by
  every ingest and exposes a helper that proves *this* call's record
  landed in a valid intact chain — `/audit/verify` alone only proved
  chain health.
- `AegisClient._parse_ingest_body` / `_parse_chain_body` (AO-002
  malformed-200 fail-secure): a 200 with a body that diverges from the
  OpenAPI contract is now classified as a transport error and
  fail-closed.
- `aegis.client.set_metrics_hook` (AO-006 — replaces a proposed direct
  `prometheus_client` dependency): single pluggable callback
  `(endpoint, duration_s, status) -> None` invoked after every backend
  request. Hook exceptions are swallowed; instrumentation never breaks
  the data path.
- Mode detection TTL (60s) + degrade-event log (`shield: mode changed
  X → Y`): `AEGIS_MODE=auto` re-probes the backend within an SLO
  window; any mode flip emits an explicit AO-006 event so audit
  readers can distinguish "always-Lite" from "Full degraded
  mid-process".
- `_user_intends_full()` heuristic + Full + fail-closed on unreachable
  backend: under `AEGIS_MODE=auto`, an explicit `AEGIS_TOKEN` or
  non-dev `AEGIS_URL` keeps the SDK in Full mode and denies all calls
  until the gateway recovers — Gateway-uniqueness (AO-001) outranks
  availability.
- `_collect_removed` cycle guard (Mythos M5): attacker-shaped circular
  structures (`d["self"] = d`) no longer trigger RecursionError or
  hang. The guard is path-local so legitimate aliasing
  (`{"x": shared, "y": shared}`) is still diffed correctly.
- `aegis.client._clear_sensitive` + new SECURITY.md "Memory posture"
  section (AO-005): documents the SDK best-effort / gateway-authoritative
  split for in-memory secret zeroize on CPython.

### Added — Operational

- `scripts/aegis-core.compose.yml` + `scripts/aegis-core-dev.sh` for
  local Tier β provisioning. `AEGIS_CORE_DIR` is required and produces
  a clean error message when missing — no brittle absolute paths.
- `.github/workflows/tier-beta.yml` runs the Full mode integration
  suite against a live aegis-core container on `workflow_dispatch`,
  `push` to `sprint/**`, and a nightly cron.
- `tests/test_contract_gate.py` static-parses every httpx path literal
  in `client.py` and asserts each exists in `openapi.json`. CI fails
  when the SDK calls a route the OpenAPI spec does not declare.

### Changed

- `openapi.json`: backported `/shield/ingest`, `/shield/policy-sync`,
  `/shield/stats`, `/shield/report` paths from aegis-core's `utoipa`
  source so the contract gate passes. Full schemas regenerate next
  time `make generate-sdk` runs against a live aegis-core.

### Backward compatibility notes

- `AEGIS_VERIFY_SSL=false` alone is now a no-op outside dev hosts,
  and a no-op even on dev hosts unless `AEGIS_DEV_INSECURE=1` is also
  set. v0.7.x callers relying on `AEGIS_VERIFY_SSL=false` against a
  local aegis-core must export `AEGIS_DEV_INSECURE=1` as well.
  Lite-mode users see no behavior change.
- Full mode now performs `/check-access` before every
  `/shield/ingest`. Cached for 30s per `(token, purpose, scope)`; the
  first call after rotation (or a new combination) pays a second RTT.
  Wire `set_metrics_hook()` to surface the impact in your own
  observability stack.

### Deferred to S024 (handoff)

- sync/async pair de-duplication
  (`authorize`/`aauthorize`, `ingest`/`aingest`,
  `_shield_full`/`_shield_full_async`, deny pair) — large refactor,
  deliberately deferred to keep the v0.8.0 behavior diff small and
  reviewable.
- `tests/conftest.py` extraction of duplicated fixtures.
- `_access_cache` bounded eviction (LRU + maxsize).
- `_detect_mode` TTL re-probe lock for concurrent first-call thundering
  herd.
- `set_token` async client `aclose` scheduling on the running loop.

## [0.7.1] — 2026-04-14

Security hardening from the first formal adversarial sprint against the
v0.7.0 new surface. No new public API; three security fixes + one
defense-in-depth fix promoted this to a patch release per the Sprint
S022 "any shipped security fix => patch release" policy.

### Security

- **A1/R8 — `__slots__` fail-closed**: classes using `__slots__` (no
  `__dict__`) are now treated as record-like, so `list[SlottedUser]`
  under a leaf scope drops fail-closed instead of leaking named
  attributes.
- **A2-A5 + A11 / R1 + R4 — `_is_traversable` helper**: `_filter_dict`
  leaf-drop, `_deny_filter_dict` recursion, and `_collect_removed` audit
  diff now cover the full non-str / non-bytes / non-`Mapping` iterable
  surface (`list`, `tuple`, `set`, `frozenset`, `deque`, `memoryview`,
  `range`, `array.array`, generators, custom `__iter__`). Pre-S022 they
  hardcoded `(list, tuple)` and let `collections.deque` / `set` /
  generator envelopes silently pass record-like payloads.
- **A6+A7+A12 / R2 — symmetric deny scalar drop**: `_deny_filter_dict`
  now drops the key fail-closed when the subtree expects descent but
  the value is a scalar — matching `_filter_dict`'s behavior. Pre-S022
  it kept the scalar, letting `deny_fields=["users.ssn"]` silently pass
  through a scalar `users` value.
- **A3 / R3 — narrowed SQLAlchemy probe**: `_is_sqla_declarative_like`
  now requires SQLAlchemy to be importable and the instance to be a
  `DeclarativeBase` subclass (or `__table__` to be a real
  `sqlalchemy.Table`). Pre-S022 duck-typing (`hasattr(__table__,
  "columns")`) accepted attacker-forged metadata — a confused-deputy
  surface.
- **A4+A9 / R9 — Pydantic v2 return-type gate**: `_to_filterable` now
  requires `model_dump()` to return a `dict`, symmetric with the v1
  path. Non-`dict` returns fail-closed.
- **A10 / R10 — NamedTuple normalization**: `typing.NamedTuple` and
  `collections.namedtuple` instances are now detected by
  `_is_record_like` and normalized via `_asdict()` in `_to_filterable`.

### Backward compatibility notes

- **Deny-mode scalar contract change**: callers relying on
  `deny_fields=["a.b"]` to keep a scalar `a` value unchanged must
  either add the scalar to an allowed path or redesign the caller to
  return a consistent shape. The pre-S022 behavior was asymmetric with
  scope and was producing silent leaks.
- **SQLAlchemy probe narrowing**: callers using duck-typed
  `__table__.columns` without installing SQLAlchemy will now fall
  through to the `__dict__` / fail-closed path. Install SQLAlchemy or
  switch to `@dataclass` / Pydantic if `_to_filterable` normalization
  is needed.
- **Pydantic v2**: any custom `model_dump()` that returns a non-`dict`
  (list / str / None / ...) will now fail-closed. Return a `dict` (the
  canonical contract) or bypass `@shield` for that path.

## [0.7.0] — 2026-04-14

Minor release. `@shield` now auto-normalizes common Python return shapes
(`@dataclass`, Pydantic v1/v2, SQLAlchemy Declarative) before filtering,
removing the boilerplate of converting objects to `dict` inside every
wrapped function. Detection is duck-typed — neither Pydantic nor
SQLAlchemy is added as a dependency.

Pre-1.0 (0.6.x → 0.7.0) bump. No breaking change for `dict` / `list` /
`None` callers. Callers who previously returned a Pydantic model or a
dataclass from a `@shield`-wrapped function were hitting the non-dict
fail-closed path and receiving `""`. That case now returns a filtered
`dict`.

### Added

- **`_to_filterable()` helper** runs at the top of `_filter_result` and
  `_deny_filter_result`. Detection order (hottest first):
  1. `dict` / `list` / `None` — pass-through.
  2. Pydantic v2 — `.model_dump()`.
  3. SQLAlchemy Declarative — iterates `__table__.columns`. Checked
     before Pydantic v1 because some ORM mixins also define `.dict`;
     `__table__.columns` is the more specific signature.
  4. Pydantic v1 — `.dict()` (only accepted when the call returns a
     `dict`).
  5. `@dataclass` — `dataclasses.asdict`.
  6. Unknown — returned unchanged; the existing non-dict fail-closed
     path fires.
- **SQLModel-like hybrid support**: objects with both `.model_dump` and
  `__table__.columns` resolve via the Pydantic v2 branch, so custom
  serializers (aliases, computed fields, validators) are preserved.
- **Top-level `list[<model>]` support**: returning `[Customer(), ...]`
  from a `@shield`-wrapped function (where `Customer` is a dataclass or
  Pydantic model) works via recursion — each element is normalized
  individually.
- **13 new tests** in `tests/test_orm_pydantic.py`: dict / list-of-dict
  regression, `@dataclass` (scope + deny), Pydantic v2 flat + nested,
  Pydantic v1 flat (optional via `skipif`), SQLAlchemy-shape duck
  typing, top-level `list[@dataclass]`, top-level `list[BaseModel]`,
  SQLModel hybrid branch-order, unknown opaque fail-closed, conversion
  exception fail-closed.
- **README "Supported return types"** table documents the full matrix,
  including the optional-dependency posture and the hybrid fallthrough.

### Fail-closed

- Conversion exceptions (`model_dump` / `asdict` / `__table__`
  traversal) return `""`, which the existing non-dict path converts to
  an empty result. Callers never see partial or exception-tainted data.

## [0.6.5.6] — 2026-04-14 — *superseded by 0.7.0*

> **This version was not published to PyPI.** Sprint S021 consolidated the
> 0.6.5.6 hotfix work with the 0.7.0 ORM/Pydantic/dataclass support in a
> single squash-merge, so only `0.7.0` exists as a PyPI release. Everything
> below is contained in `0.7.0` (plus the Plan-Review follow-ups:
> `collections.abc.Mapping`-aware drop, `_diff_keys` audit-trail fix, and
> public docstring refresh). Keep the entry for historical trace; upgrade
> path is `pip install -U aegis-trust` (resolves to 0.7.0 or later).

Hotfix release. Closes a silent-pass leak path in `scope` filtering over
list-of-dict return values, and removes five user-visible instances of a
"contact <email>…" verb/name duplication introduced during the 0.6.5.5
hotfix sweep. Also adds a lint guard so the duplication cannot recur.

Releases 0.6.5.3 and 0.6.5.4 carry obsolete contact addresses on a
domain that was never set up. They are **yanked on PyPI** with the
reason *"obsolete contact metadata; use 0.6.5.5+"*. Yank is
non-destructive: existing installs keep working, and pinned installs
(`aegis-trust==0.6.5.3`) still resolve. Default `pip install
aegis-trust` will resolve to 0.6.5.6 or later.

### Fixed

- **Silent-pass leak on `scope=["key"]` over a list of dicts** (minimum
  disclosure, fail-closed). A bare leaf whitelist over a list containing
  dict elements now drops the key and emits an `aegis` logger WARNING
  pointing at the `key.<field>` dot-notation fix. Data behavior is
  breaking for callers that relied on the previous pass-through, and the
  change is intentional — the previous behavior released inner fields the
  caller never whitelisted. Detection uses `any(isinstance(x, dict) for x
  in v)` so heterogeneous lists (`[1, {"ssn": "x"}]`) are caught too.
- **`deny_fields` symmetry**: `_deny_filter_dict`'s docstring now states
  the contract explicitly. `deny_fields=["users"]` drops the whole key;
  `deny_fields=["users.ssn"]` removes the `ssn` field from each list
  element; bare `deny_fields=["ssn"]` matches the top-level key only and
  does not recurse into child collections. No code change — the prior
  behavior already satisfies the contract; the docstring closes the
  ambiguity.
- **"contact <email>" duplication removed** from five user-visible
  locations: `shield.py` module docstring, the backend policy synchronization helper docstring,
  the backend policy synchronization helper `RuntimeError` message, `README.md` "Beyond local
  filtering" section, `SECURITY.md` attestation note, `llms.txt` optional
  extras. Verb changed from `contact` to `email` wherever the following
  token is the email address itself.

### Added

- **README "Filtering inside lists"** section documents the new drop
  semantics with copy-pasteable examples (dot-notation fix, bare-leaf
  drop, empty-list and list-of-primitive pass-through, deny-side
  symmetry).
- **Lint regression guard** (`scripts/check_trojan_compliance.py`): the
  pattern `contact\s+`?contact@` is banned in both public files and
  source-side user-visible strings. The verb/name duplication cannot
  recur silently — reintroduction fails the lint with a specific
  violation line.

### Migration

If any call site relied on `scope=["key"]` returning a list of unfiltered
dicts, change it to `scope=["key.<field>"]` with the fields the agent is
actually allowed to see. The new behavior is strictly safer: the previous
form silently released every inner field regardless of the declared
scope.

If you pinned `aegis-trust==0.6.5.3` or `==0.6.5.4`, upgrade explicitly —
those versions' contact addresses bounced.

## [0.6.5.5] — 2026-04-13

Hotfix release. Corrects a non-trivial documentation bug: releases 0.6.5.3
and 0.6.5.4 listed contact addresses on a placeholder domain that was
never actually owned or set up for mail. Messages sent to those
addresses would bounce. This release replaces every user-visible contact
channel with `contact@aegisagentcontrol.com` — the single real, owned
address — and locks the new value in the lint gate so the regression
cannot recur.

### Fixed
- **Contact address corrected everywhere**: `pyproject.toml` author email,
  README, AGENTS.md, SECURITY.md, llms.txt, NOTICE, the backend policy
  synchronization helper RuntimeError message, and every historical
  CHANGELOG reference now point at `contact@aegisagentcontrol.com`. The
  previous placeholder domain had no mail server and never did.

### Added
- **`scripts/check_trojan_compliance.py`** allowlist tightened to the
  single approved address (`contact@aegisagentcontrol.com`), and the ban
  list extended with the obsolete placeholder domain so any future
  reappearance fails the Trojan Horse lint.

### Migration
- If you saved a contact address from 0.6.5.3 or 0.6.5.4, replace it
  with `contact@aegisagentcontrol.com`. Previous versions' mails were
  not reaching anyone.

## [0.6.5.4] — 2026-04-13

Hotfix release. Closes the four agent-facing Trojan Horse leaks discovered in
the post-ship `pip install aegis-trust==0.6.5.3` review of `help()` / `dir()`.
Pure documentation, signature, and namespace cleanup. No runtime behavior change.

### Changed
- **`@shield(...)` `mode` default**: the displayed default is now the string
  `"auto"` instead of the internal enum repr form. Behavior is identical
  (the function accepts both forms), but `help(shield)` no longer surfaces
  the internal enum name.
- **`@shield(...)` docstring**: removed internal compliance code
  references. The user-facing principles ("data flow must be explicit",
  "minimum disclosure required", "fail-closed") remain unchanged.
- **`AegisClient.__init__` `base_url`** now defaults to `None` and the actual
  default URL is resolved from the module-level `_DEFAULT_BASE_URL` constant.
  `help(AegisClient)` no longer surfaces the development localhost URL in the
  signature. Behavior is identical: `base_url=None` resolves to the same value.
- **`from aegis import *`** now exports only `shield`. Direct submodule
  imports (for example `from aegis.types import Mode`, or
  `from aegis.types import IngestEntry`) continue to work. `dir(aegis)`
  shrinks from 19 names to 4.
- **Logger messages and `_validate_field_path` warnings**: stripped
  internal compliance codes from the user-visible
  `logger.{warning,error}(...)` strings. Only the human-readable principle
  text is kept ("fail-closed", "minimum disclosure", etc.).

### Added
- **`scripts/check_trojan_compliance.py` source-side scope refined**: now
  walks public top-level functions, public classes (and all their methods),
  the module docstring, and every `logger.<level>(...)` string literal.
  Private function docstrings (`_filter_dict`, `_deny_filter_dict`, etc.)
  remain free to use internal terminology for engineers reading the source.
  internal compliance codes are now banned in the same scope as other
  internal nomenclature (Full mode, legacy `aegis-shield`, etc.).

### Migration
- `from aegis import *` consumers that previously expected `Mode`,
  `AegisClient`, `IngestEntry`, etc. to be re-exported should switch to
  named imports: `from aegis.types import Mode`, `from aegis.client import
  AegisClient`. Direct named imports were never broken.

## [0.6.5.3] — 2026-04-13

### Changed
- **Documentation revamp for world release (Sprint S020 Docs).** README rewritten
  for a 30-second value scan, copy-pasteable `python -c` quickstart, and six inline
  use cases (Quickstart, FastAPI, FastMCP, `aegis.yaml`, async, `deny_fields`). All
  example imports use `from fastmcp import FastMCP` consistently across README and
  AGENTS.md.
- **PyPI metadata polished.** `keywords` extended with `mcp`, `scope`, `trust`,
  `purpose`, `field-level`, `decorator`, `minimum-disclosure`. `Development Status`
  bumped to Beta. `Framework :: Pytest` classifier added. `authors.email` now
  routes to `contact@aegisagentcontrol.com`.
- **`llms.txt` rewritten** for AI-agent discoverability and packaged inside the
  wheel (`aegis/llms.txt`) via `hatch force-include`. AGENTS.md and SECURITY.md
  rewritten for the `aegis-trust` brand and the approved
  `sales@/security@/contact@aegisagentcontrol.com` contact channels.

### Added
- **Four enforcement scripts** under `scripts/` make the S020 Agent-Friendly
  checklist runnable instead of subjective:
  - `check_public_api_docstrings.py` — every public API has a docstring (E-1).
  - `check_error_messages.py` — every `ValueError`/`RuntimeError` is actionable
    and free of internal product names (I-2).
  - `check_trojan_compliance.py` — public files plus `src/` docstrings and
    `logger.*` strings are scanned for legacy or internal-only terms.
  - `test_5min_quickstart.sh` — clean-venv `pip install` plus `python -c`
    quickstart asserted to complete inside 300 seconds (I-3, I-4). Local run
    measures roughly three seconds.

### Fixed
- **Public-surface Trojan leaks.** `client.py`, `shield.py`, and the @shield
  decorator's docstring no longer enumerate internal mode names or refer to the
  enterprise backend by its internal codename. Runtime log lines were rephrased
  in the same way. The the backend policy synchronization helper `RuntimeError` now points users at local
  filtering or `contact@aegisagentcontrol.com`, with no internal name in the message.

### Migration
- No code changes required from `aegis-trust 0.6.5.2`. This release is
  documentation, metadata, and lint-gate only.

## [0.6.5.2] — 2026-04-13

### Changed
- **Package renamed: `aegis-shield` → `aegis-trust`**. The PyPI distribution name was changed to `aegis-trust` because `aegis-shield` was already registered on PyPI by an unrelated party. The new name also better reflects the category positioning: `aegis-trust` is the trust layer for AI agents.
  - `pip install aegis-trust` (was: `pip install aegis-shield`)
  - Import path **unchanged**: `from aegis import shield` continues to work identically.
  - All internal module names (`aegis.shield`, `aegis.client`, `aegis.config`, etc.) remain the same.
  - No code changes in `src/aegis/`. Package is functionally identical to 0.6.5.1.

### Migration
- For TestPyPI users of `aegis-shield==0.6.5.1`: uninstall and reinstall as `aegis-trust==0.6.5.2`. No application-source changes needed.

## [0.6.5.1] — 2026-04-13

### Changed
- **Release metadata hardening (Trojan Horse strategy)**: package metadata now reflects the proprietary Aegis platform positioning. `pip install aegis-shield` continues to provide the full `@shield` decorator, but distribution metadata no longer exposes implementation details of the Aegis platform.
  - Removed `Homepage` / `Repository` / `Changelog` URLs from `pyproject.toml` (source repository is private).
  - Removed GitHub-hosted badges from `README.md`.
  - Replaced Operating Modes section with Aegis Platform category positioning; production deployments now direct to `contact@aegisagentcontrol.com`.
  - Removed Architecture section that exposed internal Aegis component names.
  - Replaced private-repo relative links (`examples/`, `docs/decisions/`, `SECURITY.md`) with `contact@aegisagentcontrol.com` contact.

### Added
- **NOTICE file**: explicit patent reservation. MIT License grants copyright permissions only; patent rights in Aegis platform technologies are expressly reserved by the rights holder. Commercial and patent licensing inquiries routed to `contact@aegisagentcontrol.com`.

## [0.6.5.0] — 2026-04-12

### Fixed
- **deny_fields fail-open vulnerability (minimum disclosure)**: `deny_fields=["profile", "profile.ssn"]` silently leaked `profile.age`, `profile.salary`, etc. because path tree merge made the parent non-leaf. `_parse_paths(broader_wins=True)` now ensures broader deny paths always win over narrower children. Scope mode (whitelist) is unaffected.
- **filtering path exception guard (fail-closed)**: exceptions during `_filter_result`/`_deny_filter_result` (e.g., malicious dict subclass raising on `.items()`) now return empty string instead of crashing. All three shield modes (lite, full, deny) are guarded.
- **CI checkout SHA test**: tightened from accepting mutable tags (`v4`) to requiring full 40-char SHA pin.

### Added
- **Adversarial regression suite** (`tests/adversarial/`): 10 test files, 111 tests covering scope bypass, deny_fields bypass, REST API boundary, exception info leak, YAML injection, SQLite injection, `_test_hook` abuse, CI/CD attack vectors, validation boundaries, and supply chain integrity. AI Red Team Sprint S018.
- **Direct unit tests for `_parse_paths(broader_wins=True)`**: 7 tests covering duplicates, 4-level depth chains, mixed independent paths, same-depth non-parent fields, and backwards compatibility.

### Security
- AI Red Team Sprint S018: adversarial penetration testing of v0.6.4.1 from AI attacker perspective. 10 attack scenarios, 111 adversarial tests. Found and fixed 1 MEDIUM vulnerability (deny_fields path tree merge fail-open) and 1 LOW hardening gap (filtering path exception guard).

## [0.6.4.1] — 2026-04-12

### Fixed
- **LaunchAgent log paths**: moved stdout/stderr from world-readable `/tmp/` to user-only `~/.aegis/logs/` directory. `install.sh` now replaces `__HOME__` placeholder and creates the log directory.
- **CI supply chain hardening**: `actions/checkout@v5` pinned to SHA `93cb6efe18208431cddfb8368fd83d5badbf9bfd` to prevent tag-based supply chain attacks.
- **`.gitignore` credential protection**: replaced specific `.env` / `.env.local` entries with `.env*` wildcard to prevent accidental commit of `.env.production` or similar files.

### Added
- **`uv.lock`** tracked for reproducible builds and supply chain protection.

### Security
- Security Sprint S017: systematic OWASP Top 10 + STRIDE coverage audit of v0.4-v0.6.4 codebase. Manual code review of shield.py, client.py, scripts/, launchd/, CI/CD, and dependency supply chain. Result: CRITICAL=0, HIGH=0. All findings fixed.

## [0.6.4] — 2026-04-12

### Fixed
- **CI attestation completeness (S014 T-105 root cause)**: `make ci-matrix` Makefile recipe used `/bin/sh` with `pip install ... | tail -1` and `pytest ... | tail -3`, masking non-zero exit codes behind `tail`. This caused a false "ALL PASSED" display even when all steps failed. Extracted to `scripts/ci-matrix.sh` with `set -euo pipefail`, individual exit code checks, and no pipe masking.
- **attestation integrity (S014 T-107)**: `scripts/ci-attest.sh` appended the OPENTIMESTAMPS status line after `ots stamp`, invalidating the proof. Now uses sidecar `.ots-status` file; the attestation file is never modified after stamping.
- **fail-closed CI**: `pip-audit` failure no longer silently continues attestation generation (`|| true` removed). Non-zero exit from `pip-audit` aborts attestation.
- **Same-pattern pipe mask** in `ci-attest.sh` (`pip install ... | tail -1`) fixed to `uv pip install` with direct exit code check.
- **Pre-push hook fragile grep** (`grep -q "No known vulnerabilities found"`) replaced with exit-code-based `pip-audit` check.

### Added
- **`scripts/ci-matrix.sh`** — standalone CI matrix runner with bash strict mode (`set -euo pipefail`), `uv pip install --python` for pip-less venvs, per-version result tracking.
- **`VERSION` file** — single source of truth for version. `tests/test_version_ssot.py` asserts `VERSION` = `pyproject.toml::version` = `aegis.__version__`.
- **Pre-PQC bridging**: attestation hash upgraded from SHA-256 to **SHA-3-512** (NIST FIPS 202). `tests/test_sha3_known_vector.py` validates against NIST test vectors and prevents SHA-512/256 confusion.
- **`scripts/ots-verify-external.sh`** — multi-source independent OTS verification via blockstream.info + mempool.space APIs (replaces local Bitcoin node requirement).
- **`launchd/`** directory with version-controlled LaunchAgent plists and scripts for CI cost monitoring, OTS confirmation watching, and watchdog.
- **`docs/RUNNER_HARDENING.md`** — self-hosted runner threat model and credential rotation plan.
- **`tests/test_ci_scripts.py`** — automated regression tests for CI script failure propagation (CI attestation).
- **Shellcheck CI step** in GitHub Actions workflow.
- **OTS ≠ PQC disclosure** in README.md and SECURITY.md per PQC migration roadmap commitment.

### Changed
- `actions/checkout` bumped from v4 to **v5** (v6 ignored via dependabot config, per Aegis policy).
- `attrs` dependency relaxed from `<25.0` to `<27.0` (no breaking change impact; aegis-shield does not use `field_transformer`).
- CI workflow `pip install` replaced with `uv pip install --python` for consistency with local CI matrix.
- `examples/crypto_wallet.py` — plausible secret strings replaced with `<REDACTED>` placeholders (eliminates gitleaks false positives).
- PQC migration roadmap updated: SHA-3-512 moved from v0.7 to v0.6.4, task ID corrected to T-209.

## [0.6.3] — 2026-04-10

### Changed
- **CI moved to self-hosted GitHub Actions runner.** Eliminates dependency on GitHub-hosted Actions billing entirely. The runner runs on the canonical maintainer machine (Apple Silicon, macOS) and consumes zero GitHub Actions minutes. CI matrix completes in ~1m 44s.
- **Workflow trigger restricted to `push` only.** PRs from forks are no longer auto-CI'd. This eliminates the fork-PR-attacks-self-hosted-runner attack vector entirely. To CI a contribution, the maintainer pushes it to a branch in this repo (typically `task/...`).

### Added
- **Self-hosted runner setup documentation** in `docs/RELEASE.md` — full step-by-step setup including SHA-256 verification of the runner binary, security model explanation (Aegis runner trust boundary), and persistence options.
- **Fork detection guard step** in every CI job — defense-in-depth check for `github.event.repository.fork` (trust boundary).

### Security
- Each job has explicit `runs-on: [self-hosted, macOS, ARM64, aegis-shield]` labels to prevent accidental cross-project execution.
- Workflow YAML now uses `uv` to manage Python versions on the runner instead of `actions/setup-python` (faster + more controllable).

## [0.6.2] — 2026-04-10

### Added
- **Manual CI Attestation infrastructure** — when automated CI (GitHub Actions, etc.) is unavailable, releases can be verified via local matrix CI bound to commit SHA + timestamp + SHA-256 self-signature + (optional) OpenTimestamps proof. This is the Aegis-aligned alternative to merging without CI evidence (CI attestation completeness).
  - `make ci-matrix` — runs pytest + ruff across Python 3.10/3.11/3.12/3.13 via uv
  - `make ci-attest` — generates `.gstack/ci-attestations/SXXX-vX.Y.Z.txt` (commit-bound, signed)
  - `make ci-act` — runs `.github/workflows/ci.yml` locally via `act` (validates the workflow YAML itself)
  - `scripts/ci-attest.sh` — attestation generator with OpenTimestamps anchoring
  - `scripts/ci-act.sh` — act wrapper with pre-flight checks
  - `docs/RELEASE.md` — full release process documentation (standard + manual attestation paths)
- **`SECURITY.md`** — vulnerability reporting policy with AO-aligned severity baselines
- **`.github/CODEOWNERS`** — required reviewers for security-critical files (review enforcement)
- **`.github/dependabot.yml`** — automated dependency update tracking (independent of GitHub Actions billing)
- **README badges** — CI status, PyPI version, Python versions, license, Aegis AO compliance

### Changed
- `Makefile` — added `lint`, `format`, `audit`, `ci-matrix`, `ci-attest`, `ci-act` targets
- `clean` target now also removes `.ci-venv-*` directories

## [0.6.1] — 2026-04-10

### Breaking Changes
- `@shield` decorated functions that raise an exception now return empty string `""` instead of propagating the exception (fail-closed). This prevents sensitive data (DB connection strings, customer data, error context) from leaking via tracebacks. Errors are still logged via `logger.error` for internal observability.

### Security
- **Fail-closed fix (M1)**: scope bypass on dot-path mismatch — when `scope=["profile.age"]` but the value at `profile` is a scalar (string, int, etc.), the key is now dropped (fail-closed) instead of passed through unfiltered. Previously, scalar values bypassed nested-path filtering.
- **Fail-closed fix (M2)**: exception propagation — `@shield` now wraps user function calls in try/except, returning empty string on exception. Prevents leaking internal data via tracebacks.
- **DoS hardening (M3)**: Added 10s `httpx.Timeout` to `AegisClient`. Prevents indefinite blocking when aegis-core is unresponsive.

### Added
- **CI/CD pipeline (M4)**: GitHub Actions workflow (`.github/workflows/ci.yml`) running pytest (Python 3.10-3.13) + ruff + pip-audit on push/PR.
- 9 regression tests covering M1 (scope scalar drop, deny scalar keep), M2 (sync + async exception sanitization), M3 (httpx timeout configured).

## [0.6.0] — 2026-04-10

### Breaking Changes
- `@shield` decorated functions returning non-dict/non-list values (int, str, dataclass, etc.) now return empty string `""` instead of passing through unfiltered (fail-closed). `None` still passes through. Previously these values bypassed field filtering silently.

### Added
- **aegis.yaml policy file** — centralize purpose-based scope/deny_fields in a single YAML config. `@shield(purpose="support")` auto-loads policies from `aegis.yaml` when scope/deny_fields are omitted
- `load_config()` and `reset_config()` public API for explicit config management
- Config file search order: `./aegis.yaml` → `./aegis.yml` → `AEGIS_CONFIG` env var
- Config validation: mutual exclusion of scope/deny_fields (explicit data flow), field path validation, empty deny_fields rejection (minimum disclosure)
- **pytest plugin** — `shield_history` fixture captures @shield calls in-memory during tests
- `assert_shield_blocked(records, field)` and `assert_shield_passed(records, field)` test helpers
- Plugin auto-registers via `pytest11` entry point
- **Agent Friendly files** — `llms.txt` (AI agent SDK summary), `AGENTS.md` (integration guide), `py.typed` (PEP 561 marker)
- **5 new examples**: `async_example.py`, `multi_purpose.py`, `deny_fields_example.py`, `dot_notation_example.py`, `crypto_wallet.py`

### Changed
- `pyyaml` is now an optional dependency: `pip install aegis-shield[yaml]`
- `@shield(purpose="x")` without scope/deny_fields now tries aegis.yaml before raising ValueError

### Security
- **Fail-closed fix**: Non-dict/non-list return values from `@shield` decorated functions now return empty string instead of passing through unfiltered. Previously, scalar values (int, str, etc.) bypassed field filtering silently. `None` still passes through.
- Added `requirements.lock` for deterministic dependency resolution (supply chain hardening)

## [0.5.0] — 2026-04-10

### Breaking Changes
- `scope=["name"]` now applies to top-level only (v0.4 applied to all nesting levels). Use `scope=["name", "profile.name"]` to include nested paths.
- `deny_fields=["ssn"]` now applies to top-level only. Use `deny_fields=["profile.ssn"]` for nested paths.
- `_diff_keys` now reports removed fields as dot-notation paths (e.g. `"profile.ssn"` instead of `"ssn"`)

### Added
- **Dot-notation** for `scope` and `deny_fields` — precise nested path control (e.g. `scope=["name", "profile.age"]`, `deny_fields=["profile.ssn"]`)
- Field path validation: empty strings, leading/trailing dots, consecutive dots are rejected with `ValueError`
- **Local history store** (`history.py`) — SQLite-backed recording of @shield invocations (enable with `AEGIS_HISTORY=1`)
- `HistoryStore` class with `get_history(limit, purpose)` and `get_stats()` methods
- **CLI** (`aegis history`, `aegis stats`) — inspect local filtering history from the terminal
- `AEGIS_HISTORY_PATH` environment variable to customize history database location (default: `~/.aegis/history.db`)

### Changed
- Filtering engine rewritten: `_filter_dict` / `_deny_filter_dict` now use path-tree matching instead of flat key sets
- `_parse_paths()` converts dot-notation field lists into nested tree structures
- `_shield_lite`, `_shield_full`, `_shield_deny` now record to local history when enabled

## [0.4.0] — 2026-04-09

### Added
- Recursive `deny_fields` filtering — denied keys are removed at every nesting level (minimum disclosure)
- Recursive `scope` filtering — only allowed keys are kept at every nesting level (minimum disclosure)
- Element type validation: `scope` and `deny_fields` elements must all be strings
- Defensive list copy: mutating the original scope/deny_fields list after decoration has no effect
- `IngestEntry.deny_fields` field — aegis-core audit now records which deny_fields were configured
- Recursive `_diff_keys` — audit `blocked_fields` now accurately reports all removed keys including nested ones (audit completeness)

### Changed
- `_filter_dict` and `_deny_filter_dict` are now recursive (previously top-level only)
- `_diff_keys` now recursively collects removed keys from nested dicts and lists

### Security
- Fixed: `deny_fields=["ssn"]` previously did not remove `ssn` from nested dicts like `{"profile": {"ssn": "..."}}` — now removed at all levels
- Fixed: `scope=["name"]` previously passed through all nested content under allowed keys — now filtered recursively
- Fixed: audit `blocked_fields` under-reported removals for nested data (audit completeness)

## [0.3.1] — 2026-04-08

### Fixed
- Empty `deny_fields=[]` now raises `ValueError` (fail-open risk detected by /cross-review)

## [0.3.0] — 2026-04-08

### Added
- `deny_fields` parameter for `@shield` — blacklist mode (hide specific fields, keep everything else)
- FastMCP integration example (`examples/fastmcp_tool.py`)
- Full README rewrite with 30-second quickstart, FastMCP example, and API reference

### Changed
- `scope` parameter is now optional (either `scope` or `deny_fields` required)
- Specifying both `scope` and `deny_fields` raises `ValueError` (explicit data flow)
- Specifying neither `scope` nor `deny_fields` raises `ValueError` (minimum disclosure)
- Empty `deny_fields=[]` raises `ValueError` (hides nothing, fail-open risk)

## [0.2.0] — 2026-04-08

### Added
- Shield API client: `ingest()`, `policy_sync()`, `get_stats()`, `get_report()`
- `backend policy synchronization()` function for purpose policy synchronization
- Fail-closed mode: `@shield` returns empty result when audit fails (audit completeness)
- `_diff_keys` handles `list[dict]` inputs for accurate blocked field reporting
- Shield API types: `IngestEntry`, `IngestResponse`, `PolicySyncEntry`, `PolicySyncResponse`, `ShieldStats`
- Pre-push quality gate (ruff + pytest + pip-audit)

### Changed
- `_shield_full` now uses `/shield/ingest` instead of `/audit-log`
- All Shield API methods unwrap aegis-core `{success, data}` envelope
- the backend policy synchronization helper raises `RuntimeError` in Lite mode

## [0.1.1] — 2026-04-07

### Added
- Async function support: `@shield` now works with `async def` functions
- Full-mode integration tests (9 tests, requires aegis-core)

### Fixed
- Empty token no longer sends invalid `Bearer ` header to aegis-core

## [0.1.0] — 2026-04-07

### Added
- `@shield(purpose, scope)` decorator for AI agent data access control
- Three operating modes: Lite (local filtering), Full (aegis-core), Auto (detect)
- `AegisClient` for aegis-core REST API communication
- Type definitions: `Mode`, `AccessPolicy`, `AuditEntry`, `ShieldResult`
- Auto-generated client for 31 aegis-core API endpoints
- 12 lite-mode unit tests
- Quickstart example
