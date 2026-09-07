# Changelog

## [Unreleased]

### Changed — attribution updated to the current rights holder
- The copyright holder in `LICENSE` (and the byte-identical `python/LICENSE`),
  the vendor of record in `README.md`, the licence line in `node/README.md`, and
  the package author metadata (`package.json` `author`) now name
  **NemoTek**. The repository moved to the `nemotek-inc` organisation on
  2026-09-01 and the transfer completed 2026-09-02; the published attribution
  had not been updated to match. No code, API, or licence *terms* change — this
  is the MIT licence with the holder stated correctly.
- Two historical entries asserted that the Aegis IP was held personally. That is
  no longer true, so the assertion is removed; what each release actually
  changed is kept.

### Added — typed, fail-closed reader for the AI-native `decision` object
- `parseAuthorityDecision(decision)` returns an `AuthorityDecisionView` (with
  `BoundaryPartialView` for its `parts`). It exposes what the AI-native wire
  (`toolCall` / `streamOpen` bodies, a managed stream session's decision)
  already returns but the SDK typed as `Record<string, unknown>`: the
  **server-derived** `fragment_tags`, the attribution trace `parts`
  (per-boundary field names and labels plus the free-text `reason_label`), and the chain pointers `decision_id` / `receipt_event_id` /
  `ledgered`, plus `outcome`, `verb`, `boundary`, `reason_code` /
  `reason_label`, `allowed_fields` / `withheld_fields`, `policy_generation` /
  `policy_digest`, `replayed`. `AUTHORITY_OUTCOMES` names the five-value
  outcome vocabulary.
- Fail-closed for the shapes it checks (listed here and pinned one by one
  in the shared corpus; it is not a proof of authority consistency beyond
  them): a malformed object throws `AegisValidationError`
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
  must be a non-negative safe integer (`Number.MAX_SAFE_INTEGER`, the range
  both SDKs represent exactly; `3.0` is the same JSON value as `3`; `-0` is
  normalised to `0`; rounding of over-precise literals happens in the JSON
  decoder, before the reader, identically in both). The view, its
  arrays and its partials are deep-frozen, and `AUTHORITY_OUTCOMES` is
  frozen and validated against a private copy; members are
  read as own properties, never from the prototype chain. Unknown members are
  ignored (additive-only contract). Shared cross-language corpus:
  `conformance/authority_decision_view.v0.json` (PyPI runs the same vectors).
- Not added to the flat `checkBoundary` view on purpose: `BoundaryDecisionView`
  is unchanged because the flat wire never sends `fragment_tags` / `parts`
  (it already carries the ledgered bit as `evidence_available` and the
  decision id under `evidence`). A field the wire never fills would be a
  claim without a source.

### Deferred — request-side `sessionId` / `fragmentTags` on `checkBoundary` (not in this version)
- Not added. The decision plane's flat wire accepts neither field today and
  drops unknown request keys silently, and `fragment_tags` are server-derived
  (a caller can only ever add to them, never under-declare). An SDK argument
  that is sent but not received would be a parity claim this SDK cannot
  back. Both fields land together with the plane version whose flat wire
  accepts them, as one pinned SDK/plane pair, and that entry will name the
  pair.

## [0.10.2] - 2026-09-05

### Fixed — package metadata points at the repository's current home (no code change)
- `repository.url`, `bugs.url` and `homepage` in `package.json` still named
  the repository's previous GitHub owner after the move to `nemotek-inc`.
  The npm registry verifies `repository.url` against the build provenance
  (Trusted Publisher, `--provenance`) and refused the 0.10.1 upload on that
  mismatch (HTTP 422: `repository.url` expected to match the provenance
  source), so npm never carried 0.10.1 while PyPI did. 0.10.2 is 0.10.1 with
  the URLs corrected — identical in code and behaviour.

## [0.10.1] - 2026-09-01

### Fixed — release-gate hygiene
- `guardTool({ fields })` type validation and the canonical-JSON helpers in the
  receipt verifier now throw coded `AegisValidationError` envelopes
  (`aegis.guard_tool.fields.invalid`, `aegis.receipt.canonical.not_iterable`,
  `aegis.receipt.canonical.unorderable`) instead of bare `TypeError`, so every
  error the SDK raises carries `code` / `remediation` / `docs_url`.
- Public artifacts are English-only again (three internal-label characters in
  comments replaced with English).
- `0.10.0` was tagged but never distributed (the pre-release gate stopped it on
  exactly these findings); `0.10.1` is the first version of this line on npm.

## [0.10.0] - 2026-09-01

### Added — `checkBoundary` carries an optional `destinationResourceId` (Python parity)
- `checkBoundary({ destinationResourceId })` sends top-level
  `destination_resource_id` (string) verbatim and ONLY when set; absent means
  a byte-identical body. A caller-declared label for the concrete resource
  behind `destination`; the SDK neither validates it nor changes its own
  result on it. Interpretation is server-side policy, not a client guarantee.

### Changed — comments no longer cite internal server file paths or internal ticket ids
- Wire-contract comments now describe the contract in neutral terms. No behavior change.

### Added — `checkBoundary` carries the A-1 delegation capability (PyPI parity)
- `CheckBoundaryArgs.capability` (top-level wire field `capability`), and —
  the load-bearing half — it defaults to the token attached by the enclosing
  `delegate()` window. Existing call sites are unchanged and start carrying
  the proof automatically: a capability the developer must REMEMBER to pass
  is fail-open by omission, the same reasoning that put `guardTool` in the
  call path. Explicit `capability` wins; explicit `null` opts out for one call.
- The delegation store moved to `src/delegationContext.ts` so `client.ts` can
  read it without closing an import cycle with `aiNative.ts`.
  `currentCapability` is re-exported — the public API surface is unchanged.
- A `delegate()` window whose mint FAILED now refuses `checkBoundary`
  locally (`aegis.boundary.delegationDenied`, `AegisValidationError`) instead
  of asking un-narrowed. Cross-model review caught this: `currentCapability()`
  flattens the denied sentinel to `null`, so the query would have been
  answered at the PARENT's full width — and `allowed_fields` on that answer is
  exactly what Doctor hands the agent as authorization (`checkWithCore`
  `mapView` → `BoundaryDecision.allowedData`). Same local fail-closed as
  `guardTool` / `streamSession`. An explicit `capability` still works inside a
  denied window: a hand-carried token is not a guess.
- The denied-window refusal now triggers on "no concrete token supplied", not
  on "argument unset". Scoping it to `undefined` left the explicit opt-out
  (`capability: null`, and `""`) as a one-keystroke way past the refusal and
  straight to a parent-width query — the same widening the refusal exists to
  stop. Opting out is meaningful in a GRANTED window; inside a DENIED one it
  is precisely the thing being denied. An explicit `null` outside denial still
  opts out, unchanged. Found by a second cross-review round (codex and cursor
  independently, on the same lines), which also named the test gap: opt-out
  had only ever been exercised after a SUCCESSFUL mint, and denial only with
  unset or an explicit string, never the combination.
- New error code `aegis.boundary.delegationUnsupported` (`AegisHttpError`,
  `status: 501`): a deployment that cannot evaluate a presented capability
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

### Added — keyless receipt verifier (`src/receiptVerify.ts`, PyPI parity)
- `sessionDagRoot` / `verifySessionReceiptStructure` /
  `danglingPriorReceiptRefs` / `computeLineageRoot` / `verifyLineageRoot` /
  `isValueFreeLabel` exported from the package root — the consumer-side
  (keyless) receipt verification surface, previously Python-only. Hex
  vectors pinned cross-impl with the Python SDK and Aegis Core; problem
  strings byte-identical to Python (including `repr` formatting), so
  failures grep identically across SDKs. HONESTY BOUNDARY: authenticity of
  the keyed `audit_chain_link` remains Core-verifiable only.
- Hostile non-string refs/tags are reported as problems (returns-problems
  contract), never thrown.

### Fixed — CLI + proxy hardening (S022 audit remediation)
- `aegis-mcp-proxy` argument parser is strict: an unknown flag exits 2 with
  usage (previously it silently consumed the NEXT flag as its value — a
  typo could drop `--audit-path` without warning); flag values are consumed
  only for known flags; `--help` prints usage.
- `aegis history` no longer truncates the Blocked column at 30 chars —
  blocked fields can no longer disappear from the audit inspection view
  (pad-only, Python parity).
- `aegis history --limit` rejects non-numeric values (exit 2, Python
  argparse parity) instead of silently falling back to 20; a negative limit
  means unlimited (SQLite parity) instead of silently dropping records;
  `--purpose` with a missing value exits 2 instead of meaning "no filter".
- `cmdSandbox` comment no longer claims a Python mirror (the Python CLI has
  no sandbox subcommand); `AEGIS_SANDBOX_AUDIT` documented in the README
  env table.
- History write-failure warning withholds the path and error detail (S018
  P2 minimum-disclosure parity with Python).
- `loadCanonicalPolicy` raises the coded `aegis.canonical.file.notFound`
  envelope on a missing policy file (previously a raw filesystem message);
  the proxy bin's stderr one-liner now carries the `[<code>]` suffix like
  Python, so the documented `aegis.canonical.*` codes grep identically on
  both SDKs. (Cross-review round 1, codex + cursor consensus.)

### Changed — single-sourced wire version constant
- `AEGIS_API_VERSION` / `AEGIS_API_VERSION_HEADER` moved to `constants.ts`;
  `client.ts` uses the constant instead of a second hardcoded date literal
  (drift-by-construction removed). Public exports unchanged.

### Docs — honesty corrections (S022 audit remediation)
- `checkBoundary` witness-claims comment gains a deployment caveat: claims
  are witnessed only on decide-plane-fronted deployments.

### Added — AI-native Layer 2: the interposition layer (`src/aiNative.ts`)
- `guardTool()` — the FULL-strength sibling of LITE's `shield()`: every
  invocation of the wrapped tool is decided by the boundary
  (`POST /tool-call`) BEFORE it runs. Deny / outage / malformed / unledgered
  → the tool never runs and the call resolves `null` (the shield convention
  — nothing to catch, nothing to forget). Arguments never leave the process
  (INV-6). Owner resolves option → `AEGIS_OWNER` → `AEGIS_AGENT_ID`;
  unresolvable denies locally.
- `delegate(options, fn)` — mints a (narrow-only) child capability at the
  sub-agent spawn boundary and attaches it to every guarded call inside the
  scope via `AsyncLocalStorage` (no hand-carried tokens). Nesting carries
  `parentCapability` automatically; a failed mint DENIES the whole window
  fail-closed (guarded calls resolve `null`, stream sessions refuse to
  open); exit revokes the token by default (`revokeOnExit: false` to opt
  out).
- `streamSession(envelope, fn, options)` — a managed continuous-authz
  session that owns the background heartbeat and INTERRUPTS the agent the
  moment the boundary revokes: `session.signal` aborts, `onRevoke(reason)`
  fires, and the promise rejects with `AegisStreamRevokedError` even while
  `fn` is still in flight — a revoked session can never look like a clean
  run. N consecutive heartbeat transport failures (default 3) count as
  revocation (`gateway_unavailable`). Open deny / denied delegation window
  throws `AegisStreamDeniedError` BEFORE `fn` runs; normal completion
  closes witnessed.
- New errors: `AegisStreamDeniedError`, `AegisStreamRevokedError` (carries
  `.reason`). `currentCapability()` exported for observability. Python
  parity: `@guard_tool` / `delegate()` / `stream_session()` — identical
  error codes, mirrored tests.

### Added — MCP proxy FULL mode: the in-path gateway gate (third PEP grows teeth)
- `aegis-mcp-proxy` (Node) mirrors the Python proxy's new FULL mode: explicit
  `--gate check-access|tool-call`, pre-call gateway decision with fail-closed
  outage handling (`gateway_denied` / `gateway_unavailable` audit reasons),
  serialized async line handling so gateway latency cannot reorder host
  traffic. LITE unchanged when `AEGIS_MODE` is unset.

### Added — AI-native v1 wire floor: tool-call / capability lineage / streaming clients
- New `AegisClient` methods against the FROZEN boundary contract
  (`AI_NATIVE_V1_CONTRACT.md`, additive-only): `toolCall` (per-tool-call
  boundary decision; refs and labels only), `toolAllowed` (fail-closed boolean
  gate — transport error, non-200, malformed body, non-passing outcome, or an
  UNLEDGERED decision are all a deny), `capabilityMint` (`CapabilityGrant`,
  narrow-only lineage server-side), `capabilityRevoke`, `streamOpen`,
  `streamHeartbeat` (`StreamStatus`; anything but `ok` means STOP),
  `streamClose`. New error code `aegis.aiNative.responseShape`
  (`AegisValidationError`). Types exported from the barrel. Python parity:
  same wire bodies, same fail-closed rules, mirrored tests.

### Added — Node↔Python parity: the MCP process-boundary proxy now ships on Node too
- New `aegis-mcp-proxy` command (bin) and `src/mcpProxy.ts`: a stdio MCP proxy
  that sits between any MCP host (Claude Code, Cursor, codex, agy) and any MCP
  server — host unmodified — minimizing every `tools/call` result to policy
  before the model sees it, blocking unmapped tools fail-closed, and emitting
  canonical v0 audit events. Faithful port of the Python proxy; the Node proxy
  test mirrors the Python one (same spec = cross-SDK parity for the enforcement
  point).
- New `src/canonical.ts`: aegis-policy v0 loader + aegis-audit-event v0 emitter.
  Filtering reuses the corpus-verified `wrap()`, so the proxy minimizes data
  identically to the Python proxy and the in-process SDK.
- New examples `mcpProxyDemo.ts` (agent-on-tool-path before/after) and
  `llmContextLeak.ts` (nested over-disclosure proof) — Node mirrors of the
  Python examples.

## [0.9.3] - 2026-06-13

### Fixed — live SDK↔gateway integration (found by a real end-to-end against aegis-core)
- `shield()` FULL no longer fail-closes against a live gateway: the SDK now sends the
  required `tool_name` on `/check-access` (previously omitted → HTTP 422 → every FULL
  authorize denied). `tool_name` is an audit label only; the allow/deny decision remains
  the JWT subject + purpose + scope.
- Two fail-open gaps closed. An explicit dev-host `AEGIS_URL` with no `AEGIS_TOKEN` now
  **warns** instead of silently resolving to LITE (the configured gateway was being
  bypassed). The allow-decision cache can be disabled with `AEGIS_ACCESS_CACHE_TTL_MS=0`
  to remove the ~30s stale-allow window after a policy change or gateway outage (deny is
  never cached either way).
- Install friction: a pathless base URL (`host:port` with no `/api/v1`) is now
  auto-completed to `…/api/v1` with a one-time warning, instead of returning 404 on
  every call.

### Added — MCP e2e runners wired into CI
- `node-test` now runs `npm run e2e:mcp` (both `run_end_to_end.mjs` and
  `run_dev_agent_workflow.mjs`) so every PR mechanically verifies the agent → shield →
  audit chain. `run_end_to_end.mjs` uses a fresh per-run audit dir (idempotent reruns).

### Added — LlamaIndex.TS adapter
- `toLlamaIndexTool` (`aegis-trust/adapters`): binds a `shieldedTool()` to a LlamaIndex
  `FunctionTool` via the injected `FunctionTool.from` factory (no LlamaIndex dependency;
  the tool's schema maps to LlamaIndex's `parameters` key). Runnable example
  `examples/llamaindexExample.ts` + `tests/adapters.test.ts` coverage. Brings LlamaIndex
  to parity with the existing LangChain / CrewAI / Vercel adapters.

### Added — dev-agent workflow e2e proof
- `tests/mcp/run_dev_agent_workflow.mjs` — dev-agent → shield → audit end-to-end
  for the First Protected Workflow reference policy: per-purpose exact
  `blockedFields` assertions, trace propagation, and a no-value-leak regression
  pin over the audit JSONL (names only, zero values).
- `tests/devAgentWorkflow.test.ts` gains a policy drift pin between the example
  and the runner.

### Fixed — docker quickstart example
- Bumped the demo dependency pin from `aegis-trust@0.9.0-rc5` to `0.9.2` (npm latest)
  and the demo's own version to `0.9.2`.
- HEALTHCHECK now probes `http://127.0.0.1:8080/health` (IPv4) instead of
  `localhost`: in the container `localhost` resolves to both 127.0.0.1 and ::1,
  busybox wget tries ::1 first, but the Node server binds IPv4 0.0.0.0 only, so the
  `localhost` probe was refused and the container was marked unhealthy forever.
- Example-only change (no SDK source touched); no npm/PyPI re-release required.

## [0.9.2] - 2026-06-05

### Added — Doctor v1: Core-backed `checkWithCore()` against `/check-boundary` (fail-closed)
A new async Doctor entry point asks Aegis Core for the authoritative boundary
decision instead of deciding locally. `checkWithCore(plan, { client?, context? })`
POSTs to `/check-boundary` (Bearer auth, same plumbing as `checkAccess`), maps the
returned `BoundaryDecisionView` to the SDK `BoundaryDecision`
(`PROTECTED→ALLOW`, `ACCESS_REDUCED→REDUCE_SCOPE`, `CHECK_REQUIRED→REQUIRE_CHECK`,
`APPROVAL_REQUIRED→REQUIRE_APPROVAL`, `BLOCKED→BLOCK`; `allowed_fields→allowedData`,
`withheld_fields→blockedData`; `policyVersion="core-v1"`), and returns it so
`scopeForShield(decision)` still drives `shield({ scope })` unchanged. Fail-closed:
any network error, non-2xx, or malformed body yields a `BLOCK` with empty
`allowedData` (never throws raw, never allows on error). The authenticated
principal is the JWT subject server-side and is never sent in the body. The local,
deterministic `check()` (v0) is untouched. New `AegisClient.checkBoundary()` method
and `BoundaryDecisionView` wire types exported.

#### Fail-closed hardening from 3-model cross-review
- **Partial Core response → BLOCK.** `isValidView` now requires the **full**
  `BoundaryDecisionView` shape (`source`, `outcome`, `allowed_fields`,
  `withheld_fields`, `reason_code` all present and correctly typed) before
  trusting it. A partial-but-valid-JSON body like `{"outcome":"PROTECTED"}` no
  longer maps to ALLOW — it is malformed → `CORE_MALFORMED_RESPONSE` → BLOCK.
- **Own-property outcome lookup.** Outcome is matched with
  `Object.prototype.hasOwnProperty.call(OUTCOME_MAP, …)`, so inherited keys
  (`toString`, `constructor`, `__proto__`) can never be accepted as a valid
  outcome (prototype-pollution → BLOCK).
- **Allow set cleared on non-grant outcomes.** Only `ALLOW`/`REDUCE_SCOPE` carry
  an allow set; `REQUIRE_CHECK`/`REQUIRE_APPROVAL`/`BLOCK` force `allowedData`
  to `[]`, even if the Core body (incorrectly) carries `allowed_fields`.
- **Multi-destination fail-closed.** A plan with >1 destination now sends a
  restrictive sentinel (treated as external/unknown) instead of just the first
  destination, so the decision can only get stricter, never looser.
- **Mapping & client-acquisition inside the fail-closed boundary.** `getModuleClient()`
  and the view→decision mapping run inside the try, so any error → BLOCK rather
  than escaping as a raw throw.

### Fixed — `/check-access` scope contract (CSR-03) + multi-scope fail-closed
`checkAccess` / `authorize` previously sent `scope` as a JSON **array**, but the
gateway's `CheckAccessRequest.scope` is a single advisory `Option<String>`; an
array deserialized as a type error (non-200 → fail-closed). The SDK now sends a
single string for a one-element scope and omits the field otherwise (`None` =
purpose-level), matching the server. **Fail-closed hardening (cross-review):** a
`>1`-element scope can no longer be expressed faithfully against the single
`Option<String>` contract — `authorizeDetailed`/`authorize` now **deny** a
multi-scope check (reason `multi_scope_unsupported`) instead of silently dropping
to a purpose-level request the server could ALLOW more permissively than asked.
This restores the pre-CSR-03 fail-closed direction (array body → server type
error → deny). The single-scope (string) and 0-scope (purpose-level) paths and
`authorize()`'s public boolean contract are unchanged.

### Docs — surface the shipped record-boundary streaming adapter
`shieldedStreamTool()` ships in 0.9.1 but was absent from the README, while the
"Alpha limitations" section implied streaming was unsupported and "planned for a
later release." Corrected: record-boundary streaming (LITE) is now documented in
the Runnable-integrations table, a dedicated README section, and a runnable
example ([`examples/streamExample.ts`](examples/streamExample.ts)); the
limitation entry scopes the real remaining gaps (token-level partial-chunk
filtering — not possible by design — and FULL-mode streaming, a tracked
follow-up). No code change; behaviour is unchanged (13 `adaptersStream.test.ts`
cases stay green).

### Security — Doctor↔shield trust-boundary hardening (fail-closed by default)
An independent red-team + synthetic-market sweep found that the (unreleased)
`check()`→`shield({ scope })` path failed **open** along several axes. All are
now closed by construction (1:1 with the Python SDK):
- **Path-aware, normalized field matching.** `neverFields` / `sensitiveFields` /
  per-purpose `deny` now match any path that **is**, **descends from**, or
  **encloses** a guarded field — `neverFields:["ssn"]` blocks `profile.ssn`;
  `["config"]` blocks `config.api_key`. Comparison is Unicode-NFKC + lowercase +
  trimmed, so `SSN` can no longer dodge `ssn`. `allow` grants a field and its
  descendants only (never a parent).
- **`shield` drops a bare leaf over a record-like value (fail-closed).** A bare
  `scope:["config"]` over a nested object no longer discloses the whole subtree;
  enumerate `'config.<field>'`. **Behaviour change** to `shield`.
- **Unknown destinations are treated as external (fail-closed)** — see the new
  `internalDestinations` policy field.
- **Unknown purpose fails closed by default** (`strictUnknownPurpose` defaults
  to `true`): an unknown purpose against a non-empty `purposes` map yields an
  empty allow set. Set `strictUnknownPurpose: false` for prior behaviour.
- **Enforcement coupling:** new `scopeForShield(decision)` returns the scope only
  for `ALLOW` / `REDUCE_SCOPE`; `[]` for `REQUIRE_APPROVAL` / `BLOCK`. Use it,
  not `allowedData`, to drive `shield`.
- **Empty-scope parity:** `shield({ scope: [] })` now discloses nothing (returns
  the empty shape) instead of throwing — matching Python and letting a fully
  reduced verdict drive `shield` cleanly. A truly absent spec (no scope, no
  deny) is still refused.
- **Malformed field paths fail closed at the gate** (`MALFORMED_FIELD_PATH`);
  this also rejects `..`-bearing (path-traversal) field paths.
- **`shield` drops a bare leaf over a `Map`** (a key→value container its
  dot-notation cannot traverse) — found by cross-model (codex) review.
- **Prototype-name purposes fail closed** (`check`): an attacker-supplied
  `purpose` / `actionType` of `"__proto__"` / `"constructor"` / `"toString"` no
  longer resolves an inherited `Object.prototype` member and dodge the
  unknown-purpose guard — `check` now uses own-property lookup (parity with the
  `shield` scope/deny prototype fix in 0.9.0-rc8). Python's `dict.get` was
  already immune. Found by the post-fix red-team re-run.
- **Examples + threat-model:** the `doctor` examples now drive `shield` from
  `scopeForShield(decision)` (not `allowedData` raw), and the README "Not
  guaranteed" section calls out `doctor.check()` as a local, in-process,
  bypassable diagnostic — fail-closed for an honest caller, not a sandbox.
- **Open-direction matches are exact — no normalization confused-deputy.**
  Normalization is one-directional: the never/sensitive/deny *guards* normalize
  (block more, fail-closed), but the two *permissive* matches — the `allow`
  whitelist and `internalDestinations` — match the **literal** token. Loosely
  matching `"NAME"` against `allow:["name"]` (F-1), or `"INTERNAL_SINK"` against
  `internalDestinations:["internal_sink"]` (F-2), would authorize the attacker's
  token and disclose a *distinct* field / skip the sensitive strip for a
  *different* endpoint. Found by post-fix red-team passes.
- New `LocalPolicy` fields: `internalDestinations`, `strictUnknownPurpose`.

### Added — Doctor: pre-action boundary diagnosis (`aegis-trust/doctor`)
- **`check(plan, policy)`** — a new local Trust Boundary primitive that diagnoses
  an Actor's **action plan before it executes** and returns a deterministic
  `BoundaryDecision`. Where `shield()` filters the data an agent *receives*,
  `doctor` decides — ahead of time — what an agent may *do*: which fields are
  justified for the declared purpose, whether sensitive fields are leaving for an
  external destination, and whether the action needs human approval.
  - Verdicts: `ALLOW` / `REDUCE_SCOPE` / `REQUIRE_APPROVAL` / `BLOCK`
    (`REQUIRE_CHECK` reserved). Maps 1:1 to the planned Trust Signal outcomes.
  - **Feeds `shield` directly:** `shield({ scope: decision.allowedData })` — one
    boundary, diagnosed then enforced.
  - **Deterministic, local, LITE-only:** no network, no LLM, no Aegis Core. The
    rule source is a declarative `LocalPolicy` (per-purpose allow/deny, sensitive
    fields, never-fields, external destinations, action approval rules).
  - **Fail-closed:** a `never`-listed field (e.g. secrets) hard-`BLOCK`s the
    action with an empty allowed set.
  - Versioned shared contracts (`schemaVersion`), 1:1 with the Python SDK:
    `TrustContext` / `ActionPlan` / `BoundaryDecision` / `BoundaryReceipt`
    (Local Receipt is `evidenceMode: "local"`, `coreVerified: false` — LITE never
    claims Core's authority).
  - New subpath export `aegis-trust/doctor`; runnable `examples/doctorExample.ts`.
    Zero new runtime dependencies. No `shield()` behaviour change; no version bump.
  - Authoritative enforcement, principal/tenant binding, and formal Evidence
    remain Aegis Core's responsibility (not provided by this SDK).

### Added — streaming framework adapter (`aegis-trust/adapters`)
- **`shieldedStreamTool(spec)`** — streaming sibling of `shieldedTool()` for a
  data accessor that yields a *sequence* of records. `stream(args)` returns an
  async iterable that filters each record to the declared `scope` / `denyFields`
  **at its boundary, as it arrives** — without buffering the whole result first
  (the limitation `shieldedTool()` has today). The streaming unit is one
  fully-formed record, not a token: field-level minimum disclosure needs a
  complete object, so partial-chunk filtering is intentionally out of scope.
  - Reuses the **same `shield()`** per record (pinned LITE) — one trust
    boundary, one fail-closed contract; no second filter implementation. LITE is
    a local, network-free field filter, so per-record cost is negligible.
  - **LITE-only (v1), FULL refused fail-closed.** FULL's `/check-access` gate
    must run *before* the accessor executes; a per-record gate would run the
    accessor first and, on deny, emit one placeholder per matching row —
    leaking result cardinality and breaking the pre-execution guarantee
    `shieldedTool()` gives (and FULL's audit-completeness contract). So
    `mode: "full"` throws `aegis.shield.stream.full_unsupported` at
    construction, and `mode: "auto"` that resolves to FULL at run time refuses
    fail-closed (empty stream, accessor **never called**) rather than silently
    downgrade the gate. For FULL today, use `shieldedTool()`. FULL streaming
    (open-gate-then-stream + batched audit) is a tracked follow-up.
  - **Fail-closed (stream form):** a handler that throws before producing yields
    an empty stream; an iterator that throws mid-stream stops cleanly (no
    re-throw, the in-flight raw record is never emitted, already-filtered records
    stand). A framework never sees an exception that could carry withheld data.
  - Accepts sync or async iterables/generators (and a promise resolving to one).
    Audit records the tool name via `spec.name`, symmetric with `shieldedTool()`.
  - Zero new runtime dependencies; unit-tested in `tests/adaptersStream.test.ts`
    with no framework installed. Python parity ships in the same release
    (`shielded_stream_tool`, see [`python/CHANGELOG.md`](../python/CHANGELOG.md)).

### Added — framework adapters (`aegis-trust/adapters`)
- **Dedicated agent-framework adapters**, promoting LangChain.js, CrewAI (Node
  port), and Vercel AI SDK from *compatible-by-pattern* to *integrated*. New
  subpath export `aegis-trust/adapters`:
  - `shieldedTool(spec)` — a framework-neutral primitive that wraps a data
    accessor in `shield()` (filtering + minimum-disclosure fail-closed) and
    exposes `run()` (filtered value) / `call()` (filtered value serialized for
    text-only tool runners).
  - `toLangChainTool(tool, t)` — binds to a LangChain StructuredTool. The
    `tool` factory is **dependency-injected**, so aegis-trust takes no
    dependency on LangChain and is immune to its internal version churn.
  - `toVercelTool(t, { schemaKey? })` — builds the AI SDK tool object directly.
    Schema key defaults to `inputSchema` (AI SDK v5+); pass
    `{ schemaKey: "parameters" }` for v4 and earlier.
  - `toCrewaiTool(t)` — builds the CrewAI Node port's `{ name, description, run }`
    tool object directly.
  - Zero new runtime dependencies (`dependencies` stays `{}`); the binders are
    unit-tested (`tests/adapters.test.ts`) without any framework installed.
  - The `langchainExample.ts` / `crewaiExample.ts` examples now use the adapters,
    and a new `vercelAiExample.ts` is added.
  - Scope note: Python LangChain/CrewAI adapters ship in the same release
    (see [`python/CHANGELOG.md`](../python/CHANGELOG.md)). No core `shield()`
    behaviour change; no version bump (additive surface, cross-SDK version-lock
    preserved).
  - Audit identity: the shielded accessor is named from `spec.name`, so audit
    records (local history, test hook, by-function stats, FULL ingest) carry the
    tool name instead of `"anonymous"`.
  - `toLangChainTool` is generic over the factory return type — no `unknown`
    cast at the call site.
  - `ShieldedTool.call()` fails closed if a custom `serialize` throws, and warns
    (naming the tool, withholding the error) so the bug stays diagnosable —
    symmetric with the handler-throw path. Tests cover audit identity, a
    `denyFields`-only spec, the AUTO→LITE path, and serializer fail-closed.
  - **Documented the fail-closed contract** on `ShieldedTool` / README: a
    handler error, a denied/unreachable FULL gate, or a serializer error
    resolves to a type-shaped empty value (never a thrown exception), so agent
    frameworks see an empty result rather than a failure to retry on — by
    design (an exception can carry withheld data). Also documented the
    single-argument tool-call contract (`run`/`call` forward exactly one
    structured argument to the handler).

### Docs (LITE error-parity remediation)
- **No Node code change.** The Python SDK reached parity on the LITE
  validation/config error path (it now raises `AegisValidationError` /
  `AegisConfigError` with the same `code` strings Node already used). The
  shared error registry (`node/docs/errors/README.md`) is updated to record,
  per code, which SDK(s) emit it (`both` / `node` / `python`) so the
  cross-SDK contract is explicit. Node-only codes
  (`aegis.shield.purpose.required`, `aegis.shield.mode.sync_full_unsupported`,
  the `aegis.wrap.*` codes) and Python-only codes (`aegis.shield.spec.conflict`,
  `aegis.shield.deny_fields.empty`, `aegis.shield.field_path.invalid`) reflect
  real, intentional API differences, not gaps to close.
- **P1 follow-up (Python-side, doc updated here).** A parallel adversarial audit
  found that the Python conversion-failure and local-history-failure log
  *diagnostics* leaked PII/secrets (exception message + traceback; raw
  `AEGIS_HISTORY_PATH`) on the default surface, and that the interim Python
  envelope had broken `except FileNotFoundError` / `except OSError` /
  `except ImportError`. Both are fixed in the Python SDK (diagnostics are now
  minimum-disclosure; config errors restore the natural builtin catches via
  `AegisConfigFileNotFoundError` / `AegisConfigImportError`). The shared error
  registry (`node/docs/errors/README.md`) records the catch-compat and
  minimum-disclosure guarantees. Node behaviour is unchanged (Node already
  withheld these); no Node code change.
- **P2-1 follow-up (Python-side, doc updated here).** A second independent
  re-audit found the P1 fix still surfaced the type/exception **class names**
  (`type(data).__name__` / `type(cause).__name__` / `type(exc).__name__`) in the
  Python diagnostics, so a *dynamically named* class could leak its name. Fixed:
  the Python conversion / unsupported-shape / history diagnostics now emit only
  SDK-controlled fixed strings (`conversion_failed` / `unsupported_return_shape`
  / `history_write_failed` + a fixed `stage=<label>` enum), withholding all
  application-controlled identifiers. Doc updated accordingly. No Node code change.

### failure-UX hardening + claim-integrity

Collison-grade production-readiness review +
in-scope hardening. No data-path leak was found (fail-closed re-confirmed); the
fixes below close **silent** failure-UX trust gaps and **false documentation
claims** — the worst defect class for a trust product. Source-committed on branch
`sprint/S016`; **not yet released** (rc9 publish is gate-blocked, carried forward).

### Added (schema_version contract)
- `schema_version` is now stamped on every audit event the SDK emits, from a
  single source (`src/constants.ts` `AUDIT_SCHEMA_VERSION = 1`, re-exported by
  `index.ts`). Wired to both surfaces consistently: local JSONL history records
  (`HistoryStore.record` / `recordIdempotent`) and the `/shield/ingest` wire
  payload (additive field; the aegis-core gateway ignores unknown fields, so it
  is backward-compatible — the gateway does not yet persist/use it).
- Backward compatibility: a history record written before this field reads back
  as `schemaVersion: 1` (missing → 1).
- `schema_version` is intentionally **excluded** from the idempotency
  `payloadHash` — `payloadHash` is unchanged by this sprint, so cross-language
  SHA-256 byte parity with Python is preserved.
- Deferred (not implemented): typed `Actor`, `Decision` enum,
  `resource_id`/`resource_type` (the latter is the schema_version=2 shape, gated
  behind a separate decision).

### Changed — invalid / mis-cased `mode` now throws (no silent downgrade)

- `shield({ mode })` with an unrecognized or mis-cased string (e.g. `"FULL"`,
  `"Lite"`, `"fulll"`) now throws `AegisValidationError`
  (`aegis.shield.mode.invalid`) instead of silently falling through to AUTO —
  which had downgraded a caller asking for strict FULL gating into un-gated LITE
  with zero signal. Mode is a trust boundary. (`src/shield.ts`; tests
  `tests/shield.test.ts` "invalid mode is rejected (S016)".)

### Changed — FULL-mode audit-ingest failure is no longer silent

- A post-authorization `/shield/ingest` failure already failed **closed** (data
  withheld, AO-003); it now also emits a `console.warn` with remediation + a
  `fail_closed`/`ingest_failed` audit record, so the caller does not mistake the
  empty result for "no data". (`src/shield.ts` `gateAndRunFull`.)

### Changed — `AEGIS_HISTORY=1` write failure now warns once

- When the local audit log cannot be written, `recordIfEnabled()` now warns once
  ("audit evidence is NOT being recorded") instead of silently swallowing the
  error. The data path stays unbroken; the broken-evidence condition is visible.
  (`src/history.ts`.)

### Fixed — documentation claim integrity

- Corrected the npm README's forward-pending "PyPI ships rc8" claim (PyPI is on
  rc7) and removed an over-stated local-audit integrity claim. FULL-mode gateway
  guarantees remain explicitly scoped with a "Not guaranteed" carve-out.
  (`README.md`.)

### Review artifact

- `deploy/s016/COLLISON_REVIEW.md` — the 10-dimension production-readiness review.
  (Regenerated in S017; the S016 run committed the code but did not persist the
  document.) Execution evidence — `vitest`, `tsc --noEmit`, clean-room install —
  is pending the S017 execution pass and is **not** asserted as re-run.

## [0.9.1] — 2026-06-03 — package author/copyright correction (metadata only)

### Changed
- **Package author/copyright label corrected.**
  The previous label named a company that was not registered at the time, so it
  implied a corporate entity that did not exist. Updates the
  `package.json` `author` field and the `LICENSE` copyright line. No code
  change — functionally identical to `0.9.0`; published only to correct the
  immutable package metadata on the registry.

## [0.9.0-rc8] — 2026-05-30 — fail-open → fail-closed remediation

remediation of the S014 distribution-readiness
NO-GO. Adversarial falsification (single-model + a 3-reviewer cross-model pass)
found data-path edges where the Node SDK returned data **fail-open** while the
Python SDK fail-closes, contradicting both READMEs' fail-closed contract — incl.
a prototype-name `scope` bypass that the first single-model sweep missed. All
are now aligned to Python (Direction A). **Behavioral / breaking** for callers
that relied on the previous fail-open shapes. Verified: prototype-name + 25
adversarial surfaces → 0 leaks; suite 130/130; `sdk_public_surface_parity` PASS.
Paired with PyPI `aegis-trust==0.9.0rc8` (cross-SDK version-lock).

### Changed — `shield()` / `wrap()` reject an empty spec (minimum disclosure)

- Calling `shield({ purpose })` (or `wrap(value, { purpose })`) with **neither
  `scope` nor `denyFields`** now throws `AegisValidationError`
  (`aegis.shield.spec.required` / `aegis.wrap.spec.required`). Previously the
  wrapped function's data was returned **entirely unfiltered**, leaking every
  field. Parity with Python `shield.py:761-774`.
  **Migration:** pass an explicit `scope` (whitelist) or `denyFields`
  (blacklist). An empty spec was never safe.

### Fixed — prototype-name fields no longer bypass `scope` (fail-closed)

- A returned field whose name collides with an `Object.prototype` member
  (`toString`, `constructor`, `hasOwnProperty`, `valueOf`, `__proto__`, …) was
  kept and returned **raw** even when not whitelisted, because the scope check
  used `key in pathTree` (which walks the prototype chain). Scope is a
  whitelist, so this was fail-OPEN. Fixed: the path tree is now a
  null-prototype object and both the scope and deny checks use
  `hasOwnProperty`. (Pre-existing since rc2; the Python SDK was never affected
  because it uses a real `dict`.) Surfaced by a multi-reviewer cross-model
  pass during S015.

### Changed — `denyFields` over a non-record value fails closed

- `denyFields` applied to a **scalar** (e.g. a bare string) or an
  **array of scalars** now returns a type-shaped empty (via `emptyFor`:
  `""` for a string, `0` for a number, `false` for a boolean, `[]`/`["…"]` for
  arrays), instead of the raw value. This is the fail-closed direction; a
  blacklist cannot prove a bare scalar is not itself the secret. (Python
  `_deny_filter_result` returns `""` for all non-record scalars; Node mirrors
  the *fail-closed intent* but keeps the value's empty-of-type shape — a
  documented, benign shape difference, never a leak.) Objects (incl. class
  instances, normalized via `toFilterable`) are filtered field-wise as before
  — only field-less shapes fail closed.

### Note — `scope: []` / empty spec is stricter than Python (safe direction)

- Node throws on an explicit empty spec (`scope: []` with no `denyFields`),
  whereas Python treats `scope=[]` as "disclose nothing" and returns `{}`.
  Node's filter passes unfiltered data through when `scope.length === 0`, so
  rejecting the empty spec at construction is the fail-closed choice. This is
  an intentional, safe-direction divergence, not a parity bug.

### Changed — a wrapped function that throws now fails closed

- If the protected function throws, all paths (LITE sync/async, AUTO→LITE,
  FULL `gateAndRunFull`) now catch and return a fail-closed empty rather than
  letting the exception propagate raw. A thrown error can carry PII in its
  message/stack; re-raising it leaked that data past the shield. Parity with
  Python `shield.py:921-929`.

### Changed — FULL-mode audit ingest is fail-closed (AO-003 audit completeness)

- FULL-mode `/shield/ingest` is now **awaited** and part of the trust
  contract: filtered data is released only after the audit record is durably
  accepted. On ingest failure the call fails closed to a type-shaped empty,
  matching Python `shield.py:1017-1035`. Previously ingest was fire-and-forget
  (fail-open) and the rc7 code documented this as a `python_node_parity`
  divergence deferred to v1.0 GA — that divergence is now **resolved** in favor
  of the Python fail-closed contract.

## [0.9.0-rc7] — 2026-05-26 — Pre-publish substrate gate wire + CHANGELOG artifact cleanup

rc7 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). **No public API change**; this release moves the productization 9-verifier gate into the release pipeline so every future tag push is mechanically audited before any artifact is built or published, and cleans sprint-internal Japanese strings out of the shipped `CHANGELOG.md`. Paired with PyPI `aegis-trust==0.9.0rc7` (cross-SDK version-lock).

### Changed — release pipeline now runs a fail-closed 9-verifier gate before publish

- `.github/workflows/release-attestation.yml`: a `productization-gate` job runs a fail-closed 9-verifier quality gate (5 P0 + 4 P1) against the workspace before any artifact is built. `sbom-node` + `sbom-python` now `needs: [productization-gate]`; `collect-and-sign` / `pack-and-sign-sdk` / `publish-npm-trusted-publisher` are transitively gated. If any P0 verifier fails on a tag push, **no SBOM is generated and nothing is published**. Pending P1 verifiers do not block.

### Changed — `CHANGELOG.md` is now english-first (artifact cleanup, no code change)

- `node/CHANGELOG.md` S179 reference line: replace the non-english sprint annotation with "mil-spec test-honesty doctrine". CHANGELOG ships inside the npm tarball, so customer-facing artifact text must be english-first per `internal-ops/9-verifier #2 english_first_artifact`.
- Same fix on the Python side (`python/CHANGELOG.md` S023 + S024 entries). No semantic difference; the dropped strings were sprint-internal annotation that leaked into the shipped artifact.

### Routed scenarios (internal review)

- `family_5_ops_ci_release / supply_chain_attestation`: incremental — gate is now invoked by the publish pipeline (was only a maintainer-local dogfood through rc6). Still `closure_candidate` until external oracle walk closes the literal residual.
- `family_5_ops_ci_release / npm_pypi_latest_rc_tag_drift`: unchanged — `dist-tags.latest` intentionally stays on `0.9.0-rc3` per the pre-release-doesn't-promote-to-latest design. `npm install aegis-trust@rc` resolves to rc7.



rc6 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API is additive over rc5 with one **behavioral change** on FULL-mode fail-closed return value (see `shield()` FULL mode entry below: shape-preserving empty → `null` for the data-path deny / unreachable cases). Paired with PyPI `aegis-trust==0.9.0rc6` (cross-SDK version-lock).

This is also the **first release cut from the `aegis-trust` monorepo itself** (rc1–rc5 were published from `aegis-shield`, the historical mirror; see `aegis-shield/README.md` L1 `📍 Source moved`). Provenance attestation (SBOM + cosign keyless signatures + GitHub Release artifact attach) is generated by `.github/workflows/release-attestation.yml` (Block B Phase 2) on the `v0.9.0-rc6` tag push.

### Changed — `detectMode` now intent-first (matches README AUTO behaviour matrix)

- `node/src/client.ts` `detectMode()` checks `userIntendsFull()` BEFORE
  probing the backend. Earlier rc4-rc5 builds probed `/health` first and
  opportunistically upgraded AUTO to Full whenever the gateway was
  reachable, even without intent — that contradicted the README matrix
  line "auto + no Full intent → Lite" and made dev environments without
  credentials call `/check-access` against the gateway. The intent-first
  variant restores the documented matrix exactly.
- New behaviour:
  - `AUTO + no Full intent` (no `AEGIS_TOKEN` AND no non-dev URL) → LITE
    (no probe, no `/check-access`).
  - `AUTO + Full intent + reachable backend` → FULL (opportunistic upgrade
    with intent).
  - `AUTO + Full intent + unreachable backend` → fail-closed FULL + one
    `console.warn`. Unchanged.
- `tests/fullMode.test.ts`: the rc4 "AUTO opportunistically upgrades to
  FULL when backend reachable, even without AEGIS_TOKEN" test asserted
  the now-removed probe-first behaviour. Replaced with the matrix-aligned
  assertion: "AUTO + no token + reachable backend → LITE (no opportunistic
  upgrade without intent)".
- **Routed scenarios** (internal review verification batch 1):
  `python_node_parity` divergence #2 (AUTO degrade semantics) — resolved.
  `auto_mode_behavior` (P1) — resolved.

### Changed — `shield()` FULL mode now performs a real `/check-access` trust gate

- **`shield()` FULL mode previously did client-side filtering + best-effort
  audit ingest only — it never called `/check-access`.** The `authorize()`
  gate existed on `AegisClient` but `shield()` did not invoke it, so a FULL
  `shield()` call was effectively `LITE` + telemetry. This release wires the
  gate (`T-SDK-FULL-GATE-01`):
  - In `FULL` mode, the async `shield()` wrapper now `await`s a pre-call
    `/check-access` authorization **before the wrapped function runs**. The
    protected function executes **only** after authorization is granted —
    the gate prevents its side effects / DB reads, it does not merely
    discard their result.
  - Deny / `403` / `503` (audit-fail-closed) / gateway-unreachable / network
    error all cause the wrapped function to **never be invoked**, and the
    call returns `null`. Because the function never ran there is no return
    shape to mirror, so the fail-closed value is a bare `null` (no caller
    data, ever).
  - Audit ingest now runs **only after** authorization succeeds — it is
    post-authorization telemetry (fire-and-forget, fail-open), never the
    trust gate.
  - A function not declared `async`, wrapped with explicit `Mode.FULL`, now
    throws `AegisValidationError`
    (`code: aegis.shield.mode.sync_full_unsupported`) instead of being
    silently mislabelled "full" while running un-gated `LITE` semantics. The
    `async` declaration is the wrapper's pre-execution await point; without
    it the gate cannot run before the function. `AUTO` on a non-`async`
    function resolves to `LITE`.
  - Internal filter/freeze errors **after a granted authorization** are
    caught and return the type-shaped safe empty value (`emptyFor(data)` —
    the function ran, so the data shape can be mirrored). The "fail-closed
    decorator" claim is now true for the Node SDK (previously a filter
    exception propagated).
  - Local audit/history emission (`AEGIS_HISTORY=1`) is fully fail-safe:
    `recordIfEnabled()` now initialises the history store **inside** its
    try/catch, so an unwritable history path cannot turn a FULL-deny
    `null` return — or a fail-closed filter error — into a thrown
    exception. Audit is telemetry; it never breaks the data path.
- **Local diagnostic**: a non-granted FULL authorization is recorded to the
  local history log with `decision` (`deny` / `fail_closed`) + `reason`
  (`denied` / `unreachable` / `core_503` / `http_error` / `internal_error`),
  and emits a single `console.warn` line carrying only those enum labels +
  `purpose` / `function` — no caller data. New additive
  `AegisClient.authorizeDetailed()` returns the reason; the boolean
  `authorize()` public contract is unchanged.
- This **corrects two inaccuracies** in the prior "trust-boundary claim
  scoping" entry below: the `FULL`-mode row's "per-call `/check-access`
  admission" and the headline "decorator fail-closed → empty on internal
  error" were not true of the code at that time. They are true now.

### Changed — documentation: FULL-mode docs updated to match the gate

- `README.md` `FULL`-mode policy row, **Trust-boundary scope** section, and a
  new sync-vs-`Mode.FULL` note now describe the real pre-call gate behaviour.
- Known follow-up recorded: the `authorize()` access cache has a 30 s TTL, so
  a same-token server-side policy change is invisible for ≤ 30 s (P1).

### Changed — documentation: trust-boundary claim scoping

- `README.md` now states the `aegis-core` `FULL`-mode trust-boundary
  guarantees as explicitly scoped claims, in a new **Trust-boundary scope**
  section. Following the aegis-core Core Security Remediation track
  (S173–S176), exactly four guarantees are claimed: `/check-access` JWT
  identity binding, `/check-access` ingress deny-by-default,
  `/check-access` audit-fail-closed, and `AEGIS_PROFILE=production`
  fail-secure boot validation.
- Three broad claims are now explicitly **not** made: no gateway-wide
  audit-fail-closed, no field-level `purpose × scope` minimum-disclosure
  at the gateway, and not production-ready out of the box.
- Four known follow-ups are recorded in the same section: gateway-wide
  `audit.append` sweep, `AEGIS_CAPSULE_ROOT`-missing → 500 no-audit gap,
  `scope` → RBAC/Reflex/field-level wiring, and debug-log redaction.
- The headline, the "30-second understanding" bullet, the "Why" section,
  and the `FULL`-mode policy row were reworded to drop unscoped
  guarantee language. The SDK's `LITE`-mode client-side filtering and
  fail-closed decorator behaviour are unchanged and still accurately
  described — only wording that over-claimed a server-enforced trust
  boundary was corrected.
- No code change, no API change. `python/README.md` was reviewed and is
  unchanged: it makes no `FULL`-mode gateway over-claim.
### Changed — README: `FULL mode — gateway trust-boundary guarantees` subsection (CSR 4/4 claim-scoping)

- `README.md`: added a `### FULL mode — gateway trust-boundary guarantees` subsection. It states, in **scoped** wording verified against aegis-core code, the four guarantees the gateway `/check-access` ingress provides after the Core Security Remediation track (CSR 4/4, landed in aegis-core 2026-05-21): identity binding to the auth-middleware identity, ingress denial of unknown purpose / scope / malformed capsule, audit-or-deny (HTTP 503) fail-closed, and `AEGIS_PROFILE=production` boot-time config validation. The subsection also states explicitly what is **not** guaranteed (no gateway-wide audit fail-closed, no purpose × scope field-level minimum-disclosure, not production-ready out of the box, no all-gateway-operations audit-complete claim) and records four tracked follow-ups.

### Fixed

- **CLI bin-shim silent-exit** (`src/cli.ts`): every `aegis` subcommand invoked through the npm bin shim (`node_modules/.bin/aegis`, including the `npx aegis ...` path that goes through it) silently exited with 0 bytes on both stdout and stderr and exit code 0. Root cause: the ESM "is main module" check compared `basename(process.argv[1])` (`"aegis"` under the bin shim) against the end of `import.meta.url` (`"cli.js"`); the two never matched, so `main()` was never called. Fixed by canonicalising both sides with `realpathSync(fileURLToPath(import.meta.url))` vs `realpathSync(process.argv[1])`. Customers who ran `npm install aegis-trust && npx aegis sandbox` on rc3 / rc4 / rc5 observed zero output and no error message. The next release cut ships the fix. Direct invocation (`node path/to/dist/cli.js sandbox`) was unaffected.
- Regression test added: `tests/cli_bin_invocation.test.ts` spawns the compiled `dist/cli.js` through a symlink in a temp directory (the same shape npm creates at install time) and asserts non-empty stdout + correct exit codes for `--help`, `sandbox`, `history`, `stats`, no-arg, and unknown-command invocations.

### Refs

- T-S179-cli-bin-shim (Tier 0)
- Codex Operational Scenario Review finding #2 (2026-05-21)
- Memory `feedback_test_honesty.md`: fail-silent violates the mil-spec test-honesty doctrine

## [0.9.0-rc5] — 2026-05-21 — cross-SDK version-lock (PyPI rc5 parity, no functional change)

Tier 0 follow-up. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). **Functional content identical to v0.9.0-rc4.**

### Why rc5 (no behaviour change on the npm side)

The Python `aegis-trust@0.9.0rc5` PyPI package was published with the wheel-packaging fix (the legacy `aegis` back-compat shim was re-included after the rc4 wheel target dropped it). The PyPI shim issue is Python-specific (module rename `aegis` → `aegis_trust`); npm has no analogous concept. Bumping npm to rc5 keeps cross-SDK version-lock per the "Version-locked to PyPI" doctrine.

### Changed

- `VERSION` 0.9.0-rc4 → 0.9.0-rc5
- `package.json` version bump
- `src/index.ts` `VERSION` export bump

No source / behavioural changes vs v0.9.0-rc4.

### Refs

- Published-artifact parity gate doctrine (adopted after the rc3 release-integrity incident)
- Wheel-packaging shim drift (PyPI-side)
- Paired with PyPI `aegis-trust 0.9.0rc5`
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0) — closed the source ↔ registry drift that surfaced when `aegis-trust@0.9.0-rc5` was published to npm from `aegis-core/sdk/node-trust/` (commit `080d02cf`) without committing back to this monorepo. The published rc5 npm package was content-identical to rc4 at publish time and remains so.

## [0.9.0-rc4] — 2026-05-21 — pre-GA preview (cross-SDK env-var canonicalisation + AUTO probe-first)

post-canonical-audit cross-SDK parity closure. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.9.0-rc3 with one **breaking-for-direct-callers** semantic change on an exported helper (see Migration below). Paired with PyPI `aegis-trust@0.9.0-rc4`.

> **Why rc4 (not rc3)**: npm published `aegis-trust@0.9.0-rc3` from a commit that carried only the `Aegis-Api-Version` dated header + repository-metadata polish. The PyPI parity closure work below missed the rc3 cut and lands as v0.9.0-rc4 on both PyPI and npm in parity.

### Added — `AEGIS_URL` canonical, `AEGIS_BASE_URL` deprecation alias

- `resolveBaseUrl()` in `src/client.ts` resolves the gateway base URL via a documented precedence order: `AEGIS_URL` (canonical, parity with PyPI `aegis-trust` `shield.py:119`) → `AEGIS_BASE_URL` (deprecation alias) → `DEFAULT_BASE_URL` (`https://localhost:8443/api/v1`).
- `AEGIS_BASE_URL` continues to work for v0.8.x → v0.9.x backward compatibility but emits a one-shot `console.warn` per process the first time it is read. The warning is re-armed by `resetModuleClient()` so test fixtures see one warning per logical reset. **`AEGIS_BASE_URL` will be removed in v1.0.0** per [`docs/VERSIONING.md`](docs/VERSIONING.md) deprecation policy.
- `userIntendsFull()` (exported) now inspects `AEGIS_URL` and `AEGIS_BASE_URL` (alongside `AEGIS_TOKEN`) when deciding whether the user expects Full mode. Local hosts (`localhost` / `127.0.0.1` / `::1` / `*.local`) are treated as dev regardless of port so dev fixtures keep working.

### Added — Mode detection TTL cache (parity with PyPI `_DETECT_MODE_TTL_S = 60.0`)

- `_DETECT_MODE_TTL_MS = 60_000` in `src/client.ts`. `AEGIS_MODE=auto` re-probes the backend every 60 s so process state stays in sync with reality without a per-call probe.
- Without this TTL, a stuck `lite` detection survives gateway recovery, and a stuck fail-closed `full` keeps warning even after the backend is healthy.

### Changed — AUTO probe-first behaviour matrix (parity with PyPI `shield.py:_detect_mode` line 162-177)

`detectMode()` now probes the backend FIRST and consults `userIntendsFull()` only when the probe fails. The full behaviour matrix:

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no token AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full.
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `console.warn`. Previously silently fell back to Lite, which would skip the user-visible warning and provide weaker semantics than the user asked for.

### Migration — `userIntendsFull()` breaking-for-direct-callers (semantic)

- **Pre-rc4**: `userIntendsFull()` returned `true` for `AEGIS_MODE=full` alone (no token / URL required).
- **rc4+**: `userIntendsFull()` requires `AEGIS_TOKEN` OR a non-dev URL (via `AEGIS_URL` or `AEGIS_BASE_URL`). `AEGIS_MODE=full` is handled separately in `detectMode()` and is no longer a sole intent signal for direct callers of `userIntendsFull()`.
- **Who is affected**: callers that import and invoke `userIntendsFull()` directly from `aegis-trust` and rely on `AEGIS_MODE=full` returning `true` from it.
- **Migration recipe**: set `AEGIS_TOKEN` or a non-dev `AEGIS_URL` alongside `AEGIS_MODE=full`. Callers that use only `detectMode()` (the primary entry point) are unaffected — `AEGIS_MODE=full` continues to produce Full mode via the matrix above.

### Tests

- New `tests/fullMode.test.ts` coverage (5 added → 9 total): AUTO probe-first behaviour (LITE fallback when token absent AND backend unreachable; opportunistic FULL when backend reachable; FULL when token + backend reachable; fail-closed FULL with one warn when intent + unreachable), `AEGIS_BASE_URL` deprecation alias (exactly one warn per process), `AEGIS_URL` precedence over `AEGIS_BASE_URL` with no warn.

### Refs

- Paired with PyPI `aegis-trust@0.9.0-rc4` env-var canonicalisation + AUTO probe-first.
- Mirrors PyPI `shield.py` `_resolve_base_url`, `_user_intends_full` extension, and `_detect_mode` probe-first ordering.
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0).
## [0.9.0-rc1] — 2026-05-17 — pre-GA preview

rollup. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.8.1; no breaking changes. SLA: none. Production use: at your own risk. See [`docs/VERSIONING.md`](docs/VERSIONING.md).

### Added — machine-parseable error model

- `AegisError` base class + `AegisValidationError`, `AegisConfigError`,
  `AegisIngestError`, `AegisAuditError`, `AegisHttpError` (`src/errors.ts`).
  Every error carries `code` + `remediation` + `docs_url`.
- `aegisDocsUrl(code)` helper.
- All `shield()` / `wrap()` / `loadConfig()` validation paths now throw
  typed errors. Internal HTTP / test-time errors unchanged.
- Error code registry: [`docs/errors/README.md`](docs/errors/README.md).

### Added — trace propagation

- `withTraceContext({ traceId }, fn)` opens an `AsyncLocalStorage` scope.
- `shield()` reads the ambient `trace_id` and emits it on every audit
  record.
- `newTraceId()` helper (uses `crypto.randomUUID` when available).
- `trace_id` field added to `HistoryRecord`.

### Added — idempotent local audit

- `HistoryStore.recordIdempotent(args, idempotencyKey)` — Stripe
  Idempotency-Key model translated to the local JSONL store. Cross-run
  dedup via lazy key cache seeded from existing records.
- `idempotencyKey` field added to `HistoryRecord`.

### Added — versioning doctrine

- `STABILITY_LEVEL`, `AUDIT_SCHEMA_VERSION` exports from `src/index.ts`.
- [`docs/VERSIONING.md`](docs/VERSIONING.md) — 7-axis versioning doctrine
  (SemVer + schema_version + stability level + breaking change rule +
  dated API version reservation + deprecation policy + error code
  contract).

### Added — productization gates

- `tests/timing/first_call_script.js` + `tests/timing/run_timing_gate.sh`
  — 60s `time_to_first_call` verifier harness.
- `tests/idempotency/invocation.py` + `invocation_runner.mjs` — 100x
  retry `idempotency_guarantee` verifier harness.
- `tests/mcp/run_end_to_end.mjs` — agent → shield → audit end-to-end
  proof, materialises audit JSONL for `trace_propagation` verifier.
- `.github/workflows/node-trust-ci.yml` — added P0 5 verifier steps
  (advisory; release.yml is the authoritative gate via Path A).

### Changed

- `VERSION` 0.8.1 → 0.9.0-rc1.
- `package.json` version bumped; `dist-tag=rc` recommended for publish.
- README first-fold polished per Stripe Press archetype
  (category positioning + 1-line primitive composition + 30s readability).

### Migration (v0.8.1 → v0.9.0-rc1)

- All existing v0.8.1 code continues to work unchanged.
- `shield({ purpose: "" })` and `wrap(value, { purpose: "" })` now throw
  `AegisValidationError` instead of bare `TypeError`. `AegisValidationError`
  extends `Error` and is named `"AegisValidationError"`, so `catch (e: Error)`
  and `instanceof Error` still work; tests asserting `/purpose/` on the
  message still pass.
- aegis.yaml config validation now throws `AegisConfigError` instead of
  bare `Error`. Same compatibility — extends `Error`, message text is
  preserved.

## [0.8.1] — 2026-05-16

First release of `aegis-trust` on npm — TypeScript / Node port of the
`aegis-trust` Python package on PyPI. Version-locked to PyPI 0.8.1 to
signal feature parity with the same semantic guarantees.

### Added — full parity with PyPI aegis-trust 0.8.1

- `shield(options)(fn)` HOF — wraps a sync or async function, filters its
  return value by purpose-bound `scope` / `denyFields`.
- `wrap(value, options)` — direct value filter (TS-only convenience) that
  returns a `ShieldResult` with `filteredKeys` for audit.
- `Mode.LITE / FULL / AUTO` — operating mode (parity with Python).
- `AegisClient` — full HTTP wrapper for aegis-core REST API:
  `/health`, `/check-access`, `/audit-log`, `/shield/ingest`,
  `/audit/verify`, `/shield/policy-sync`, `/shield/stats`, `/shield/report`.
- `loadConfig` / `getPurposePolicy` / `resetConfig` — YAML policy loader
  (requires optional `yaml` dep).
- `HistoryStore` / `recordIfEnabled` / `resetStore` — local audit log
  (JSONL backend, no native SQLite available in Node stdlib).
- `useShieldHistory` / `assertShieldBlocked` / `assertShieldPassed` —
  vitest helpers (parity with Python pytest plugin).
- `aegis` CLI — `aegis history`, `aegis stats` for local inspection.
- `syncPolicies` / `refreshToken` / `reset` — admin helpers.
- `setMetricsHook` — instrumentation hook called after each backend
  request.
- TLS verify prod-lock (`AEGIS_DEV_INSECURE=1` + dev host only).
- Mode.FULL fire-and-forget ingest; telemetry failures never bubble to
  caller.

### Fail-closed invariants (parity with Python)

- bare leaf scope over list-of-records → drop key (`scope: ["users"]`
  with `{ users: [{ssn: "..."}] }` returns `{}`).
- scope expects nested but value is scalar → drop key.
- broader deny wins over child deny (`denyFields: ["profile",
  "profile.ssn"]` collapses to deny `profile` entirely).
- `authorize`: 200 without `allowed: true` → deny.
- `ingest`: non-monotonic seq → reject.

### Parity-by-design difference (documented, intentional)

- Local audit backend: PyPI uses stdlib SQLite. Node has no stdlib
  SQLite, so this port uses an append-only JSONL file. Public API
  surface (`record`, `getHistory`, `getStats`) is identical.
- ORM detection: PyPI auto-detects pydantic v1/v2 / SQLAlchemy /
  dataclass / NamedTuple. TS handles plain objects and class instances
  with `__dict__`-like enumerable keys. Adapter pattern for Zod / Prisma
  / TypeORM is deferred to a future minor release once design alignment
  is set.

## See also

For full sprint history of the Python package (v0.1.0 → v0.8.1), see
the [aegis-trust PyPI CHANGELOG](https://pypi.org/project/aegis-trust/).
The TS port catches the Python package up at the v0.8.1 mark and tracks
it from here.
