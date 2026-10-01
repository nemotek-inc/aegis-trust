// AegisClient — TS port of aegis.client (Python).
//
// Thin facade over the aegis-core REST API. Used by Mode.FULL of the shield
// wrapper, and directly when callers want backend access from non-decorator
// code paths.
//
// Endpoints:
//   GET    /health
//   POST   /check-access
//   POST   /audit-log
//   POST   /shield/ingest
//   GET    /audit/verify
//   POST   /shield/policy-sync
//   GET    /shield/stats
//   GET    /shield/report
//   POST   /tool-call            (AI-native v1)
//   POST   /capability/mint      (AI-native v1)
//   POST   /capability/revoke    (AI-native v1)
//   POST   /stream/open          (AI-native v1)
//   POST   /stream/heartbeat     (AI-native v1)
//   POST   /stream/close         (AI-native v1)

import {
  aegisDocsUrl,
  AegisAuditError,
  AegisHttpError,
  AegisIngestError,
  AegisValidationError,
} from "./errors.js";
import { currentCapabilityFor, delegationDenied } from "./delegationContext.js";
import { isValueFreeLabel } from "./receiptVerify.js";
import {
  AEGIS_API_VERSION,
  AEGIS_API_VERSION_HEADER,
  AUDIT_SCHEMA_VERSION,
} from "./constants.js";
import type {
  AuditChainStatus,
  FieldStats,
  FunctionStats,
  IngestEntry,
  IngestResponse,
  PolicySyncEntry,
  PolicySyncResponse,
  PurposeStats,
  ShieldStats,
} from "./types.js";

function httpError(endpoint: string, status: number): AegisHttpError {
  return new AegisHttpError({
    code: "aegis.http.nonOk",
    remediation: "Inspect server logs; verify endpoint + token; retry if 5xx.",
    docs_url: aegisDocsUrl("aegis.http.nonOk"),
    message: `${endpoint} HTTP ${status}`,
    status,
  });
}

function ingestError(detail: string): AegisIngestError {
  return new AegisIngestError({
    code: "aegis.ingest.responseShape",
    remediation: "Server returned a malformed shield/ingest response. Check aegis-core version.",
    docs_url: aegisDocsUrl("aegis.ingest.responseShape"),
    message: `ingest: ${detail}`,
  });
}

function auditError(detail: string): AegisAuditError {
  return new AegisAuditError({
    code: "aegis.audit.responseShape",
    remediation: "Server returned a malformed audit/verify response. Check aegis-core version.",
    docs_url: aegisDocsUrl("aegis.audit.responseShape"),
    message: `verify: ${detail}`,
  });
}

function aiNativeError(detail: string): AegisValidationError {
  return new AegisValidationError({
    code: "aegis.aiNative.responseShape",
    remediation:
      "Server returned a malformed AI-native response. Check the boundary version "
      + "against AI_NATIVE_V1_CONTRACT.md (additive-only).",
    docs_url: aegisDocsUrl("aegis.aiNative.responseShape"),
    message: detail,
  });
}

const DEFAULT_BASE_URL = "https://localhost:8443/api/v1";
const HEALTH_TIMEOUT_MS = 2_000;
const API_TIMEOUT_MS = 10_000;
// Allow-decision cache TTL. An allow is cached so repeated identical calls do
// not re-hit the gateway. The window is also a fail-open exposure: a gateway
// that goes down or a policy that revokes access is not seen until the entry
// expires (S015 P-27, confirmed live). Operators who need policy changes to
// take effect immediately can set AEGIS_ACCESS_CACHE_TTL_MS=0 to disable the
// cache (every call re-consults the gateway), trading latency for zero stale
// window. Deny is never cached regardless. Default 30s.
const ACCESS_CACHE_TTL_MS = ((): number => {
  const raw = process.env.AEGIS_ACCESS_CACHE_TTL_MS;
  if (raw === undefined || raw.trim() === "") return 30_000;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : 30_000;
})();

export interface AegisClientOptions {
  readonly baseUrl?: string;
  readonly token?: string;
  readonly verifySsl?: boolean;
}

export type MetricsHook = (
  endpoint: string,
  durationMs: number,
  status: number,
) => void;

let _metricsHook: MetricsHook | null = null;

export function setMetricsHook(hook: MetricsHook | null): void {
  _metricsHook = hook;
}

function emitMetric(endpoint: string, startedMs: number, status: number): void {
  const hook = _metricsHook;
  if (!hook) return;
  try {
    hook(endpoint, performance.now() - startedMs, status);
  } catch {
    // Instrumentation must never break the data path.
  }
}

// In Node 18+, global fetch exists. For TLS verify override we'd need
// undici Agent; in Node, env NODE_TLS_REJECT_UNAUTHORIZED=0 is the user
// escape hatch. We honor `verifySsl: false` by setting that env when the
// client constructs — but only if the host is local (mirror Python prod-lock).

const DEV_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
]);

export function isDevHost(urlOrHost: string): boolean {
  try {
    const u = new URL(urlOrHost);
    const host = (u.hostname || urlOrHost).toLowerCase();
    return DEV_HOSTS.has(host) || host.endsWith(".local");
  } catch {
    const host = urlOrHost.toLowerCase();
    return DEV_HOSTS.has(host) || host.endsWith(".local");
  }
}

// S015 install-friction fix (P-37, hit live this sprint): the gateway serves
// every endpoint under `/api/v1`. A base URL of just host:port (no path) makes
// every call 404 with no hint it is a path problem. If the caller passes a
// pathless URL, complete it to `…/api/v1` and warn once so the assumption is
// visible. An explicit non-root path is respected unchanged.
let _baseUrlPathCompletedWarned = false;
export function normalizeBaseUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return url; // not parseable here — leave it for the request layer to error
  }
  if (u.pathname === "/" || u.pathname === "") {
    const completed = `${u.origin}/api/v1`;
    if (!_baseUrlPathCompletedWarned) {
      _baseUrlPathCompletedWarned = true;
      console.warn(
        `aegis-trust: base URL '${url}' has no path; the gateway serves under `
          + `'/api/v1', so using '${completed}'. Set the full URL to silence this.`,
      );
    }
    return completed;
  }
  return url;
}

export function resolveVerifySsl(
  baseUrl: string,
  requested: boolean,
): boolean {
  // Production (non-dev host): TLS verify is forced ON. AEGIS_VERIFY_SSL=false
  // is ignored unless AEGIS_DEV_INSECURE=1 AND host is dev.
  if (requested) return true;
  if (!isDevHost(baseUrl)) {
    return true;
  }
  if (process.env.AEGIS_DEV_INSECURE === "1") {
    return false;
  }
  return true;
}

// ── check-boundary (Doctor v1, Core-backed) ────────────────
// Wire shape of the gateway's BoundaryDecisionView (POST /check-boundary).
// `outcome` is the SCREAMING_SNAKE_CASE DecisionOutcome enum
// (decision_bundle.rs); `reason_code` is snake_case. Field names are surfaced
// (never values).
export type CoreBoundaryOutcome =
  | "PROTECTED"
  | "ACCESS_REDUCED"
  | "CHECK_REQUIRED"
  | "APPROVAL_REQUIRED"
  | "BLOCKED";

export interface CoreDecisionEvidence {
  readonly decision_id: string;
  readonly policy: string;
  readonly enforced_by: string;
  readonly integrity_checkable_at: string;
  readonly recorded_at: string;
}

export interface BoundaryDecisionView {
  readonly source: string; // "CORE"
  readonly outcome: CoreBoundaryOutcome;
  readonly purpose_label: string;
  readonly allowed_fields: ReadonlyArray<string>;
  readonly withheld_fields: ReadonlyArray<string>;
  readonly reason_code: string;
  readonly reason_label: string;
  readonly evidence_available: boolean;
  readonly evidence: CoreDecisionEvidence | null;
  /**
   * The receipt a receipt-issuing Core attaches (absent when the server does
   * not issue one; `null` with `boundary_receipt_error` when it could not
   * commit one). Carried, never checked: verification is the Core's
   * public-key verifier (`aegis-receipt-verify`), not something the SDK decides.
   */
  readonly boundary_receipt?: Record<string, unknown> | null;
  readonly boundary_receipt_error?: string;
}

// ── AI-native `decision` object: typed, fail-closed reader ───────────
// The AI-native wire (POST /tool-call, POST /stream/open) returns a shared
// `decision` object (contract: AI_NATIVE_V1_CONTRACT.md, additive-only) that
// carries more than the flat /check-boundary view does: the SERVER-DERIVED
// `fragment_tags[]`, the attribution trace `parts[]`, and the chain
// pointers `decision_id` / `receipt_event_id` / `ledgered`. Until now the SDK
// handed that object back as `Record<string, unknown>`, so a caller could not
// read those fields without re-deriving the wire shape. This reader exposes
// them and refuses a malformed object instead of defaulting a field the wire
// did not send (a defaulted `fragment_tags: []` would claim "no tags released"
// for a plane that never said so). Python twin: client.py
// parse_authority_decision; shared corpus conformance/authority_decision_view.v0.json.

/** The outcome vocabulary the authority can return (wire, SCREAMING_SNAKE_CASE).
 *  Frozen at runtime — `ReadonlyArray` is only a compile-time promise, and the
 *  reader validates against a private copy, so no caller can widen the
 *  vocabulary by mutating this export. */
export const AUTHORITY_OUTCOMES: ReadonlyArray<CoreBoundaryOutcome> = Object.freeze([
  "PROTECTED",
  "ACCESS_REDUCED",
  "CHECK_REQUIRED",
  "APPROVAL_REQUIRED",
  "BLOCKED",
] as const);
const AUTHORITY_OUTCOME_SET: ReadonlySet<string> = new Set<string>(AUTHORITY_OUTCOMES);
/** Severity rank of each outcome — the authority composes "most restrictive
 *  wins", so the composed outcome can never rank below any partial's. */
const OUTCOME_SEVERITY: ReadonlyMap<string, number> = new Map(
  AUTHORITY_OUTCOMES.map((name, rank) => [name, rank] as const),
);
/** The operator-facing verb is a pure function of the outcome on the wire. */
const OUTCOME_VERB: ReadonlyMap<string, string> = new Map([
  ["PROTECTED", "allow"],
  ["ACCESS_REDUCED", "allow_reduced"],
  ["CHECK_REQUIRED", "require_classification"],
  ["APPROVAL_REQUIRED", "require_approval"],
  ["BLOCKED", "block"],
]);

/** One boundary's verdict inside `AuthorityDecisionView.parts` — the attribution
 *  trace (which boundary said what). Field NAMES and server-derived labels only.
 *  Deep-frozen by the reader. */
export interface BoundaryPartialView {
  readonly boundary: string;
  readonly outcome: CoreBoundaryOutcome;
  readonly reason_code: string;
  readonly reason_label: string;
  readonly allowed_fields: ReadonlyArray<string>;
  readonly withheld_fields: ReadonlyArray<string>;
  readonly fragment_tags: ReadonlyArray<string>;
}

/**
 * Typed view of the `decision` object the AI-native wire returns (`toolCall` /
 * `streamOpen` bodies, a managed stream session's decision). Intended to be
 * built by {@link parseAuthorityDecision}, which refuses a malformed object
 * rather than defaulting a field the wire did not send; an object assembled by
 * hand carries none of that guarantee.
 *
 * `fragment_tags` are SERVER-DERIVED: the authority classifies the data
 * reference and accumulates tags per session; a caller cannot under-declare
 * them. `parts` is the attribution trace (every boundary partial that
 * composed into `outcome`). `ledgered` is the chain witness — an unledgered
 * decision carries no evidence claim, so read `fragment_tags` as released
 * only when `ledgered` is true. `decision_id` doubles as the
 * integrity-checkable ledger id.
 *
 * Immutable: the reader deep-freezes the view, its arrays and its partials
 * (`readonly` is only a compile-time promise).
 *
 * This is NOT the flat `/check-boundary` view: {@link BoundaryDecisionView}
 * carries neither `fragment_tags` nor `parts` (its `evidence_available` is the
 * `ledgered` bit and `evidence.decision_id` the decision id).
 */
export interface AuthorityDecisionView {
  readonly outcome: CoreBoundaryOutcome;
  readonly ledgered: boolean;
  readonly decision_id: string;
  readonly receipt_event_id: string;
  readonly reason_code: string;
  readonly reason_label: string;
  readonly verb: string;
  readonly boundary: string;
  readonly allowed_fields: ReadonlyArray<string>;
  readonly withheld_fields: ReadonlyArray<string>;
  readonly fragment_tags: ReadonlyArray<string>;
  readonly parts: ReadonlyArray<BoundaryPartialView>;
  readonly policy_generation: number | null;
  readonly policy_digest: string | null;
  readonly replayed: boolean;
}

function decisionShapeError(detail: string): AegisValidationError {
  return new AegisValidationError({
    code: "aegis.aiNative.decisionShape",
    remediation:
      "The 'decision' object does not have the AI-native wire shape. Pass the "
      + "'decision' member of a toolCall / streamOpen response (not the whole "
      + "body) and check the boundary version against AI_NATIVE_V1_CONTRACT.md "
      + "(additive-only).",
    docs_url: aegisDocsUrl("aegis.aiNative.decisionShape"),
    message: `authority decision: ${detail}`,
  });
}

const hasOwn = (o: object, k: string | number): boolean =>
  Object.prototype.hasOwnProperty.call(o, k);

/** "Blank" for chain ids, defined identically in both SDKs: nothing but ASCII
 *  whitespace. `trim()` and Python's `str.strip()` disagree on Unicode
 *  whitespace (U+FEFF vs U+0085), so neither is used. */
const isBlank = (s: string): boolean => /^[ \t\n\r\v\f]*$/.test(s);

/** Copy a wire array by OWN INDEX and return the copy only if every element is
 *  a string; `null` otherwise. One traversal: the copy that is validated is the
 *  copy that is returned. `every()` would skip holes in a sparse array, a
 *  polluted `Array.prototype` would fill a hole with an inherited value, and a
 *  spread (`[...raw]`) would consult a custom or polluted iterator that can
 *  yield values the index check never saw. */
function stringListSnapshot(raw: unknown): ReadonlyArray<string> | null {
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    if (!hasOwn(raw, i)) return null;
    const v: unknown = raw[i];
    if (typeof v !== "string") return null;
    out.push(v);
  }
  return Object.freeze(out);
}

function requiredStr(o: Record<string, unknown>, key: string, where: string): string {
  const v = hasOwn(o, key) ? o[key] : undefined;
  if (typeof v !== "string") throw decisionShapeError(`${where}'${key}' missing or not a string`);
  return v;
}

function optionalStr(o: Record<string, unknown>, key: string, where: string): string | null {
  if (!hasOwn(o, key)) return null;
  const v = o[key];
  if (typeof v !== "string") throw decisionShapeError(`${where}'${key}' not a string`);
  return v;
}

function requiredOutcome(o: Record<string, unknown>, where: string): CoreBoundaryOutcome {
  const v = hasOwn(o, "outcome") ? o.outcome : undefined;
  if (typeof v !== "string" || !AUTHORITY_OUTCOME_SET.has(v)) {
    throw decisionShapeError(`${where}'outcome' missing or unknown`);
  }
  return v as CoreBoundaryOutcome;
}

function requiredStrList(
  o: Record<string, unknown>,
  key: string,
  where: string,
): ReadonlyArray<string> {
  const snapshot = stringListSnapshot(hasOwn(o, key) ? o[key] : undefined);
  if (snapshot === null) {
    throw decisionShapeError(`${where}'${key}' missing or not a list of strings`);
  }
  return snapshot;
}

function requiredLabels(
  o: Record<string, unknown>,
  key: string,
  where: string,
): ReadonlyArray<string> {
  // Shape rule only (ASCII label charset, length cap — the receipt verifier's
  // gate): it refuses a tag that is not label-shaped, it does not classify
  // what a label-shaped string means. Tags are server-derived labels.
  const tags = requiredStrList(o, key, where);
  for (const t of tags) {
    if (!isValueFreeLabel(t)) {
      throw decisionShapeError(`${where}'${key}' member is not a value-free label`);
    }
  }
  return tags;
}

/** A non-negative integer no larger than `Number.MAX_SAFE_INTEGER`. JSON has one
 *  number type: `3.0` on the wire is the same value as `3` and reads as 3 in
 *  both SDKs; anything fractional, non-finite, negative, or beyond the safe
 *  range is refused (a larger value would already have been rounded by
 *  `JSON.parse`, so the "exact policy pin" would be silently wrong). */
function parsePolicyGeneration(pg: unknown): number {
  // `Number.isSafeInteger` already bounds the value to ±(2^53 - 1) (Python
  // refuses the same range so both SDKs carry the pin exactly).
  if (typeof pg !== "number" || !Number.isSafeInteger(pg) || pg < 0) {
    throw decisionShapeError("'policy_generation' not a non-negative integer");
  }
  // `-0` is a JavaScript artefact (Python reads the same bytes as 0); normalise
  // so the two SDKs surface the identical value.
  return pg === 0 ? 0 : pg;
}

function parsePart(raw: unknown, index: number): BoundaryPartialView {
  const where = `'parts[${index}]' `;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw decisionShapeError(`${where}is not an object`);
  }
  const o = raw as Record<string, unknown>;
  return Object.freeze({
    boundary: requiredStr(o, "boundary", where),
    outcome: requiredOutcome(o, where),
    reason_code: requiredStr(o, "reason_code", where),
    reason_label: requiredStr(o, "reason_label", where),
    allowed_fields: requiredStrList(o, "allowed_fields", where),
    withheld_fields: requiredStrList(o, "withheld_fields", where),
    fragment_tags: requiredLabels(o, "fragment_tags", where),
  });
}

/**
 * Parse the AI-native `decision` object into an {@link AuthorityDecisionView},
 * fail-closed.
 *
 * Required (present and correctly typed, else `AegisValidationError`
 * `aegis.aiNative.decisionShape`) — every member the frozen wire declares:
 * `outcome` (one of {@link AUTHORITY_OUTCOMES}), `ledgered` (boolean),
 * `decision_id`, `receipt_event_id`, `reason_code`, `reason_label`, `verb`,
 * `boundary` (string), `allowed_fields` / `withheld_fields` (string[]),
 * `fragment_tags` (a list of labels that pass the value-free label SHAPE rule
 * — ASCII label charset, length cap, the receipt verifier's gate; a tag
 * outside that shape is refused. The rule does not classify meaning: tags are
 * server-derived labels, and a label-shaped string is surfaced as-is), and
 * `parts` (boundary partials, each validated the same way). Optional, typed
 * when present (added to the wire after the freeze, or omitted by design):
 * `policy_generation` (non-negative integer no larger than
 * `Number.MAX_SAFE_INTEGER` so both SDKs carry it exactly; `3.0` is the same
 * JSON value as `3`), `policy_digest`, `replayed` (boolean; the wire omits it
 * when false). The returned view is deep-frozen. The chain witness is two-way: `ledgered: true` must carry
 * non-blank `decision_id` / `receipt_event_id` (the claim is only as good as
 * the ids that make it checkable; blank = nothing but ASCII whitespace, the
 * same rule in both SDKs), and `ledgered: false` is only the
 * hard-fault form — `outcome` BLOCKED, blank ids, no composed `fragment_tags`,
 * no `allowed_fields` / `withheld_fields`, not `replayed` (the trace `parts` is preserved verbatim
 * as the diagnostic of what was refused, tags and all — a partial's
 * `allowed_fields` / `fragment_tags` describe what that boundary computed, they
 * are never a grant); an executable outcome or a chain pointer on an unledgered
 * decision is refused. A ledgered decision is also checked against its own
 * trace: the composed `outcome` is at least as restrictive as every partial's
 * (the authority composes most-restrictive-wins) and the composed
 * `fragment_tags` contain every tag a partial carries (the authority composes
 * the union), and the composed `allowed_fields` equal the winning partial's
 * own allow set (the authority copies it verbatim, so a differing composed set
 * is a grant the trace does not support). Unknown members are ignored (the
 * contract is additive-only). `verb` must be the verb of `outcome`; a ledgered
 * decision with no trace at all is accepted only as the fail-closed BLOCKED
 * form with an empty allow set. The returned view is deep-frozen. A decision with `ledgered: true`
 * must carry non-blank `decision_id` / `receipt_event_id` (the witness claim
 * is only as good as the ids that make it checkable). Unknown members are
 * ignored (the contract is additive-only). The returned view holds copies — mutating the
 * input afterwards does not change it.
 *
 * Pass the `decision` MEMBER (`body.decision`), not the whole response body.
 */
export function parseAuthorityDecision(decision: unknown): AuthorityDecisionView {
  if (decision === null || typeof decision !== "object" || Array.isArray(decision)) {
    throw decisionShapeError("not an object");
  }
  const o = decision as Record<string, unknown>;
  const where = "";
  const outcome = requiredOutcome(o, where);
  const ledgered = hasOwn(o, "ledgered") ? o.ledgered : undefined;
  if (typeof ledgered !== "boolean") {
    throw decisionShapeError("'ledgered' missing or not a boolean");
  }
  let decision_id = requiredStr(o, "decision_id", where);
  let receipt_event_id = requiredStr(o, "receipt_event_id", where);
  const reason_code = requiredStr(o, "reason_code", where);
  const reason_label = requiredStr(o, "reason_label", where);
  const verb = requiredStr(o, "verb", where);
  if (verb !== OUTCOME_VERB.get(outcome)) {
    throw decisionShapeError("'verb' does not match 'outcome'");
  }
  const boundary = requiredStr(o, "boundary", where);
  const policy_digest = optionalStr(o, "policy_digest", where);
  let policy_generation: number | null = null;
  if (hasOwn(o, "policy_generation")) {
    policy_generation = parsePolicyGeneration(o.policy_generation);
  }
  let replayed = false;
  if (hasOwn(o, "replayed")) {
    const rp = o.replayed;
    if (typeof rp !== "boolean") throw decisionShapeError("'replayed' not a boolean");
    replayed = rp;
  }
  // The chain witness is two-way. ledgered=true must carry the ids that make
  // the claim checkable (blank counts as missing — receipt precedent).
  // ledgered=false is ONLY the hard-fault form: the union ledger refused the
  // write, so the decision is BLOCKED, carries no chain ids, releases no tags
  // and cannot be a replay. An executable outcome or a chain pointer on an
  // unledgered decision is a claim the chain never witnessed.
  if (ledgered) {
    if (isBlank(decision_id)) {
      throw decisionShapeError("'decision_id' empty on a ledgered decision");
    }
    if (isBlank(receipt_event_id)) {
      throw decisionShapeError("'receipt_event_id' empty on a ledgered decision");
    }
  } else {
    if (outcome !== "BLOCKED") {
      throw decisionShapeError("'outcome' must be BLOCKED on an unledgered decision");
    }
    if (!isBlank(decision_id)) {
      throw decisionShapeError("'decision_id' present on an unledgered decision");
    }
    if (!isBlank(receipt_event_id)) {
      throw decisionShapeError("'receipt_event_id' present on an unledgered decision");
    }
    if (replayed) throw decisionShapeError("'replayed' set on an unledgered decision");
    // Blank means blank: a whitespace-only id is normalised so a caller's
    // truthiness check cannot read it as a chain pointer.
    decision_id = "";
    receipt_event_id = "";
  }
  const allowed_fields = requiredStrList(o, "allowed_fields", where);
  const withheld_fields = requiredStrList(o, "withheld_fields", where);
  const fragment_tags = requiredLabels(o, "fragment_tags", where);
  if (!ledgered && fragment_tags.length > 0) {
    throw decisionShapeError("'fragment_tags' present on an unledgered decision");
  }
  if (!ledgered && allowed_fields.length > 0) {
    throw decisionShapeError("'allowed_fields' present on an unledgered decision");
  }
  if (!ledgered && withheld_fields.length > 0) {
    throw decisionShapeError("'withheld_fields' present on an unledgered decision");
  }
  const partsRaw = hasOwn(o, "parts") ? o.parts : undefined;
  if (!Array.isArray(partsRaw)) throw decisionShapeError("'parts' missing or not a list");
  // Index loop, not `map()`: `map` skips holes in a sparse array and would
  // hand back an unvalidated hole where a partial should be.
  const partsOut: BoundaryPartialView[] = [];
  for (let i = 0; i < partsRaw.length; i++) {
    partsOut.push(parsePart(hasOwn(partsRaw, i) ? partsRaw[i] : undefined, i));
  }
  // The trace is NOT constrained on a hard fault: the authority keeps the
  // partials the boundaries had already composed (with their own tags and
  // allow sets) as the value-free diagnostic of what was refused, and clears
  // only the composed result. Refusing tags inside the trace would reject a
  // legitimate ledger-outage response (cross-review round 4, codex, from the
  // authority's hard-fault constructor).
  const parts = Object.freeze(partsOut);
  if (ledgered) {
    // The composed decision is derived from its parts: the outcome is the most
    // restrictive partial ("first-max", later gate steps may only raise it)
    // and the composed tags are the union of the partials' tags. A ledgered
    // decision whose top level is LESS restrictive than one of its parts, or
    // that drops a tag a part released, is contradictory — a caller gating on
    // the top level would fail open.
    const composedRank = OUTCOME_SEVERITY.get(outcome) ?? -1;
    const composedTags = new Set(fragment_tags);
    let winner = -1;
    let winnerRank = -1;
    for (let i = 0; i < parts.length; i++) {
      const rank = OUTCOME_SEVERITY.get(parts[i].outcome) ?? -1;
      if (rank > composedRank) {
        throw decisionShapeError(`'outcome' less restrictive than 'parts[${i}]' 'outcome'`);
      }
      for (const t of parts[i].fragment_tags) {
        if (!composedTags.has(t)) {
          throw decisionShapeError(`'fragment_tags' missing tags carried by 'parts[${i}]'`);
        }
      }
      // first-max: only a STRICTLY greater severity replaces the winner
      if (rank > winnerRank) {
        winner = i;
        winnerRank = rank;
      }
    }
    // The composed allow set IS the winner partial's own allow set (the
    // authority copies it verbatim, no widening step exists). A composed allow
    // set that differs from the winner's is a widened (or narrowed) grant the
    // trace does not support.
    if (winner >= 0) {
      const a = new Set(allowed_fields);
      const w = new Set(parts[winner].allowed_fields);
      let same = a.size === w.size;
      if (same) {
        for (const f of a) {
          if (!w.has(f)) {
            same = false;
            break;
          }
        }
      }
      if (!same) {
        throw decisionShapeError(`'allowed_fields' differs from the winning 'parts[${winner}]'`);
      }
    } else if (outcome !== "BLOCKED" || allowed_fields.length > 0) {
      // No trace at all: the authority's compose of an empty partial list is
      // the fail-closed BLOCKED form with an empty allow set. A ledgered grant
      // with nothing to attribute it to is a grant without a witness.
      throw decisionShapeError("'parts' empty on a ledgered decision that is not BLOCKED");
    }
  }
  return Object.freeze({
    outcome,
    ledgered,
    decision_id,
    receipt_event_id,
    reason_code,
    reason_label,
    verb,
    boundary,
    allowed_fields,
    withheld_fields,
    fragment_tags,
    parts,
    policy_generation,
    policy_digest,
    replayed,
  });
}

// Enforcement-neutral attribution witness claim (usage metering).
// Wire shape mirrors the server-side consumer of these claims:
// `{human, on_behalf_of[]}` — snake_case on the wire, so the field names here
// ARE the wire names and the object is sent verbatim. Claims the human (and
// delegation chain) this request serves, for billing attribution only: NEVER an
// authorization input — Core cannot change the decision on it; only hash
// witnesses reach the receipt chain (a hash witness only, never the raw ids).
export interface AttributionClaim {
  readonly human?: string;
  readonly on_behalf_of?: ReadonlyArray<string>;
}

// Request to POST /check-boundary. `purpose` + `scope` are required; the rest
// are optional. The authenticated principal is the JWT subject server-side and
// is NEVER sent in the body.
export interface CheckBoundaryArgs {
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly destination?: string;
  /**
   * Optional caller-declared identifier of the concrete resource behind
   * `destination` (for example a folder id or a channel id). Sent verbatim as
   * top-level `destination_resource_id` and ONLY when set; the SDK neither
   * validates it nor changes its own result on it. What the server does with
   * the label is server-side policy, not a client guarantee.
   */
  readonly destinationResourceId?: string;
  readonly agentId?: string;
  readonly environment?: string;
  readonly mode?: string;
  readonly schemaVersion?: number;
  // OPTIONAL enforcement-neutral witness claims — sent verbatim, ONLY when
  // set (an unset claim leaves the body byte-identical to prior SDKs).
  // `attribution` = the human/delegation chain this request serves;
  // `synthetic: true` marks probe/drill traffic for billing exclusion.
  // Neither ever changes the decision.
  readonly attribution?: AttributionClaim;
  readonly synthetic?: boolean;
  /**
   * What the caller will DO at `destination`: `"read"` or `"write"`. Sent
   * verbatim as top-level `action` and ONLY when set; the SDK does not trim,
   * case-fold or validate it. The server compares it byte for byte and treats
   * no declaration, `"write"`, or any other value as a write — a server-side
   * exemption for registered public-read sources applies only to a declared
   * `"read"`. Servers that predate the field ignore it.
   */
  readonly action?: string;
  // AI-native v1 delegation (A-1): the capability token this call was
  // narrowed by. Normally NOT set by hand — an enclosing `delegate()` window
  // attaches its token automatically (see checkBoundary). Set it explicitly
  // only when carrying a token across a process boundary the async context
  // cannot cross. `null` opts out of the automatic attachment for one call.
  readonly capability?: string | null;
}

// T-SDK-FULL-GATE-01: reason a /check-access authorization did not grant.
// Lets shield() FULL record a local diagnostic without widening the boolean
// `authorize()` public contract.
export type AuthzReason =
  | "allowed" // granted
  | "denied" // HTTP 200 + allowed:false — gateway policy denied
  | "core_503" // aegis-core audit-fail-closed (CSR-02)
  | "http_error" // 403 identity_mismatch / other non-200 / unparseable body
  | "unreachable" // network error / timeout — gateway not reached
  | "multi_scope_unsupported"; // >1 scope vs single-scope server (fail-closed, finding B)

export interface AuthzResult {
  readonly allowed: boolean;
  readonly reason: AuthzReason;
}

// ── AI-native v1 wire types (frozen contract: boundary-core
// docs/AI_NATIVE_V1_CONTRACT.md, additive-only). Decision-adjacent shapes
// keep the wire's snake_case field names (BoundaryDecisionView precedent);
// client-side ARG objects use camelCase (CheckBoundaryArgs precedent).

export interface ToolCallArgs {
  readonly tool: string;
  readonly purpose: string;
  readonly owner: string;
  readonly fields?: ReadonlyArray<string>;
  readonly sessionId?: string;
  readonly destination?: string;
  readonly capability?: string;
  /** `"read"` / `"write"` at `destination`; same contract as CheckBoundaryArgs.action. */
  readonly action?: string;
}

export interface ToolCallResult {
  readonly decision: Record<string, unknown> & {
    readonly outcome: string;
    readonly ledgered: boolean;
  };
  readonly enforcement: unknown;
  readonly [k: string]: unknown;
}

export interface CapabilityMintArgs {
  readonly forAgent: string;
  readonly purposes: ReadonlyArray<string>;
  readonly scope?: ReadonlyArray<string>;
  readonly tools?: ReadonlyArray<string>;
  readonly ttlSecs?: number;
  readonly parentCapability?: string;
}

export interface CapabilityGrant {
  readonly capability: string;
  readonly id: string;
  readonly exp: number;
  readonly depth: number;
  readonly root_delegator: string;
}

export interface StreamOpenResult extends ToolCallResult {
  readonly stream: { readonly stream_id: string; readonly status: string } | null;
}

export interface StreamStatus {
  readonly status: string; // "ok" | "revoked" | "closed"
  readonly reason: string | null;
}

export class AegisClient {
  private _baseUrl: string;
  private _token: string;
  private _verifySsl: boolean;
  private _accessCache: Map<string, number> = new Map();
  private _tokenEpoch: number = 0;
  private _maxAuditSeq: number = 0;

  constructor(options: AegisClientOptions = {}) {
    this._baseUrl = normalizeBaseUrl(options.baseUrl ?? DEFAULT_BASE_URL);
    this._token = options.token ?? "";
    this._verifySsl = resolveVerifySsl(this._baseUrl, options.verifySsl ?? true);
  }

  get baseUrl(): string {
    return this._baseUrl;
  }

  get maxAuditSeq(): number {
    return this._maxAuditSeq;
  }

  private authHeaders(): Record<string, string> {
    // Always attach the Aegis-Api-Version dated header (single-sourced
    // constant — a second hardcoded literal here drifted-by-construction).
    const headers: Record<string, string> = {
      [AEGIS_API_VERSION_HEADER]: AEGIS_API_VERSION,
    };
    if (this._token) {
      headers["Authorization"] = `Bearer ${this._token}`;
    }
    return headers;
  }

  private async req(
    method: "GET" | "POST",
    path: string,
    options: {
      body?: unknown;
      timeoutMs?: number;
      params?: Record<string, string>;
    } = {},
  ): Promise<Response> {
    const timeout = options.timeoutMs ?? API_TIMEOUT_MS;
    let url = this._baseUrl + path;
    if (options.params && Object.keys(options.params).length > 0) {
      const qs = new URLSearchParams(options.params).toString();
      url += `?${qs}`;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const headers: Record<string, string> = {
      ...this.authHeaders(),
    };
    let body: string | undefined;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    // verifySsl=false escape only honored when caller is on dev host AND
    // process env says insecure dev is intended. Handled at construction.
    // Node fetch respects NODE_TLS_REJECT_UNAUTHORIZED globally; we don't
    // toggle it per-request to avoid race conditions.
    try {
      const resp = await fetch(url, {
        method,
        headers,
        body,
        signal: ctrl.signal,
      });
      return resp;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── health ────────────────────────────────────────────
  async isAvailable(): Promise<boolean> {
    try {
      const resp = await this.req("GET", "/health", {
        timeoutMs: HEALTH_TIMEOUT_MS,
      });
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  // ── check-access ──────────────────────────────────────
  private cacheKey(purpose: string, scope: ReadonlyArray<string>): string {
    const sorted = [...scope].sort().join("|");
    return `${this._tokenEpoch}::${purpose}::${sorted}`;
  }

  private cachedAllow(purpose: string, scope: ReadonlyArray<string>): boolean {
    const v = this._accessCache.get(this.cacheKey(purpose, scope));
    return v !== undefined && Date.now() < v;
  }

  private rememberAllow(
    purpose: string,
    scope: ReadonlyArray<string>,
    epochAtRequest: number,
  ): void {
    if (epochAtRequest !== this._tokenEpoch) return;
    this._accessCache.set(
      this.cacheKey(purpose, scope),
      Date.now() + ACCESS_CACHE_TTL_MS,
    );
  }

  private static checkAccessAllowed(body: unknown): boolean {
    if (
      body
      && typeof body === "object"
      && typeof (body as { allowed?: unknown }).allowed === "boolean"
    ) {
      return (body as { allowed: boolean }).allowed;
    }
    return false;
  }

  // Contract fix (CSR-03): the gateway's `/check-access` `scope` field is a
  // single `Option<String>` advisory scope identifier (aegis_gateway
  // rest.rs:296), NOT an array. Sending a JSON array deserializes as a type
  // error server-side (non-200 -> fail-closed), so the prior `{ purpose, scope }`
  // array body silently broke every scope-bearing /check-access call. The
  // authoritative gate is the JWT subject + purpose; `scope` is advisory
  // minimum-disclosure metadata where `None` means "purpose-level access only".
  // This helper emits what the endpoint expects without changing authorize()'s
  // grant/deny contract:
  //   - 0 scopes  -> omit `scope` (None / purpose-level)
  //   - 1 scope   -> send the single string
  //   - >1 scopes -> see authorizeDetailed(): the caller FAILS CLOSED before a
  //                 request is even built (this body builder is never invoked
  //                 with >1 scope on the gate path).
  // Review finding B (fail-closed regression fix): a >1-scope check must NOT
  // silently drop to purpose-level. Earlier, sending the array produced a
  // server type error (non-2xx -> deny); the scope->Option<String> fix changed
  // ">1 scope" into "omit scope", which made the server evaluate at
  // purpose-level and could ALLOW where the caller asked for a stricter,
  // narrower scope. That is a fail-open regression. We therefore DENY a
  // multi-scope check in authorizeDetailed() rather than send a purpose-level
  // request the single-scope server would evaluate more permissively than asked.
  // NOTE: /check-boundary correctly uses `scope: string[]` and does NOT route
  // through here.
  private static checkAccessBody(
    purpose: string,
    scope: ReadonlyArray<string>,
    toolName: string,
  ): Record<string, unknown> {
    // `tool_name` is a REQUIRED (non-Option) field on the gateway's
    // CheckAccessRequest (aegis_gateway rest.rs). Omitting it makes the gateway
    // reject the body with 422 → fail-closed deny on EVERY FULL authorize, so
    // shield() FULL can never grant against a live gateway. It is an audit
    // LABEL only (it does not affect the allow/deny decision — that is JWT
    // subject + purpose + scope), so sending the wrapped function's name is the
    // honest value. (Found by the S015 live SDK↔gateway e2e; same class as the
    // Doctor-v1 agent_id always-BLOCK bug.)
    const body: Record<string, unknown> = {
      purpose,
      tool_name: toolName && toolName.length > 0 ? toolName : "shielded_call",
    };
    if (scope.length === 1) {
      body.scope = scope[0];
    }
    return body;
  }

  async checkAccess(
    purpose: string,
    scope: ReadonlyArray<string>,
    toolName: string = "shielded_call",
  ): Promise<{ allowed: boolean } & Record<string, unknown>> {
    const resp = await this.req("POST", "/check-access", {
      body: AegisClient.checkAccessBody(purpose, scope, toolName),
    });
    if (!resp.ok) throw httpError("check-access", resp.status);
    return (await resp.json()) as { allowed: boolean };
  }

  // ── check-boundary (Doctor v1) ────────────────────────
  // POST /check-boundary, reusing the SAME auth header / base-url / timeout /
  // req() + httpError plumbing as checkAccess. Non-2xx throws httpError so the
  // Doctor v1 entry point maps it to a fail-closed BLOCK. `scope` is a string[]
  // here (the boundary endpoint's contract), unlike /check-access. The JWT
  // subject is the authoritative principal server-side — agentId is advisory
  // and the principal is never sent.
  async checkBoundary(args: CheckBoundaryArgs): Promise<BoundaryDecisionView> {
    const body: Record<string, unknown> = {
      purpose: args.purpose,
      scope: [...args.scope],
    };
    if (args.destination !== undefined) body.destination = args.destination;
    if (args.destinationResourceId !== undefined) body.destination_resource_id = args.destinationResourceId;
    if (args.agentId !== undefined) body.agent_id = args.agentId;
    if (args.environment !== undefined) body.environment = args.environment;
    if (args.mode !== undefined) body.mode = args.mode;
    if (args.schemaVersion !== undefined) body.schema_version = args.schemaVersion;
    // Enforcement-neutral witness claims (usage metering): verbatim,
    // only when set — never authorization inputs, hash-witnessed by Core.
    // Deployment caveat: only newer server builds carry both claims; older
    // builds ignore these fields (HTTP 200, nothing witnessed). Confirm the
    // server build before relying on `synthetic` for billing exclusion.
    if (args.attribution !== undefined) body.attribution = args.attribution;
    if (args.synthetic !== undefined) body.synthetic = args.synthetic;
    if (args.action !== undefined) body.action = args.action;
    // A-1 delegation. A denied window refuses HERE, before the wire: the mint
    // failed, so there is no token to narrow with, and asking un-narrowed
    // would answer at the PARENT's full width. `allowed_fields` on that answer
    // is what Doctor hands the agent as authorization (doctor/checkWithCore
    // mapView → BoundaryDecision.allowedData), so a full-width answer inside a
    // denied window is a widening even though this method only asks a
    // question. Same local fail-closed as guardTool / streamSession.
    //
    // The condition is "no concrete token supplied", NOT "argument unset".
    // Scoping it to `undefined` left the explicit opt-out (`capability: null`)
    // as a way to walk straight past the refusal and ask at parent width —
    // the same widening this block exists to stop, reachable by one keystroke.
    // Opting out of attachment is meaningful in a GRANTED window (ask this one
    // question unnarrowed on purpose); inside a DENIED window it is exactly
    // the thing being denied. Only a caller who brings their own token may
    // proceed. Found by cross-review (codex + cursor, independently, 2026-07-29)
    // — the hole adjacent to the hole the previous round closed.
    // `""` counts as no token: it cannot narrow anything, so letting it through
    // would reopen the same door with an extra keystroke.
    if (!(typeof args.capability === "string" && args.capability !== "") && delegationDenied()) {
      throw new AegisValidationError({
        code: "aegis.boundary.delegationDenied",
        remediation:
          "The enclosing delegate() window is denied — its capability mint "
          + "failed, so no narrowed decision can be obtained. Fix the "
          + "delegation (narrowing, depth, revoked ancestor) or ask outside "
          + "the window. Nothing was sent; the answer would have been at the "
          + "parent's full width.",
        docs_url: aegisDocsUrl("aegis.boundary.delegationDenied"),
        message:
          "check-boundary: the enclosing delegation window is denied — "
          + "not asked (fail-closed)",
      });
    }
    // The token comes from the enclosing delegate() window by default: a
    // boundary the caller must REMEMBER to carry is fail-open by forgetting,
    // the same reasoning that put guardTool in the call path. An explicit
    // `capability` wins; explicit `null` opts out for one call.
    //
    // Wire shape: TOP-LEVEL `capability`. This flat face is not the envelope
    // dialect — sending `delegation: {capability}` here is refused 422 by the
    // server-side flat-wire handler, precisely so a token
    // in the wrong shape is never silently dropped and answered at full width.
    // Origin-bound read: the ambient token is attached ONLY if this client is
    // the one it was minted against. A bare bearer read would let a second
    // client in the same window ship a capability minted for one boundary to
    // a different base URL (cross-review, codex 2026-07-29, severity high).
    const capability =
      args.capability === undefined ? currentCapabilityFor(this._baseUrl) : args.capability;
    if (capability !== null && capability !== undefined) body.capability = capability;
    const resp = await this.req("POST", "/check-boundary", { body });
    // A monolith-gateway deployment refuses a presented capability with 501
    // rather than deciding at full width with the token unread (aegis_gateway
    // rest.rs check_boundary, "A-1 delegation refusal"). That is the correct
    // fail-closed answer, but a generic non-2xx makes it read as an outage —
    // name the cause so the operator fixes the deployment, not the code.
    if (resp.status === 501 && capability !== null && capability !== undefined) {
      throw new AegisHttpError({
        code: "aegis.boundary.delegationUnsupported",
        remediation:
          "This deployment does not evaluate delegated capabilities: only the "
          + "decide-plane serves check-boundary with A-1 delegation. Front the "
          + "deployment with the plane. Do NOT strip the capability to get a "
          + "200 — that trades a refusal for a full-width answer the "
          + "delegation was supposed to narrow. Fix the deployment.",
        docs_url: aegisDocsUrl("aegis.boundary.delegationUnsupported"),
        message: "check-boundary HTTP 501 — deployment is not plane-fronted",
        status: 501,
      });
    }
    if (!resp.ok) throw httpError("check-boundary", resp.status);
    // The body as received, not a rebuilt view: keys the interface does not
    // declare (policy_generation, response_policy, …) stay on the object. A
    // receipt-issuing Core signs a digest of this object minus the receipt
    // keys, so forwarding it whole is what keeps the decision verifiable.
    return (await resp.json()) as BoundaryDecisionView;
  }

  // AO-003 gate: fail-closed authorize. The detailed variant returns the
  // failure reason so callers (shield() FULL) can record a local diagnostic.
  // T-SDK-FULL-GATE-01: additive — the boolean `authorize()` contract below
  // is unchanged; existing direct callers are unaffected.
  async authorizeDetailed(
    purpose: string,
    scope: ReadonlyArray<string>,
    toolName: string = "shielded_call",
  ): Promise<AuthzResult> {
    // Review finding B: the gateway's /check-access scope is a single
    // Option<String>. A >1-scope request cannot be expressed faithfully, and
    // dropping to purpose-level would let the server ALLOW more than the caller
    // asked for. Fail closed BEFORE any request — deny, never grant
    // purpose-level. (0-scope purpose-level and 1-scope single-string are
    // unchanged.) /check-boundary is the right path for multi-field scope.
    if (scope.length > 1) {
      return { allowed: false, reason: "multi_scope_unsupported" };
    }
    if (this.cachedAllow(purpose, scope)) {
      return { allowed: true, reason: "allowed" };
    }
    const epochAtRequest = this._tokenEpoch;
    const t0 = performance.now();
    let resp: Response;
    try {
      resp = await this.req("POST", "/check-access", {
        body: AegisClient.checkAccessBody(purpose, scope, toolName),
      });
    } catch {
      emitMetric("check-access", t0, 0);
      return { allowed: false, reason: "unreachable" };
    }
    emitMetric("check-access", t0, resp.status);
    if (resp.status === 200) {
      let body: unknown;
      try {
        body = await resp.json();
      } catch {
        return { allowed: false, reason: "http_error" };
      }
      if (AegisClient.checkAccessAllowed(body)) {
        this.rememberAllow(purpose, scope, epochAtRequest);
        return { allowed: true, reason: "allowed" };
      }
      return { allowed: false, reason: "denied" };
    }
    // CSR-02: aegis-core returns 503 when a /check-access decision cannot be
    // written to the audit log (audit-fail-closed).
    if (resp.status === 503) {
      return { allowed: false, reason: "core_503" };
    }
    // 403 identity_mismatch / RBAC deny / unknown_scope / invalid_capsule_id,
    // and any other non-200.
    return { allowed: false, reason: "http_error" };
  }

  // Boolean AO-003 gate — unchanged public contract. Delegates to
  // authorizeDetailed(); existing direct callers see identical behaviour.
  async authorize(
    purpose: string,
    scope: ReadonlyArray<string>,
  ): Promise<boolean> {
    return (await this.authorizeDetailed(purpose, scope)).allowed;
  }

  // ── audit-log ─────────────────────────────────────────
  async logAudit(args: {
    purpose: string;
    toolName: string;
    requesterId: string;
    decision: string;
    sessionId?: string;
    reason?: string;
    bytesReturned?: number;
  }): Promise<void> {
    const payload: Record<string, unknown> = {
      purpose: args.purpose,
      tool_name: args.toolName,
      requester_id: args.requesterId,
      decision: args.decision,
    };
    if (args.sessionId !== undefined) payload.session_id = args.sessionId;
    if (args.reason !== undefined) payload.reason = args.reason;
    if (args.bytesReturned !== undefined) payload.bytes_returned = args.bytesReturned;
    const resp = await this.req("POST", "/audit-log", { body: payload });
    if (!resp.ok) throw httpError("audit-log", resp.status);
  }

  // ── shield/ingest ─────────────────────────────────────
  private static ingestPayload(entries: ReadonlyArray<IngestEntry>): unknown {
    return {
      entries: entries.map((e) => ({
        function: e.function,
        purpose: e.purpose,
        scope: [...e.scope],
        blocked_fields: [...e.blockedFields],
        timestamp: e.timestamp,
        count: e.count,
        deny_fields: [...e.denyFields],
        schema_version: AUDIT_SCHEMA_VERSION,
        // Cross-review round 3 P0-4: trace_id propagation to gateway.
        ...(e.trace_id !== undefined ? { trace_id: e.trace_id } : {}),
      })),
    };
  }

  private static parseIngestBody(body: unknown): IngestResponse {
    if (!body || typeof body !== "object") {
      throw ingestError("body is not a dict");
    }
    const data = (body as { data?: unknown }).data;
    if (!data || typeof data !== "object") {
      throw ingestError("body['data'] missing or not a dict");
    }
    const d = data as {
      ingested?: unknown;
      audit_seq_start?: unknown;
      audit_seq_end?: unknown;
    };
    if (typeof d.ingested !== "number" || d.ingested < 0) {
      throw ingestError("'ingested' invalid");
    }
    if (typeof d.audit_seq_start !== "number" || d.audit_seq_start < 0) {
      throw ingestError("'audit_seq_start' invalid");
    }
    if (
      typeof d.audit_seq_end !== "number"
      || d.audit_seq_end < d.audit_seq_start
    ) {
      throw ingestError("'audit_seq_end' invalid or non-monotonic");
    }
    return {
      ingested: d.ingested,
      auditSeqStart: d.audit_seq_start,
      auditSeqEnd: d.audit_seq_end,
    };
  }

  private recordSeq(parsed: IngestResponse): IngestResponse {
    if (parsed.auditSeqEnd > this._maxAuditSeq) {
      this._maxAuditSeq = parsed.auditSeqEnd;
    }
    return parsed;
  }

  // FULL mode is audit-before-release: the gateway must durably accept ALL
  // entries before the shield path releases the filtered data. A contract-valid
  // `200 {ingested: 0, ...}` (or any ingested < expected) means at least one
  // audit record was NOT committed — releasing anyway is a fail-OPEN on audit
  // completeness (AO-003). Throw so the FULL gate fails closed instead of
  // leaking. Only `ingested === expected` is asserted: the audit_seq_* window
  // is gateway-assigned and not contracted to equal the batch size, so a
  // window-size check would risk fail-closing a legitimate ingest. S017 H10.
  private static requireFullAcceptance(
    parsed: IngestResponse,
    expected: number,
  ): void {
    if (parsed.ingested !== expected) {
      throw ingestError(
        `partial acceptance (${parsed.ingested}/${expected}) — audit incomplete, failing closed`,
      );
    }
  }

  async ingest(entries: ReadonlyArray<IngestEntry>): Promise<IngestResponse> {
    const t0 = performance.now();
    const resp = await this.req("POST", "/shield/ingest", {
      body: AegisClient.ingestPayload(entries),
    });
    emitMetric("shield.ingest", t0, resp.status);
    if (!resp.ok) throw httpError("shield/ingest", resp.status);
    const parsed = AegisClient.parseIngestBody(await resp.json());
    AegisClient.requireFullAcceptance(parsed, entries.length);
    return this.recordSeq(parsed);
  }

  // ── audit/verify ──────────────────────────────────────
  private static parseChainBody(body: unknown): AuditChainStatus {
    if (!body || typeof body !== "object") {
      throw auditError("body is not a dict");
    }
    const b = body as { chain_valid?: unknown; total_entries?: unknown };
    if (typeof b.chain_valid !== "boolean") {
      throw auditError("'chain_valid' must be bool");
    }
    if (typeof b.total_entries !== "number" || b.total_entries < 0) {
      throw auditError("'total_entries' invalid");
    }
    return { chainValid: b.chain_valid, totalEntries: b.total_entries };
  }

  async verifyAuditChain(): Promise<AuditChainStatus> {
    const resp = await this.req("GET", "/audit/verify");
    if (!resp.ok) throw httpError("audit/verify", resp.status);
    return AegisClient.parseChainBody(await resp.json());
  }

  async verifyInclusion(opts: { seqEnd?: number } = {}): Promise<boolean> {
    const target = opts.seqEnd ?? this._maxAuditSeq;
    if (target <= 0) return false;
    let status: AuditChainStatus;
    try {
      status = await this.verifyAuditChain();
    } catch {
      return false;
    }
    return status.chainValid && status.totalEntries >= target;
  }

  // ── policy-sync ───────────────────────────────────────
  async policySync(
    purposes: Readonly<Record<string, PolicySyncEntry>>,
  ): Promise<PolicySyncResponse> {
    const payload = {
      purposes: Object.fromEntries(
        Object.entries(purposes).map(([k, v]) => [
          k,
          { scope: [...v.scope], deny_fields: [...v.denyFields] },
        ]),
      ),
    };
    const resp = await this.req("POST", "/shield/policy-sync", { body: payload });
    if (!resp.ok) throw httpError("shield/policy-sync", resp.status);
    const json = (await resp.json()) as { data?: unknown };
    const d = (json.data as {
      synced?: number;
      added?: string[];
      updated?: string[];
    }) ?? {};
    return {
      synced: d.synced ?? 0,
      added: d.added ?? [],
      updated: d.updated ?? [],
    };
  }

  // ── shield/stats ──────────────────────────────────────
  async getStats(
    opts: {
      fromTime?: string;
      toTime?: string;
      purpose?: string;
    } = {},
  ): Promise<ShieldStats> {
    const params: Record<string, string> = {};
    if (opts.fromTime) params.from = opts.fromTime;
    if (opts.toTime) params.to = opts.toTime;
    if (opts.purpose) params.purpose = opts.purpose;
    const resp = await this.req("GET", "/shield/stats", { params });
    if (!resp.ok) throw httpError("shield/stats", resp.status);
    const json = (await resp.json()) as { data?: unknown };
    const d = json.data as {
      period: { from: string; to: string };
      total_calls: number;
      total_blocked_fields: number;
      by_purpose?: Record<string, { calls: number; blocked: number }>;
      by_field?: Record<string, { blocked_count: number }>;
      by_function?: Record<string, { calls: number; purposes?: string[] }>;
    };
    const byPurpose: Record<string, PurposeStats> = {};
    for (const [k, v] of Object.entries(d.by_purpose ?? {})) {
      byPurpose[k] = { calls: v.calls, blocked: v.blocked };
    }
    const byField: Record<string, FieldStats> = {};
    for (const [k, v] of Object.entries(d.by_field ?? {})) {
      byField[k] = { blockedCount: v.blocked_count };
    }
    const byFunction: Record<string, FunctionStats> = {};
    for (const [k, v] of Object.entries(d.by_function ?? {})) {
      byFunction[k] = { calls: v.calls, purposes: v.purposes ?? [] };
    }
    return {
      periodFrom: d.period.from,
      periodTo: d.period.to,
      totalCalls: d.total_calls,
      totalBlockedFields: d.total_blocked_fields,
      byPurpose,
      byField,
      byFunction,
    };
  }

  // ── shield/report ─────────────────────────────────────
  async getReport(
    opts: { format?: "json" | "pdf" } = {},
  ): Promise<Record<string, unknown> | Uint8Array> {
    const fmt = opts.format ?? "json";
    const params: Record<string, string> = fmt === "pdf" ? { format: "pdf" } : {};
    const resp = await this.req("GET", "/shield/report", { params });
    if (!resp.ok) throw httpError("shield/report", resp.status);
    if (fmt === "pdf") {
      const buf = await resp.arrayBuffer();
      return new Uint8Array(buf);
    }
    const json = (await resp.json()) as { data?: unknown };
    return (json.data as Record<string, unknown>) ?? {};
  }

  // ── token rotation ────────────────────────────────────
  setToken(newToken: string): void {
    this._token = newToken;
    this._tokenEpoch += 1;
    this._accessCache.clear();
  }

  // ── AI-native v1: tool-call / capability lineage / streaming ─────
  // Wire contract: boundary-core docs/AI_NATIVE_V1_CONTRACT.md (frozen
  // 2026-07-03, additive-only). These are the WIRE-FLOOR methods — the
  // in-path interposition layer (MCP proxy / decorators / managed stream
  // sessions) builds on them.

  /** Decision outcomes that permit the guarded action to proceed. */
  static readonly PASSING_OUTCOMES: ReadonlyArray<string> = ["PROTECTED", "ACCESS_REDUCED"];

  private static requireDecision(op: string, body: unknown): ToolCallResult {
    if (body === null || typeof body !== "object") {
      throw aiNativeError(`${op}: body is not an object`);
    }
    const decision = (body as Record<string, unknown>).decision;
    if (decision === null || typeof decision !== "object") {
      throw aiNativeError(`${op}: 'decision' missing`);
    }
    const d = decision as Record<string, unknown>;
    if (typeof d.outcome !== "string") throw aiNativeError(`${op}: 'decision.outcome' missing`);
    if (typeof d.ledgered !== "boolean") throw aiNativeError(`${op}: 'decision.ledgered' missing`);
    return body as ToolCallResult;
  }

  private static toolCallBody(args: ToolCallArgs): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      tool: args.tool,
      purpose: args.purpose,
      owner: args.owner,
      fields: [...(args.fields ?? [])],
    };
    if (args.sessionId !== undefined) payload.session_id = args.sessionId;
    if (args.destination !== undefined) payload.destination = args.destination;
    if (args.capability !== undefined) payload.capability = args.capability;
    if (args.action !== undefined) payload.action = args.action;
    return payload;
  }

  /** Decide ONE tool invocation at the boundary (POST /tool-call).
   * Arguments never leave the caller — refs and labels only. A
   * BLOCKED outcome is still HTTP 200; gate on `decision.outcome` being in
   * PASSING_OUTCOMES AND `decision.ledgered` (or use toolAllowed()). */
  async toolCall(args: ToolCallArgs): Promise<ToolCallResult> {
    const resp = await this.req("POST", "/tool-call", {
      body: AegisClient.toolCallBody(args),
    });
    if (!resp.ok) throw httpError("tool-call", resp.status);
    return AegisClient.requireDecision("tool-call", await resp.json());
  }

  /** Fail-closed boolean gate over toolCall() (authorize() parity): any
   * transport error, non-200, malformed body, non-passing outcome, or
   * unledgered decision is a deny. */
  async toolAllowed(args: ToolCallArgs): Promise<boolean> {
    try {
      const out = await this.toolCall(args);
      return (
        AegisClient.PASSING_OUTCOMES.includes(out.decision.outcome)
        && out.decision.ledgered === true
      );
    } catch {
      return false;
    }
  }

  /** Mint a delegation capability (POST /capability/mint). Root grants are
   * bounded by the caller's role NOW; a child grant (`parentCapability`) can
   * only NARROW its parent. Chain-witnessed before the token returns. */
  async capabilityMint(args: CapabilityMintArgs): Promise<CapabilityGrant> {
    const payload: Record<string, unknown> = {
      for_agent: args.forAgent,
      purposes: [...args.purposes],
      scope: [...(args.scope ?? [])],
      tools: [...(args.tools ?? [])],
    };
    if (args.ttlSecs !== undefined) payload.ttl_secs = args.ttlSecs;
    if (args.parentCapability !== undefined) payload.parent_capability = args.parentCapability;
    const resp = await this.req("POST", "/capability/mint", { body: payload });
    if (!resp.ok) throw httpError("capability/mint", resp.status);
    const json = (await resp.json()) as Record<string, unknown>;
    const { capability, id, exp, depth, root_delegator: root } = json;
    if (typeof capability !== "string" || capability === "") {
      throw aiNativeError("capability/mint: 'capability' missing");
    }
    if (typeof id !== "string" || id === "") throw aiNativeError("capability/mint: 'id' missing");
    if (typeof exp !== "number" || exp <= 0) throw aiNativeError("capability/mint: 'exp' invalid");
    if (typeof depth !== "number" || depth <= 0) {
      throw aiNativeError("capability/mint: 'depth' invalid");
    }
    if (typeof root !== "string" || root === "") {
      throw aiNativeError("capability/mint: 'root_delegator' missing");
    }
    return { capability, id, exp, depth, root_delegator: root };
  }

  /** Revoke a capability (POST /capability/revoke): present the token
   * (holder / delegator / root delegator) or, as Admin, the id. Returns the
   * revoked id. Revocation is transitive and cuts matching open streams. */
  async capabilityRevoke(
    args: { capability?: string; capabilityId?: string },
  ): Promise<string> {
    const payload: Record<string, unknown> = {};
    if (args.capability !== undefined) payload.capability = args.capability;
    if (args.capabilityId !== undefined) payload.capability_id = args.capabilityId;
    const resp = await this.req("POST", "/capability/revoke", { body: payload });
    if (!resp.ok) throw httpError("capability/revoke", resp.status);
    const json = (await resp.json()) as Record<string, unknown>;
    if (json.ok !== true) throw aiNativeError("capability/revoke: 'ok' missing");
    if (typeof json.revoked !== "string" || json.revoked === "") {
      throw aiNativeError("capability/revoke: 'revoked' missing");
    }
    return json.revoked;
  }

  /** Open a continuous-authz stream (POST /stream/open) with a full Common
   * Envelope. `stream` is non-null iff the decision passes AND is ledgered. */
  async streamOpen(envelope: Record<string, unknown>): Promise<StreamOpenResult> {
    const resp = await this.req("POST", "/stream/open", { body: { envelope } });
    if (!resp.ok) throw httpError("stream/open", resp.status);
    const body = AegisClient.requireDecision("stream/open", await resp.json());
    const stream = (body as Record<string, unknown>).stream;
    if (stream !== null && stream !== undefined) {
      if (
        typeof stream !== "object"
        || typeof (stream as Record<string, unknown>).stream_id !== "string"
      ) {
        throw aiNativeError("stream/open: 'stream.stream_id' missing");
      }
    }
    return body as StreamOpenResult;
  }

  /** Revalidate a stream NOW (POST /stream/heartbeat). `status` is
   * ok | revoked | closed — anything but ok means STOP. */
  async streamHeartbeat(streamId: string): Promise<StreamStatus> {
    const resp = await this.req("POST", "/stream/heartbeat", {
      body: { stream_id: streamId },
    });
    if (!resp.ok) throw httpError("stream/heartbeat", resp.status);
    const json = (await resp.json()) as Record<string, unknown>;
    if (typeof json.status !== "string") {
      throw aiNativeError("stream/heartbeat: 'status' missing");
    }
    return {
      status: json.status,
      reason: typeof json.reason === "string" ? json.reason : null,
    };
  }

  /** Close a stream (POST /stream/close; owner or Admin). Witnessed. */
  async streamClose(streamId: string): Promise<boolean> {
    const resp = await this.req("POST", "/stream/close", { body: { stream_id: streamId } });
    if (!resp.ok) throw httpError("stream/close", resp.status);
    const json = (await resp.json()) as Record<string, unknown>;
    if (json.ok !== true) throw aiNativeError("stream/close: 'ok' missing");
    return true;
  }

  // ── teardown ──────────────────────────────────────────
  // fetch has no persistent socket pool in user code; nothing to close.
  async close(): Promise<void> {
    this._accessCache.clear();
  }
}

// ── Module-level lazy client (mirrors Python _get_client) ──

let _moduleClient: AegisClient | null = null;
let _detectedMode: "lite" | "full" | null = null;
let _detectedModeTs = 0;
let _baseUrlAliasWarned = false;
let _liteDespiteUrlWarned = false;

// Mode detection cache TTL — parity with PyPI shield.py `_DETECT_MODE_TTL_S = 60.0`.
// AEGIS_MODE=auto re-probes the backend every `_DETECT_MODE_TTL_MS` ms so
// process state stays in sync with reality without per-call probes. Without
// this, a stuck `lite` detection survives gateway recovery, and a stuck
// fail-closed `full` keeps warning even after the backend is healthy.
const _DETECT_MODE_TTL_MS = 60_000;

// Canonical env var resolution. AEGIS_URL is canonical (parity with PyPI
// aegis-trust shield.py:119). AEGIS_BASE_URL is a deprecated alias kept
// for v0.8.x → v0.9.x backward compatibility — emits one warning per
// process, removed in v1.0.0 per docs/VERSIONING.md deprecation policy.
function resolveBaseUrl(): string {
  const aegisUrl = process.env.AEGIS_URL?.trim();
  if (aegisUrl) return aegisUrl;
  const aegisBaseUrl = process.env.AEGIS_BASE_URL?.trim();
  if (aegisBaseUrl) {
    if (!_baseUrlAliasWarned) {
      _baseUrlAliasWarned = true;
      console.warn(
        "aegis-trust: AEGIS_BASE_URL is deprecated — use AEGIS_URL "
          + "(parity with PyPI aegis-trust). AEGIS_BASE_URL will be removed in v1.0.0.",
      );
    }
    return aegisBaseUrl;
  }
  return DEFAULT_BASE_URL;
}

export function getModuleClient(): AegisClient {
  if (_moduleClient === null) {
    const baseUrl = resolveBaseUrl();
    const token = process.env.AEGIS_TOKEN || "";
    const verifyEnv = process.env.AEGIS_VERIFY_SSL;
    const verifySsl = verifyEnv === "false" || verifyEnv === "0" ? false : true;
    _moduleClient = new AegisClient({ baseUrl, token, verifySsl });
  }
  return _moduleClient;
}

// "User expects Full mode" heuristic, parity with PyPI shield.py
// _user_intends_full (line 165-181). Returns true when:
//   - AEGIS_TOKEN is set, OR
//   - AEGIS_URL / AEGIS_BASE_URL points at a non-dev host.
// (NOTE: explicit `AEGIS_MODE=full` is NOT a Full-intent signal here —
// it is handled in its own branch by `detectMode()` before the AUTO
// probe, mirroring PyPI's `_detect_mode` line 160-161.)
// When true, detectMode refuses to silently degrade to Lite on a
// transient backend outage — AO-001 Gateway-uniqueness outranks
// availability.
export function userIntendsFull(): boolean {
  if (process.env.AEGIS_TOKEN?.trim()) return true;
  const url = (process.env.AEGIS_URL || process.env.AEGIS_BASE_URL || "").trim();
  return !!url && !isDevHost(url);
}

export async function detectMode(): Promise<"lite" | "full"> {
  // TTL cache — parity with PyPI shield.py `_DETECT_MODE_TTL_S = 60.0`.
  // Without this, a transient backend outage causes a permanently-stuck
  // "lite" (or fail-closed Full warn) for the process lifetime.
  const nowMs = Date.now();
  if (_detectedMode !== null && nowMs - _detectedModeTs < _DETECT_MODE_TTL_MS) {
    return _detectedMode;
  }

  const envMode = process.env.AEGIS_MODE?.toLowerCase();
  if (envMode === "lite") {
    _detectedMode = "lite";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  if (envMode === "full") {
    // Explicit Full: never silently degrade. Calls fail-closed at the
    // gateway until the backend recovers. Parity with PyPI shield.py
    // _detect_mode line 160-161.
    _detectedMode = "full";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  // AUTO branch — intent-first per the README AUTO behaviour matrix:
  //   - no Full intent (no AEGIS_TOKEN, no non-dev URL) → LITE (no probe)
  //   - Full intent + reachable backend                 → FULL
  //   - Full intent + unreachable backend               → fail-closed FULL + warn
  // The intent check runs BEFORE the /health probe so a dev environment
  // without credentials does not opportunistically call the gateway —
  // this matches the documented matrix exactly. Earlier rc4-rc5 builds
  // probed first and upgraded to Full whenever the gateway was reachable
  // regardless of intent; that behaviour contradicted the matrix line
  // "auto + no Full intent → Lite" and is corrected here. Mirrors PyPI
  // shield.py _detect_mode intent-first variant.
  if (!userIntendsFull()) {
    // S015 P-38 (confirmed live): an explicit AEGIS_URL pointing at a dev host
    // (e.g. a localhost sidecar gateway) with no AEGIS_TOKEN resolves to LITE
    // and the gateway is NEVER consulted — shield() filters locally only. That
    // is the documented intent-first matrix, but it is silent, so an operator
    // who stood up a gateway cannot tell it is being bypassed. Make it loud
    // (fail-loud): warn once. Behaviour is unchanged.
    const explicitUrl = (process.env.AEGIS_URL || process.env.AEGIS_BASE_URL || "").trim();
    if (explicitUrl && !_liteDespiteUrlWarned) {
      _liteDespiteUrlWarned = true;
      console.warn(
        "aegis-trust: AEGIS_URL is set but mode resolved to LITE — no Full intent "
          + "(dev-host URL and no AEGIS_TOKEN). The gateway at this URL will NOT be "
          + "consulted; shield() filters locally only. Set AEGIS_TOKEN (or "
          + "AEGIS_MODE=full) to use the gateway.",
      );
    }
    _detectedMode = "lite";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  const client = getModuleClient();
  const available = await client.isAvailable();
  if (available) {
    _detectedMode = "full";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  // AUTO + explicit Full intent + unreachable: fail-closed Full.
  // Silent Lite degrade would leak data the user asked the gateway to
  // filter.
  _detectedMode = "full";
  _detectedModeTs = nowMs;
  console.warn(
    "aegis-trust: AEGIS_MODE=auto with explicit URL/TOKEN but backend "
      + "unreachable — staying in Full mode (fail-closed). All shield() "
      + "calls will deny until the gateway recovers.",
  );
  return _detectedMode;
}

export function resetModuleClient(): void {
  _moduleClient = null;
  _detectedMode = null;
  _detectedModeTs = 0;
  _baseUrlAliasWarned = false;
  _liteDespiteUrlWarned = false;
  _baseUrlPathCompletedWarned = false;
}
