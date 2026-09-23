// aegis-trust — TypeScript port of aegis-trust (PyPI).
//
// AI agent data access control. Control what agents can see based on
// declared purpose. Drop-in: one wrapper declares purpose; SDK enforces
// field-level access control.
//
// Quickstart:
//
//     import { shield } from "aegis-trust";
//
//     const safeGetUser = shield({
//       purpose: "show_profile",
//       scope: ["name", "email"],
//     })(async function getUser(id: number) {
//       return await db.users.find(id); // returns { id, name, email, ssn, ... }
//     });
//
//     const u = await safeGetUser(123);
//     // u → { name: "...", email: "..." }
//
// Lite mode: in-process dict filter, zero infrastructure, zero runtime
// deps. Full mode: filter + audit chain via AegisClient (aegis-core).

// Core decorator surface.
export { shield, wrap, syncPolicies, refreshToken, reset } from "./shield.js";

// AI-native interposition layer (Layer 2 — the §8 product surface):
// per-tool-call gating, automatic capability propagation, managed
// continuous-authz sessions. Python parity: aegis_trust.ai_native.
export {
  guardTool,
  delegate,
  streamSession,
  currentCapability,
  type GuardToolOptions,
  type DelegateOptions,
  type StreamSessionOptions,
  type StreamSessionHandle,
} from "./aiNative.js";

// Machine-parseable error model (v0.9.0-rc1).
export {
  AegisError,
  AegisValidationError,
  AegisConfigError,
  AegisIngestError,
  AegisAuditError,
  AegisHttpError,
  AegisStreamDeniedError,
  AegisStreamRevokedError,
  aegisDocsUrl,
  type AegisErrorPayload,
} from "./errors.js";

// Trace context propagation (v0.9.0-rc1).
export {
  type TraceContext,
  withTraceContext,
  getTraceContext,
  newTraceId,
} from "./trace.js";

// Mode enum + types (parity with aegis.types).
export { Mode } from "./types.js";
export type {
  AccessPolicy,
  AuditChainStatus,
  AuditEntry,
  FieldStats,
  FunctionStats,
  IngestEntry,
  IngestResponse,
  PathTree,
  PolicySyncEntry,
  PolicySyncResponse,
  PurposeStats,
  ShieldOptions,
  ShieldResult,
  ShieldStats,
} from "./types.js";

// AegisClient (Full mode HTTP wrapper, parity with aegis.client).
export {
  AegisClient,
  type AegisClientOptions,
  type MetricsHook,
  setMetricsHook,
  getModuleClient,
  detectMode,
  resetModuleClient,
  isDevHost,
  normalizeBaseUrl,
  resolveVerifySsl,
  // userIntendsFull is the rc4-level intent heuristic (parity with PyPI
  // `_user_intends_full`). Re-exported in the barrel so the rc4 CHANGELOG
  // Migration recipe ("callers that import userIntendsFull directly from
  // aegis-trust") resolves against the public package surface. Without
  // this re-export, the Migration story is non-functional for npm
  // consumers (codex iter-1 cross-review P1 closure).
  userIntendsFull,
  // Doctor v1 (Core-backed) — boundary check wire types.
  type BoundaryDecisionView,
  type CoreBoundaryOutcome,
  type CoreDecisionEvidence,
  type CheckBoundaryArgs,
  type AttributionClaim,
  // AI-native `decision` object — typed, fail-closed reader (server-derived
  // fragment_tags / parts / decision_id / ledgered).
  AUTHORITY_OUTCOMES,
  parseAuthorityDecision,
  type AuthorityDecisionView,
  type BoundaryPartialView,
  // AI-native v1 (frozen contract: AI_NATIVE_V1_CONTRACT.md) — wire floor.
  type ToolCallArgs,
  type ToolCallResult,
  type CapabilityMintArgs,
  type CapabilityGrant,
  type StreamOpenResult,
  type StreamStatus,
} from "./client.js";

// Config (YAML loader, parity with aegis.config).
export {
  loadConfig,
  getPurposePolicy,
  resetConfig,
  type PurposeConfig,
  type PurposeConfigScope,
  type PurposeConfigDeny,
} from "./config.js";

// History (local audit store, parity with aegis.history).
export {
  HistoryStore,
  type HistoryRecord,
  type HistoryStats,
  recordIfEnabled,
  resetStore,
} from "./history.js";

// Vitest plugin (parity with aegis.pytest_plugin).
export {
  useShieldHistory,
  assertShieldBlocked,
  assertShieldPassed,
  type ShieldRecord,
  type ShieldHistoryHandle,
} from "./vitestPlugin.js";

export const VERSION = "0.11.0";

// Schema version for the audit event format emitted by HistoryStore and
// the ingest endpoint payload. Bumped when audit record shape changes.
// API versioning doctrine §2: SemVer for the package, schema_version for
// the on-disk / on-wire audit event shape (independent axis).
export { AUDIT_SCHEMA_VERSION } from "./constants.js";

// Stability level — see docs/VERSIONING.md.
//   "preview"  → v0.x.y-rc* : public API may change between rc tags.
//   "stable"   → v1+        : SemVer breaking change rules apply.
//   "deprecated" → marked for removal in next major.
export const STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "preview";

// Aegis-Api-Version dated header (Stripe-model dated API versioning) —
// single-sourced in constants.ts (client.ts uses the same definition; a
// second hardcoded literal there drifted-by-construction).
export { AEGIS_API_VERSION, AEGIS_API_VERSION_HEADER } from "./constants.js";

// Keyless (LITE) structural receipt verifier — gap 1, the consumer-side
// verification surface (parity with python aegis_trust.receipt_verify;
// cross-impl pinned vectors in tests/receiptVerify.test.ts).
export {
  LINEAGE_ROOT_LEN,
  SPAN_CRYPTO_SCHEMA_TAG,
  computeLineageRoot,
  danglingPriorReceiptRefs,
  isValueFreeLabel,
  sessionDagRoot,
  verifyLineageRoot,
  verifySessionReceiptStructure,
} from "./receiptVerify.js";

// Core attestation verification (S051 ③). The SDK verifies Core's statement
// about a disk; it never re-derives one of its own. See
// docs/ATTESTATION_VERIFY.md and aegis-boundary-core/docs/ATTESTATION_CONTRACT.md.
export {
  ALL_CHECKS,
  ATTEST_MESSAGE_PREFIX,
  EXIT_ABNORMAL,
  EXIT_CLEAN,
  EXIT_NO_REPORT,
  MAX_SAFE_INTEGER,
  STATE_SCHEMA,
  UNSIGNED_FIELDS,
  AttestFormatError,
  AttestStateError,
  advanceState,
  canonicalMessage,
  ed25519Verify,
  findingsDigest,
  loadState,
  parseAttestation,
  parseRfc3339Ms,
  reportArrivedCheck,
  saveState,
  stateFromJSON,
  stateToJSON,
  verifyAttestation,
  type AttestCheck,
  type AttestExpectation,
  type AttestSignature,
  type AttestState,
  type AttestVerdict,
  type Attestation,
  type CapsuleFinding,
  type ChainReport,
  type CheckOutcome,
} from "./attestVerify.js";
