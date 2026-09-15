// Verifier for Aegis Core attestations (S051 ③ — the SDK half), Node.
// Parity target: python/src/aegis_trust/attest_verify.py. Check identifiers,
// their order, and every detail string are byte-identical across the two SDKs,
// and conformance/attest_verify.v0.json is what holds them that way.
//
// Core **produces** an attestation; this module **verifies it and nothing
// else**. It never opens the capsule directory and never re-derives a verdict
// about what is on the disk. If it did, one disk would have two
// implementations answering one question, and the first time they disagreed a
// customer would be told two things about their own data. The wire contract is
// aegis-boundary-core/docs/ATTESTATION_CONTRACT.md.
//
// WHAT IS CHECKED (contract §4). Any single failure is an anomaly; the verifier
// does not weigh them against each other:
//
//   signature_present   an unsigned attestation is not a verified one
//   signature_valid     Ed25519 over the canonical message, rebuilt here
//   message_digest      message_sha256 describes the message that signed
//   signing_key         the signature is by the key this deployment pinned
//   host                the attestation is about the host that was pinned
//   nonce               the freshness challenge came back
//   freshness           generated_at is inside the expected window
//   core_abnormal       Core's own verdict is empty
//   chain_status        the ledger verified, rather than being absent
//   sequence_advanced   the ledger grew — see SILENCE below
//   chain_linked        it grew forward, rather than being rewritten
//   chain_identity      it is still the same ledger (genesis unchanged)
//   judged_nonzero      something was actually examined
//   payload_intact      no non-terminal capsule lost its body
//   metadata_consistent no capsule disagrees with its recorded state
//   inventory           the capsules you expected are the ones reported
//
// SILENCE IS THE FAILURE MODE THIS LAYER EXISTS FOR. A boundary that has
// stopped writing records produces an attestation that looks calm: nothing
// abnormal, chain valid, no losses. `sequence_advanced` is what turns "the same
// head as last time, again" into a finding instead of "no news", and
// `reportArrivedCheck` is what turns an attestation that never came at all into
// one. Neither can work without the previous observation, which is why
// `AttestState` is part of the API rather than an implementation detail.
//
// A CHECK THAT DID NOT RUN IS NOT A CHECK THAT PASSED. Every check reports
// pass / fail / skip with a reason, and `ok` is false when anything failed.
// Skips are carried in the verdict and printed by the CLI rather than folded
// into the green. S012 is why: a shipped verifier answered LEDGER OK and exit 0
// about evidence that did not exist.
//
// WHAT CORE DOES NOT CLAIM, AND THIS MODULE THEREFORE CANNOT (contract §6):
// decryptability (bodies are AEAD-sealed against the sealing host, so the
// attestation proves a body is present and non-empty, never that it opens), and
// completeness against an expected inventory (`judged` is what Core found;
// twenty capsules reduced to one reads `judged: 1` and is otherwise clean).
// The second is why `AttestExpectation.capsuleIds` exists — and why leaving it
// unset makes `inventory` report `skip`, never `pass`.
//
// WHAT THE SIGNATURE DOES NOT COVER. Exactly one field an operator reads sits
// outside the canonical message: `signature.key_id`. It is a label, and the key
// itself is what authenticates, so pinning it with `AttestExpectation.keyId`
// catches an honest misconfiguration — a rotation that moved the key without the
// label, or the reverse — and catches nothing an attacker does, because an
// attacker who is rewriting the document can set the label to whatever is
// expected. That limit is stated here rather than implied, and pinned by the
// `key-id-is-outside-the-signature` corpus case.
//
// `records_checked`, `first_break` and `skipped_non_capsule` were outside it in
// the first draft of the contract, which this verifier reported during §8.2 —
// none of the three could manufacture false safety, since `judged` and the
// findings digest were already signed, but `skipped_non_capsule` is the only
// window onto what was NOT counted, and blanking it hid "nineteen files were
// skipped" while verification still succeeded. Core moved all three inside the
// message, so rewriting any of them now breaks the signature.
//
// DECLARED ASYMMETRY WITH THE PYTHON SDK (undeclared asymmetry is how two SDKs
// stop being the same product). A count written as `4.0` instead of `4` is
// accepted here and rejected there, because `JSON.parse` cannot tell the two
// apart. The verdict is the same either way — `4.0` renders into the canonical
// message as `4`, so the signature decides — and the shared corpus therefore
// carries no such vector. Both SDKs refuse integers above MAX_SAFE_INTEGER so
// that the case where the rendering would genuinely differ is rejected
// identically instead.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { ed25519Verify } from "./ed25519.js";

export { ed25519Verify };

export const ATTEST_MESSAGE_PREFIX = "aegis-attest-v1";
export const STATE_SCHEMA = "aegis-attest-verifier-state.v1";

/**
 * Exit codes, contract §5. `EXIT_NO_REPORT` is deliberately distinct from
 * `EXIT_ABNORMAL`: "I could not report" is not "I found problems", and
 * collapsing them means a broken invocation pages the same person as a broken
 * deployment.
 */
export const EXIT_CLEAN = 0;
export const EXIT_ABNORMAL = 1;
export const EXIT_NO_REPORT = 2;

/**
 * The largest integer JavaScript represents exactly. Both SDKs refuse counts
 * above it: this one cannot tell 2**53+1 from 2**53+2 after `JSON.parse`, so it
 * would render a different decimal into the canonical message than the one Core
 * signed and report a forgery. Refusing in both places keeps the two SDKs
 * answering the same thing, at the cost of a ledger limit no real deployment
 * reaches.
 */
export const MAX_SAFE_INTEGER = 9007199254740991;

/**
 * The document fields the canonical message does NOT cover — the receptacle for
 * "which parts of what a reader is looking at are merely claims".
 *
 * It held three members until Core moved them in (`records_checked`,
 * `first_break`, `skipped_non_capsule`), which this verifier reported during
 * §8.2: none of the three could manufacture false safety, since `judged` and the
 * findings digest were already signed, but `skipped_non_capsule` was the only
 * window onto what was NOT counted and blanking it hid "nineteen files were
 * skipped" while verification still succeeded.
 *
 * What remains is the key label. It is a label — the key itself is what
 * authenticates — so pinning it with `AttestExpectation.keyId` catches a
 * rotation that moved the key without the label, and catches nothing an
 * attacker does, because an attacker rewriting the document can set the label to
 * whatever is expected.
 *
 * This is not a comment: "the signature covers everything else" mutates every
 * other field in a signed attestation and requires the signature to break, and
 * mutates these and requires it to hold. A contract change that takes a field
 * out of the message without updating this list fails there.
 */
export const UNSIGNED_FIELDS = ["signature.key_id"] as const;

// Check identifiers. Stable strings: they are what a caller branches on and
// what the conformance corpus pins, so they are part of the contract.
export const CHECK_DOCUMENT = "document";
export const CHECK_SIGNATURE_PRESENT = "signature_present";
export const CHECK_SIGNATURE_VALID = "signature_valid";
export const CHECK_MESSAGE_DIGEST = "message_digest";
export const CHECK_SIGNING_KEY = "signing_key";
export const CHECK_HOST = "host";
export const CHECK_NONCE = "nonce";
export const CHECK_FRESHNESS = "freshness";
export const CHECK_CORE_ABNORMAL = "core_abnormal";
export const CHECK_CHAIN_STATUS = "chain_status";
export const CHECK_SEQUENCE_ADVANCED = "sequence_advanced";
export const CHECK_CHAIN_LINKED = "chain_linked";
export const CHECK_CHAIN_IDENTITY = "chain_identity";
export const CHECK_JUDGED_NONZERO = "judged_nonzero";
export const CHECK_PAYLOAD_INTACT = "payload_intact";
export const CHECK_METADATA_CONSISTENT = "metadata_consistent";
export const CHECK_INVENTORY = "inventory";
export const CHECK_REPORT_ARRIVED = "report_arrived";

/**
 * Every check `verifyAttestation` can report, in the order it reports them. A
 * caller can assert against this list to notice a check that silently stopped
 * being emitted.
 */
export const ALL_CHECKS = [
  CHECK_DOCUMENT,
  CHECK_SIGNATURE_PRESENT,
  CHECK_SIGNATURE_VALID,
  CHECK_MESSAGE_DIGEST,
  CHECK_SIGNING_KEY,
  CHECK_HOST,
  CHECK_NONCE,
  CHECK_FRESHNESS,
  CHECK_CORE_ABNORMAL,
  CHECK_CHAIN_STATUS,
  CHECK_SEQUENCE_ADVANCED,
  CHECK_CHAIN_LINKED,
  CHECK_CHAIN_IDENTITY,
  CHECK_JUDGED_NONZERO,
  CHECK_PAYLOAD_INTACT,
  CHECK_METADATA_CONSISTENT,
  CHECK_INVENTORY,
] as const;

/**
 * The document is not an attestation. Thrown by `parseAttestation` for a
 * missing or wrongly typed field. Nothing is coerced: a `judged` of `"4"` is
 * not a 4, because the string and the number do not render into the canonical
 * message the same way, and silently picking one would mean verifying a
 * signature over a message Core never produced.
 *
 * Carries the same message text as Python's `AttestFormatError` so failures
 * grep identically across SDKs.
 */
export class AttestFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestFormatError";
  }
}

/**
 * The stored previous observation exists but cannot be read. Distinct from
 * "there is no previous observation": treating a corrupt state file as a fresh
 * start is the bypass for the whole silence check — delete the file and
 * `sequence_advanced` skips forever.
 */
export class AttestStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestStateError";
  }
}

export type CheckOutcome = "pass" | "fail" | "skip";

export interface AttestCheck {
  check: string;
  outcome: CheckOutcome;
  detail: string;
}

// --------------------------------------------------------------------------
// The document, read strictly.
// --------------------------------------------------------------------------

/**
 * The JSON type name of a parsed value. Deliberately the JSON vocabulary rather
 * than the host language's: Python would say str/dict/NoneType where this would
 * say string/object/null, and the two SDKs would then produce different text
 * for the same malformed document.
 */
function jsonType(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "object";
  return "unknown";
}

/**
 * Quote a value for a human-readable detail line. Plain and identical in both
 * SDKs — Python's `repr` would not be (it renders `None` where JavaScript
 * renders `null`, and escapes differently).
 */
function q(value: unknown): string {
  return value === null || value === undefined ? "none" : `'${String(value)}'`;
}

/**
 * Render a duration for a detail line, truncated toward zero. Truncation rather
 * than rounding because Python's `:.0f` rounds halves to even and `toFixed(0)`
 * rounds them away from zero, so the two SDKs would print different sentences
 * for the same attestation at exactly .5 seconds.
 */
function secs(value: number): string {
  return String(Math.trunc(value));
}

/**
 * Python sorts strings by Unicode CODE POINT; the JS default sort compares
 * UTF-16 CODE UNITS, and the two orders diverge when an astral character is
 * compared against a BMP character in [U+E000, U+FFFF]. Capsule ids are
 * attacker-influenced text, so the inventory finding sorts by code point to
 * match Python byte for byte. (Same helper as node/src/receiptVerify.ts, kept
 * module-private there.)
 */
function codePointCompare(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca - cb;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  return a.length - i - (b.length - j);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown, where: string, allowNull = false): string | null {
  if ((value === null || value === undefined) && allowNull) return null;
  if (typeof value !== "string") {
    throw new AttestFormatError(`${where}: expected a string, got ${jsonType(value)}`);
  }
  return value;
}

function asUint(value: unknown, where: string, allowNull = false): number | null {
  if ((value === null || value === undefined) && allowNull) return null;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new AttestFormatError(`${where}: expected an integer, got ${jsonType(value)}`);
  }
  if (value < 0) {
    throw new AttestFormatError(
      `${where}: expected a non-negative integer, got ${value}`,
    );
  }
  if (value > MAX_SAFE_INTEGER) {
    throw new AttestFormatError(
      `${where}: ${value} is above the ${MAX_SAFE_INTEGER} both SDKs can render identically`,
    );
  }
  return value;
}

function asBool(value: unknown, where: string, dflt?: boolean): boolean {
  if ((value === null || value === undefined) && dflt !== undefined) return dflt;
  if (typeof value !== "boolean") {
    throw new AttestFormatError(`${where}: expected a boolean, got ${jsonType(value)}`);
  }
  return value;
}

function asStringList(value: unknown, where: string): string[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new AttestFormatError(`${where}: expected an array, got ${jsonType(value)}`);
  }
  return value.map((item, i) => {
    if (typeof item !== "string") {
      throw new AttestFormatError(
        `${where}[${i}]: expected a string, got ${jsonType(item)}`,
      );
    }
    return item;
  });
}

/** What the attestation found about one capsule. `claimedState` is a claim the
 * capsule makes about itself, never a verdict. */
export interface CapsuleFinding {
  capsuleId: string;
  claimedState: string;
  payloadPresent: boolean;
  payloadBytes: number | null;
  issue: string | null;
  terminal: boolean;
}

/** The ledger half. `recordsChecked` and `firstBreak` are outside the signature
 * (see UNSIGNED_FIELDS) and drive no verdict. */
export interface ChainReport {
  status: string;
  recordsChecked: number;
  lastSeq: number;
  currHash: string;
  genesisAnchor: string;
  firstBreak: string | null;
}

export interface AttestSignature {
  keyId: string;
  publicKeyHex: string;
  signatureHex: string;
  messageSha256: string;
}

/** One attestation, read from the wire without coercion. */
export interface Attestation {
  generatedAt: string;
  hostFingerprint: string;
  capsuleRoot: string;
  nonce: string | null;
  judged: number;
  payloadMissing: number;
  inconsistent: number;
  skippedNonCapsule: string[];
  findings: CapsuleFinding[];
  chain: ChainReport;
  selfLimitTripped: string | null;
  abnormal: string[];
  signature: AttestSignature | null;
}

function parseFinding(raw: unknown, where: string): CapsuleFinding {
  if (!isObject(raw)) throw new AttestFormatError(`${where}: expected an object`);
  return {
    capsuleId: asString(raw["capsule_id"], `${where}.capsule_id`) as string,
    claimedState: asString(raw["claimed_state"], `${where}.claimed_state`) as string,
    payloadPresent: asBool(raw["payload_present"], `${where}.payload_present`),
    payloadBytes: asUint(raw["payload_bytes"], `${where}.payload_bytes`, true),
    issue: asString(raw["issue"], `${where}.issue`, true),
    // `#[serde(default)]` on the Rust side: an older attestation without the
    // field means false, and must digest as false.
    terminal: asBool(raw["terminal"], `${where}.terminal`, false),
  };
}

function parseChain(raw: unknown): ChainReport {
  if (!isObject(raw)) throw new AttestFormatError("chain: expected an object");
  return {
    status: asString(raw["status"], "chain.status") as string,
    recordsChecked: asUint(raw["records_checked"], "chain.records_checked") as number,
    lastSeq: asUint(raw["last_seq"], "chain.last_seq") as number,
    // serde(default) = "" — the default applies to an ABSENT key only.
    // `?? ""` would also swallow an explicit `"curr_hash": null`, which
    // Python refuses; a null head hash has to be refused by both SDKs.
    currHash: asString(
      "curr_hash" in raw ? raw["curr_hash"] : "",
      "chain.curr_hash",
    ) as string,
    genesisAnchor: asString(raw["genesis_anchor"], "chain.genesis_anchor") as string,
    firstBreak: asString(raw["first_break"], "chain.first_break", true),
  };
}

function parseSignature(raw: unknown): AttestSignature {
  if (!isObject(raw)) throw new AttestFormatError("signature: expected an object");
  return {
    keyId: asString(raw["key_id"], "signature.key_id") as string,
    publicKeyHex: asString(raw["public_key_hex"], "signature.public_key_hex") as string,
    signatureHex: asString(raw["signature_hex"], "signature.signature_hex") as string,
    messageSha256: asString(raw["message_sha256"], "signature.message_sha256") as string,
  };
}

/**
 * Read a JSON-shaped attestation. Throws `AttestFormatError` when a field is
 * absent or the wrong type.
 */
export function parseAttestation(document: unknown): Attestation {
  if (!isObject(document)) {
    throw new AttestFormatError("attestation: expected a JSON object");
  }
  const rawFindings = document["findings"];
  if (!Array.isArray(rawFindings)) {
    throw new AttestFormatError(
      `findings: expected an array, got ${jsonType(rawFindings)}`,
    );
  }
  return {
    generatedAt: asString(document["generated_at"], "generated_at") as string,
    hostFingerprint: asString(document["host_fingerprint"], "host_fingerprint") as string,
    capsuleRoot: asString(document["capsule_root"], "capsule_root") as string,
    nonce: asString(document["nonce"], "nonce", true),
    judged: asUint(document["judged"], "judged") as number,
    payloadMissing: asUint(document["payload_missing"], "payload_missing") as number,
    inconsistent: asUint(document["inconsistent"], "inconsistent") as number,
    skippedNonCapsule: asStringList(
      document["skipped_non_capsule"],
      "skipped_non_capsule",
    ),
    findings: rawFindings.map((f, i) => parseFinding(f, `findings[${i}]`)),
    chain: parseChain(document["chain"]),
    selfLimitTripped: asString(document["self_limit_tripped"], "self_limit_tripped", true),
    abnormal: asStringList(document["abnormal"], "abnormal"),
    signature:
      document["signature"] === null || document["signature"] === undefined
        ? null
        : parseSignature(document["signature"]),
  };
}

// --------------------------------------------------------------------------
// The signed message (contract §3).
// --------------------------------------------------------------------------

/**
 * SHA-256, lowercase hex, over every finding in the order given.
 *
 * Each of the six parts is fed as an 8-byte little-endian length followed by
 * the UTF-8 bytes. The prefix is not decoration: with plain concatenation
 * ("ab", "c") and ("a", "bc") hash identically, which is how a rewritten
 * capsule id hides inside an issue string.
 *
 * The length is a count of BYTES, matching Rust's `str::len()` — hence
 * `Buffer.byteLength`, not `String.length`. A capsule id outside ASCII is where
 * a UTF-16 unit count would silently diverge, so the conformance corpus carries
 * one.
 */
export function findingsDigest(findings: readonly CapsuleFinding[]): string {
  const h = createHash("sha256");
  for (const f of findings) {
    const parts = [
      f.capsuleId,
      f.claimedState,
      f.payloadPresent ? "present" : "absent",
      f.terminal ? "terminal" : "live",
      f.payloadBytes === null ? "" : String(f.payloadBytes),
      f.issue === null ? "" : f.issue,
    ];
    for (const part of parts) {
      const encoded = Buffer.from(part, "utf8");
      const length = Buffer.alloc(8);
      length.writeBigUInt64LE(BigInt(encoded.length));
      h.update(length);
      h.update(encoded);
    }
  }
  return h.digest("hex");
}

/**
 * The exact string Core signed (contract §3).
 *
 * Rebuilt field by field rather than by re-serializing the JSON: a signature
 * over a re-serialized document breaks the moment either side changes a
 * serializer, and the break looks like a forgery.
 */
export function canonicalMessage(att: Attestation): string {
  return (
    `${ATTEST_MESSAGE_PREFIX}\n`
    + `generated_at=${att.generatedAt}\n`
    + `host=${att.hostFingerprint}\n`
    + `root=${att.capsuleRoot}\n`
    + `nonce=${att.nonce ?? ""}\n`
    + `judged=${att.judged}\n`
    + `payload_missing=${att.payloadMissing}\n`
    + `inconsistent=${att.inconsistent}\n`
    + `chain_status=${att.chain.status}\n`
    + `chain_last_seq=${att.chain.lastSeq}\n`
    + `chain_curr_hash=${att.chain.currHash}\n`
    + `chain_genesis=${att.chain.genesisAnchor}\n`
    + `chain_records_checked=${att.chain.recordsChecked}\n`
    + `chain_first_break=${att.chain.firstBreak ?? ""}\n`
    + `skipped_non_capsule=${att.skippedNonCapsule.join(",")}\n`
    + `self_limit=${att.selfLimitTripped ?? ""}\n`
    + `findings_sha256=${findingsDigest(att.findings)}\n`
    + `abnormal=${att.abnormal.join(";")}\n`
  );
}

// --------------------------------------------------------------------------
// What this deployment expects, and what it last saw.
// --------------------------------------------------------------------------

/**
 * What a healthy attestation for *this* deployment must look like.
 *
 * `publicKeyHex` and `hostFingerprint` are required and have no defaults. A
 * verifier that accepted whatever key signed the document would be checking
 * that an attacker can use Ed25519.
 */
export interface AttestExpectation {
  publicKeyHex: string;
  hostFingerprint: string;
  /**
   * The challenge that was sent with the request. `null` means none was sent,
   * which is reported as a failure unless `allowUnchallenged` says the caller
   * accepted that risk knowingly: without a nonce, an attestation taken before
   * the data went missing replays perfectly.
   */
  nonce?: string | null;
  allowUnchallenged?: boolean;
  /** Optional label pin. The key is what authenticates; this catches a key
   * rotation that changed the label without changing the key, or vice versa. */
  keyId?: string | null;
  maxAgeSeconds?: number;
  /** How far ahead of local time `generatedAt` may sit before it is read as a
   * forged timestamp rather than clock skew between two honest machines. */
  maxClockSkewSeconds?: number;
  /** The capsules this deployment believes exist. Core does not hold an
   * expected inventory (contract §6), so when this is absent the `inventory`
   * check reports `skip` — never `pass`. */
  capsuleIds?: readonly string[] | null;
  /** Refuse to verify without a previous observation. A deployment past its
   * first attestation should set this: with no baseline the silence check
   * cannot run, so deleting the state file is otherwise a way to make it skip
   * forever. */
  requirePrevious?: boolean;
}

/** The previous observation — the only thing that makes silence visible. */
export interface AttestState {
  hostFingerprint: string;
  publicKeyHex: string;
  lastSeq: number;
  currHash: string;
  genesisAnchor: string;
  generatedAt: string;
  observations: number;
  /** How many times a deliberate ledger reset has been acknowledged.
   * Counted rather than forgotten: an operator asserting "this rotation was
   * mine" is making a claim the SDK cannot verify, so the claim is kept. */
  ledgerResets: number;
}

export function stateToJSON(state: AttestState): Record<string, unknown> {
  return {
    schema: STATE_SCHEMA,
    host_fingerprint: state.hostFingerprint,
    public_key_hex: state.publicKeyHex,
    last_seq: state.lastSeq,
    curr_hash: state.currHash,
    genesis_anchor: state.genesisAnchor,
    generated_at: state.generatedAt,
    observations: state.observations,
    ledger_resets: state.ledgerResets,
  };
}

export function stateFromJSON(raw: unknown): AttestState {
  if (!isObject(raw)) throw new AttestStateError("state: expected a JSON object");
  const schema = raw["schema"];
  if (schema !== STATE_SCHEMA) {
    throw new AttestStateError(
      `state: schema is ${q(schema)}, expected ${q(STATE_SCHEMA)}`,
    );
  }
  try {
    return {
      hostFingerprint: asString(raw["host_fingerprint"], "state.host_fingerprint") as string,
      publicKeyHex: asString(raw["public_key_hex"], "state.public_key_hex") as string,
      lastSeq: asUint(raw["last_seq"], "state.last_seq") as number,
      currHash: asString(raw["curr_hash"], "state.curr_hash") as string,
      genesisAnchor: asString(raw["genesis_anchor"], "state.genesis_anchor") as string,
      generatedAt: asString(raw["generated_at"], "state.generated_at") as string,
      observations: asUint(raw["observations"], "state.observations") as number,
      // Optional: a state written before resets could be acknowledged
      // simply has not had one.
      ledgerResets: asUint(raw["ledger_resets"] ?? 0, "state.ledger_resets") as number,
    };
  } catch (err) {
    throw new AttestStateError(err instanceof Error ? err.message : String(err));
  }
}

/**
 * Read the previous observation.
 *
 * Returns `null` ONLY when the file does not exist. A file that exists and
 * cannot be read throws `AttestStateError` instead of degrading to "no previous
 * observation": the degradation is the bypass — corrupt the file and the
 * silence check skips every run while the report stays green.
 */
export function loadState(path: string): AttestState | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new AttestStateError(
      `state file ${path} exists but could not be read: ${String(err)}`,
    );
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new AttestStateError(
      `state file ${path} exists but could not be read: ${String(err)}`,
    );
  }
  return stateFromJSON(raw);
}

/** Write the observation to compare the next attestation against. */
export function saveState(path: string, state: AttestState): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(stateToJSON(state), null, 2) + "\n", "utf8");
}

// --------------------------------------------------------------------------
// Time.
// --------------------------------------------------------------------------

/**
 * RFC3339 with a mandatory offset. Written out rather than handed to
 * `Date.parse`, which accepts a great deal that is not RFC3339 (and differs
 * between engines) — the two SDKs must agree on what a valid timestamp is.
 */
const RFC3339_RE =
  /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * Milliseconds since the epoch for an RFC3339 timestamp. Milliseconds, not
 * microseconds, because this clock has no finer resolution and the two SDKs
 * must describe the same attestation with the same sentence. `chrono` emits up
 * to 9 fractional digits; the extra ones are truncated rather than rounded,
 * identically on both sides.
 */
export function parseRfc3339Ms(value: string): number {
  const m = RFC3339_RE.exec(value.trim());
  if (m === null) {
    throw new RangeError(`${q(value)} is not an RFC3339 timestamp with an offset`);
  }
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map((s) => parseInt(s, 10));
  const fraction = m[7] ?? "";
  const offset = m[8];

  // setUTCFullYear rather than Date.UTC: the latter maps years 0-99 into the
  // 1900s. The round-trip check is how an impossible date (2026-02-30) is
  // refused here, which is what Python's datetime() raises on.
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, 0);
  if (
    d.getUTCFullYear() !== year
    || d.getUTCMonth() !== month - 1
    || d.getUTCDate() !== day
    || d.getUTCHours() !== hour
    || d.getUTCMinutes() !== minute
    || d.getUTCSeconds() !== second
  ) {
    throw new RangeError(`${q(value)} is not an RFC3339 timestamp with an offset`);
  }

  const fracMs = fraction ? parseInt((fraction.slice(1) + "000").slice(0, 3), 10) : 0;
  let offsetMinutes = 0;
  if (offset !== "Z" && offset !== "z") {
    const sign = offset[0] === "+" ? 1 : -1;
    offsetMinutes = sign * (parseInt(offset.slice(1, 3), 10) * 60 + parseInt(offset.slice(4, 6), 10));
  }
  return d.getTime() + fracMs - offsetMinutes * 60_000;
}

function nowMs(now?: Date): number {
  return now === undefined ? Date.now() : now.getTime();
}

// --------------------------------------------------------------------------
// The verdict.
// --------------------------------------------------------------------------

/** The result of verifying one attestation. */
export interface AttestVerdict {
  checks: AttestCheck[];
  signatureVerified: boolean;
  /** The observation to carry into the next verification, or `null` when the
   * document did not earn the right to move the baseline. */
  nextState: AttestState | null;
  /** The checks that failed. Empty means nothing failed. */
  findings: AttestCheck[];
  /** The checks that could not run. Never counted as clean. */
  skipped: AttestCheck[];
  ok: boolean;
  /** `0` clean / `1` abnormal. Never `2`: this verdict exists, so a report was
   * produced. `2` belongs to the caller that could not obtain one at all. */
  exitCode: number;
}

function buildVerdict(
  checks: AttestCheck[],
  signatureVerified: boolean,
  nextState: AttestState | null,
): AttestVerdict {
  const findings = checks.filter((c) => c.outcome === "fail");
  return {
    checks,
    signatureVerified,
    nextState,
    findings,
    skipped: checks.filter((c) => c.outcome === "skip"),
    ok: findings.length === 0,
    exitCode: findings.length === 0 ? EXIT_CLEAN : EXIT_ABNORMAL,
  };
}

function hexBytes(value: string, expectedLen: number): Buffer | null {
  // Buffer.from(hex) stops silently at the first non-hex character, so the
  // syntax is checked before the length: without this, "zz" decodes to an empty
  // buffer and a caller that only looked at the length would see a length
  // error for what is really garbage.
  if (!/^[0-9a-fA-F]*$/.test(value) || value.length !== expectedLen * 2) return null;
  return Buffer.from(value, "hex");
}

/**
 * Verify one attestation against what this deployment expects.
 *
 * `previous` is the last verified observation (see `loadState`). Without it the
 * silence checks report `skip`, which is why `requirePrevious` exists.
 *
 * The content checks run ONLY when the signature verifies. On a document that
 * is unsigned or forged they report `skip`, not `pass`: their answers would be
 * about text an attacker chose, and "9 of 11 checks passed" on a forged
 * document is a sentence no operator should ever be shown.
 */
export function verifyAttestation(
  document: unknown,
  expect: AttestExpectation,
  previous: AttestState | null = null,
  options: { now?: Date } = {},
): AttestVerdict {
  const checks: AttestCheck[] = [];
  const currentMs = nowMs(options.now);
  const expectNonce = expect.nonce ?? null;
  const maxAge = expect.maxAgeSeconds ?? 3600;
  const maxSkew = expect.maxClockSkewSeconds ?? 60;

  const add = (check: string, outcome: CheckOutcome, detail: string): void => {
    checks.push({ check, outcome, detail });
  };

  const skipRest = (reason: string, fromIndex: number): AttestVerdict => {
    for (const name of ALL_CHECKS.slice(fromIndex)) {
      add(name, "skip", reason);
    }
    return buildVerdict(checks, false, null);
  };

  // 1. Is this an attestation at all?
  let att: Attestation;
  try {
    att = parseAttestation(document);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    add(CHECK_DOCUMENT, "fail", `not a readable attestation: ${message}`);
    return skipRest("the document could not be read as an attestation", 1);
  }
  add(CHECK_DOCUMENT, "pass", "the document has the shape of an attestation");

  // 2. Signature. "No key configured" is not "nothing to check".
  if (att.signature === null) {
    add(
      CHECK_SIGNATURE_PRESENT,
      "fail",
      "the attestation is unsigned — an unsigned statement is not a verified one",
    );
    return skipRest("the attestation carries no signature", 2);
  }
  add(CHECK_SIGNATURE_PRESENT, "pass", `signed, key_id=${q(att.signature.keyId)}`);

  const message = canonicalMessage(att);
  const messageBytes = Buffer.from(message, "utf8");
  const publicKey = hexBytes(att.signature.publicKeyHex, 32);
  const signature = hexBytes(att.signature.signatureHex, 64);

  if (publicKey === null || signature === null) {
    add(
      CHECK_SIGNATURE_VALID,
      "fail",
      "public_key_hex must be 32 bytes of hex and signature_hex 64",
    );
    return skipRest("the signature material is malformed", 3);
  }

  if (!ed25519Verify(publicKey, messageBytes, signature)) {
    add(
      CHECK_SIGNATURE_VALID,
      "fail",
      "the signature does not verify over the canonical message rebuilt from this document",
    );
    return skipRest("the signature does not verify", 3);
  }
  add(CHECK_SIGNATURE_VALID, "pass", "Ed25519 over the canonical message");

  // 3. From here the content is authenticated, so a finding about it means
  //    something.
  const actualDigest = createHash("sha256").update(messageBytes).digest("hex");
  if (att.signature.messageSha256 !== actualDigest) {
    add(
      CHECK_MESSAGE_DIGEST,
      "fail",
      `message_sha256 says ${att.signature.messageSha256} but the signed message hashes to ${actualDigest}`,
    );
  } else {
    add(CHECK_MESSAGE_DIGEST, "pass", "message_sha256 matches the signed message");
  }

  const expectedKey = expect.publicKeyHex.trim().toLowerCase();
  const presentedKey = att.signature.publicKeyHex.trim().toLowerCase();
  if (presentedKey !== expectedKey) {
    add(
      CHECK_SIGNING_KEY,
      "fail",
      `signed by ${presentedKey}, expected ${expectedKey} — a valid signature by an unexpected key is an attacker with a key`,
    );
  } else if (
    expect.keyId !== undefined
    && expect.keyId !== null
    && att.signature.keyId !== expect.keyId
  ) {
    add(
      CHECK_SIGNING_KEY,
      "fail",
      `key_id is ${q(att.signature.keyId)}, expected ${q(expect.keyId)}`,
    );
  } else {
    add(CHECK_SIGNING_KEY, "pass", "signed by the pinned key");
  }

  if (att.hostFingerprint !== expect.hostFingerprint) {
    add(
      CHECK_HOST,
      "fail",
      `attestation is about ${att.hostFingerprint}, this deployment is pinned to ${expect.hostFingerprint} — an attestation about another machine is not about your data`,
    );
  } else {
    add(CHECK_HOST, "pass", `about ${att.hostFingerprint}`);
  }

  if (expectNonce !== null) {
    if (att.nonce !== expectNonce) {
      add(
        CHECK_NONCE,
        "fail",
        `nonce is ${q(att.nonce)}, the challenge sent was ${q(expectNonce)}`,
      );
    } else {
      add(CHECK_NONCE, "pass", "the challenge came back");
    }
  } else if (expect.allowUnchallenged) {
    add(
      CHECK_NONCE,
      "skip",
      "no freshness challenge was issued (allow_unchallenged); a replayed attestation is excluded by generated_at and the chain head alone",
    );
  } else {
    add(
      CHECK_NONCE,
      "fail",
      "no freshness challenge was issued, so this attestation cannot be distinguished from one taken before the data went missing; set allow_unchallenged to accept that knowingly",
    );
  }

  try {
    const generatedMs = parseRfc3339Ms(att.generatedAt);
    const age = (currentMs - generatedMs) / 1000;
    if (age > maxAge) {
      add(
        CHECK_FRESHNESS,
        "fail",
        `generated ${secs(age)}s ago, older than the ${secs(maxAge)}s window`,
      );
    } else if (-age > maxSkew) {
      add(
        CHECK_FRESHNESS,
        "fail",
        `generated ${secs(-age)}s in the future, beyond the ${secs(maxSkew)}s skew allowance`,
      );
    } else {
      add(CHECK_FRESHNESS, "pass", `generated ${secs(age)}s ago`);
    }
  } catch (err) {
    const message_ = err instanceof Error ? err.message : String(err);
    add(CHECK_FRESHNESS, "fail", `generated_at is unreadable: ${message_}`);
  }

  if (att.abnormal.length > 0) {
    add(CHECK_CORE_ABNORMAL, "fail", "Core reported: " + att.abnormal.join("; "));
  } else {
    add(CHECK_CORE_ABNORMAL, "pass", "Core reported nothing abnormal");
  }

  // Contract §4: `valid` means every record in the inspected range linked and
  // rehashed — and an EMPTY ledger is valid, a genuine zero-record chain.
  // `records_checked` is how a caller tells those apart, and it is inside the
  // signed message (it was not, until this verifier reported that), so it can be
  // relied on. The consequence is pinned as a corpus case rather than silently
  // accepted: a deployment holding capsules whose ledger has never recorded
  // anything verifies clean on a FIRST observation. From the second,
  // `sequence_advanced` catches it, because the head does not move.
  if (att.chain.status !== "valid") {
    add(
      CHECK_CHAIN_STATUS,
      "fail",
      `audit chain status is ${q(att.chain.status)}, not 'valid' — absent is not intact`,
    );
  } else {
    add(CHECK_CHAIN_STATUS, "pass", "the audit chain verified");
  }

  // 4. Silence. The check this whole layer exists for.
  if (previous === null) {
    if (expect.requirePrevious) {
      const reason =
        "no previous observation, and require_previous is set — a deployment past its first attestation must have a baseline, or deleting the state file silences the silence check";
      add(CHECK_SEQUENCE_ADVANCED, "fail", reason);
      add(CHECK_CHAIN_LINKED, "fail", reason);
      add(CHECK_CHAIN_IDENTITY, "fail", reason);
    } else {
      const reason =
        "first attestation for this deployment — there is nothing to compare against, so silence cannot be ruled out yet";
      add(CHECK_SEQUENCE_ADVANCED, "skip", reason);
      add(CHECK_CHAIN_LINKED, "skip", reason);
      add(CHECK_CHAIN_IDENTITY, "skip", reason);
    }
  } else {
    if (att.chain.lastSeq > previous.lastSeq) {
      add(
        CHECK_SEQUENCE_ADVANCED,
        "pass",
        `ledger head moved ${previous.lastSeq} -> ${att.chain.lastSeq}`,
      );
    } else if (att.chain.lastSeq === previous.lastSeq) {
      add(
        CHECK_SEQUENCE_ADVANCED,
        "fail",
        `the ledger head is still ${att.chain.lastSeq} — the same head as last time, again. A boundary that has stopped recording reports exactly this: nothing abnormal, chain valid, no losses`,
      );
    } else {
      add(
        CHECK_SEQUENCE_ADVANCED,
        "fail",
        `the ledger head went backwards, ${previous.lastSeq} -> ${att.chain.lastSeq} — the ledger was truncated or replaced`,
      );
    }

    if (att.chain.currHash && att.chain.currHash === previous.currHash) {
      add(
        CHECK_CHAIN_LINKED,
        "fail",
        `the head hash is unchanged at ${att.chain.currHash} — the ledger did not grow forward`,
      );
    } else if (!att.chain.currHash) {
      add(
        CHECK_CHAIN_LINKED,
        "fail",
        "the attestation reports no head hash, so growth cannot be told from a rewrite to the same length",
      );
    } else {
      add(CHECK_CHAIN_LINKED, "pass", "a new head hash at a new height");
    }

    if (previous.genesisAnchor && att.chain.genesisAnchor !== previous.genesisAnchor) {
      add(
        CHECK_CHAIN_IDENTITY,
        "fail",
        `genesis anchor changed from ${previous.genesisAnchor} to ${att.chain.genesisAnchor} — this is a different ledger, not a longer one`,
      );
    } else {
      add(CHECK_CHAIN_IDENTITY, "pass", "same ledger as last time");
    }
  }

  if (att.judged === 0) {
    add(
      CHECK_JUDGED_NONZERO,
      "fail",
      "judged 0 capsules — an attestation over nothing cannot distinguish 'intact' from 'not looked at'",
    );
  } else {
    add(CHECK_JUDGED_NONZERO, "pass", `judged ${att.judged} capsule(s)`);
  }

  // The two signed loss counts, judged here rather than taken from Core's
  // verdict. Both are inside the canonical message, so reading them costs
  // nothing and removes a dependency: without these, a capsule with a real
  // problem reached this verdict only because Core had also written a line into
  // `abnormal`.
  if (att.payloadMissing) {
    add(
      CHECK_PAYLOAD_INTACT,
      "fail",
      `${att.payloadMissing} capsule(s) have no payload on disk. A terminal capsule with no body is correct and is not counted here, so this is loss rather than erasure`,
    );
  } else {
    add(CHECK_PAYLOAD_INTACT, "pass", "every non-terminal capsule examined had a body");
  }

  if (att.inconsistent) {
    add(
      CHECK_METADATA_CONSISTENT,
      "fail",
      `${att.inconsistent} capsule(s) disagree with their recorded state. The per-capsule reason is in findings[].issue, which the signature covers`,
    );
  } else {
    add(CHECK_METADATA_CONSISTENT, "pass", "no capsule disagreed with its recorded state");
  }

  const expectedCapsules = expect.capsuleIds ?? null;
  if (expectedCapsules === null) {
    add(
      CHECK_INVENTORY,
      "skip",
      "no expected capsule set was supplied; Core does not hold one (contract §6), so nothing here can tell 20 capsules reduced to 1 from a deployment that only ever had 1",
    );
  } else {
    const reported = new Set(att.findings.map((f) => f.capsuleId));
    const expectedSet = new Set(expectedCapsules);
    const missing = [...expectedSet].filter((c) => !reported.has(c)).sort(codePointCompare);
    const unexpected = [...reported].filter((c) => !expectedSet.has(c)).sort(codePointCompare);
    if (missing.length > 0 || unexpected.length > 0) {
      const parts: string[] = [];
      if (missing.length > 0) parts.push(`expected but not reported: ${missing.join(", ")}`);
      if (unexpected.length > 0) {
        parts.push(`reported but not expected: ${unexpected.join(", ")}`);
      }
      add(CHECK_INVENTORY, "fail", parts.join("; "));
    } else {
      add(
        CHECK_INVENTORY,
        "pass",
        `all ${expectedSet.size} expected capsule(s) reported`,
      );
    }
  }

  // 5. The baseline only moves for an attestation that is about this deployment
  //    and signed by its key. Otherwise an attacker sets the baseline with one
  //    forged document and every later real one looks stale.
  let nextState: AttestState | null = null;
  if (presentedKey === expectedKey && att.hostFingerprint === expect.hostFingerprint) {
    nextState = {
      hostFingerprint: att.hostFingerprint,
      publicKeyHex: presentedKey,
      lastSeq: att.chain.lastSeq,
      currHash: att.chain.currHash,
      genesisAnchor: att.chain.genesisAnchor,
      generatedAt: att.generatedAt,
      observations: previous ? previous.observations + 1 : 1,
      // The verdict's observation describes THIS attestation. The reset counter
      // belongs to the stored baseline, so advanceState carries it; zero here
      // keeps the two SDKs serialising the same shape.
      ledgerResets: previous ? previous.ledgerResets : 0,
    };
  }

  return buildVerdict(checks, true, nextState);
}

/**
 * The baseline to store after a verification, or `null` to leave it alone.
 *
 * MONOTONE IN BOTH AXES, INDEPENDENTLY. The stored baseline carries two
 * different facts — the highest ledger head that has been verified, and the
 * most recent attestation that arrived — and neither may go backwards.
 *
 * Without that, a genuinely signed OLD attestation is a rollback tool. Replay
 * the one from head 5, the baseline drops to 5, and every attestation between 5
 * and the real head now "advances" again. The silence check would still be
 * running, and would still be answering about a boundary that stopped recording
 * days ago.
 *
 * Returns `null` when nothing moved forward, which the caller should treat as
 * "do not rewrite the state file" rather than as an error.
 *
 * `acceptLedgerReset` is the one documented way past the monotone rule, and it
 * exists because without it there was none. Core's `genesis.json` lives beside
 * the log and is re-read if present, so SEALING AND ROTATING A LEDGER KEEPS THE
 * GENESIS ANCHOR: `chain_identity` does not notice, and `sequence_advanced`
 * reports "the ledger went backwards" against the stored head — forever,
 * because the head never lowers. The only escape was deleting the state file,
 * which also destroys the last-report baseline and is exactly what an attacker
 * clearing evidence would do.
 *
 * A rotation and a truncation are the same bytes: same genesis, lower head.
 * This SDK cannot tell them apart and does not try. The flag records that an
 * operator asserted it, increments `ledgerResets`, and changes nothing about
 * the verdict for the attestation in hand — that run still reports the drop.
 */
export function advanceState(
  previous: AttestState | null,
  verdict: AttestVerdict,
  options: { acceptLedgerReset?: boolean } = {},
): AttestState | null {
  const next = verdict.nextState;
  if (next === null) {
    // The document was not signed by this deployment's key, or was not about
    // its host. It has no business setting the baseline.
    return null;
  }
  if (previous === null) return next;

  const headForward = next.lastSeq > previous.lastSeq;
  let newerReport = false;
  try {
    newerReport = parseRfc3339Ms(next.generatedAt) > parseRfc3339Ms(previous.generatedAt);
  } catch {
    // An unreadable timestamp is not a newer one.
    newerReport = false;
  }
  if (options.acceptLedgerReset && next.lastSeq < previous.lastSeq) {
    // The operator asserts this drop is a deliberate reset — a sealed and
    // rotated ledger. The SDK cannot check that: genesis.json survives a
    // rotation, so a rotation and a truncation are the same bytes on the wire
    // (same genesis, lower head). The assertion is therefore RECORDED, not
    // inferred, and the verification itself still reported the drop — this only
    // decides what the next run is compared against.
    return {
      hostFingerprint: next.hostFingerprint,
      publicKeyHex: next.publicKeyHex,
      lastSeq: next.lastSeq,
      currHash: next.currHash,
      genesisAnchor: next.genesisAnchor,
      generatedAt: newerReport ? next.generatedAt : previous.generatedAt,
      observations: previous.observations + 1,
      ledgerResets: previous.ledgerResets + 1,
    };
  }

  if (!headForward && !newerReport) return null;

  return {
    hostFingerprint: next.hostFingerprint,
    publicKeyHex: next.publicKeyHex,
    lastSeq: headForward ? next.lastSeq : previous.lastSeq,
    currHash: headForward ? next.currHash : previous.currHash,
    genesisAnchor: headForward ? next.genesisAnchor : previous.genesisAnchor,
    generatedAt: newerReport ? next.generatedAt : previous.generatedAt,
    observations: previous.observations + 1,
    ledgerResets: previous.ledgerResets,
  };
}


// --------------------------------------------------------------------------
// The report that never came.
// --------------------------------------------------------------------------

/**
 * Has an attestation arrived inside the expected interval?
 *
 * The contract's other half of silence: "An expected report that never came is
 * an anomaly the SDK raises on its own timer, not something it waits to be told
 * about." Nothing calls into Core here — the input is the last observation this
 * verifier recorded and the clock.
 *
 * A deployment that has never produced a verified attestation FAILS this check
 * rather than skipping it. There is no baseline, but there is also no report,
 * and "no report at all" is the most complete form of the silence this exists
 * to catch.
 */
export function reportArrivedCheck(
  previous: AttestState | null,
  options: { intervalSeconds: number; now?: Date; graceSeconds?: number },
): AttestCheck {
  const currentMs = nowMs(options.now);
  const deadline = options.intervalSeconds + (options.graceSeconds ?? 0);
  if (previous === null) {
    return {
      check: CHECK_REPORT_ARRIVED,
      outcome: "fail",
      detail: "no attestation has ever been verified for this deployment",
    };
  }
  let lastMs: number;
  try {
    lastMs = parseRfc3339Ms(previous.generatedAt);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      check: CHECK_REPORT_ARRIVED,
      outcome: "fail",
      detail: `the recorded generated_at is unreadable: ${message}`,
    };
  }
  const age = (currentMs - lastMs) / 1000;
  if (age > deadline) {
    return {
      check: CHECK_REPORT_ARRIVED,
      outcome: "fail",
      detail: `the last attestation is ${secs(age)}s old, past the ${secs(deadline)}s interval — a report that never came is an anomaly, not silence to be waited out`,
    };
  }
  return {
    check: CHECK_REPORT_ARRIVED,
    outcome: "pass",
    detail: `the last attestation is ${secs(age)}s old, inside the ${secs(deadline)}s interval`,
  };
}
