/**
 * Attestation verifier behaviour that the shared corpus cannot express (Node).
 *
 * conformance/attest_verify.v0.json pins the verdict for a given document. What
 * it cannot pin is what happens *around* the verdict: which exit code the CLI
 * returns, whether the stored baseline can be rolled backwards, and whether a
 * corrupt state file degrades into "no previous observation". Those are where a
 * verifier stops being a verifier without any single check looking wrong.
 *
 * Mirror: python/tests/test_attest_verify.py.
 */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  EXIT_ABNORMAL,
  EXIT_CLEAN,
  EXIT_NO_REPORT,
  UNSIGNED_FIELDS,
  advanceState,
  canonicalMessage,
  findingsDigest,
  loadState,
  parseAttestation,
  saveState,
  stateFromJSON,
  verifyAttestation,
  type AttestExpectation,
  type AttestState,
  type AttestVerdict,
  type CapsuleFinding,
} from "../src/attestVerify.js";
import { main } from "../src/cli.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CORPUS = JSON.parse(
  readFileSync(join(REPO, "conformance", "attest_verify.v0.json"), "utf8"),
) as {
  signing_keys: { pinned: { public_key_hex: string } };
  cases: Array<{
    id: string;
    now: string;
    expect: Record<string, unknown>;
    previous: Record<string, unknown> | null;
    attestation: Record<string, unknown>;
  }>;
};

const PINNED_KEY = CORPUS.signing_keys.pinned.public_key_hex;
// Read from the corpus, never repeated as a literal: two values that must
// agree with nothing making them agree is the break canonical_digest.v0.json
// was created for.
const HOST = corpusCase("healthy-full-green").expect.host_fingerprint as string;

function corpusCase(id: string) {
  const found = CORPUS.cases.find((c) => c.id === id);
  if (!found) throw new Error(`no corpus case ${id}`);
  return found;
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aegis-attest-"));
  // The CLI prints a full check table per invocation; silence it so a failure
  // in this file is readable.
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

function write(id: string): string {
  const path = join(dir, `${id}.json`);
  writeFileSync(path, JSON.stringify(corpusCase(id).attestation), "utf8");
  return path;
}

function cli(...args: string[]): number {
  return main([
    "attest-verify",
    ...args,
    "--expect-key",
    PINNED_KEY,
    "--expect-host",
    HOST,
    // The corpus documents carry fixed timestamps, so the window has to be wide
    // enough that this file does not start failing tomorrow.
    "--max-age",
    "999999999",
  ]);
}

function expectationFrom(raw: Record<string, unknown>): AttestExpectation {
  return {
    publicKeyHex: raw.public_key_hex as string,
    hostFingerprint: raw.host_fingerprint as string,
    nonce: raw.nonce as string | null,
    allowUnchallenged: raw.allow_unchallenged as boolean,
    keyId: raw.key_id as string | null,
    maxAgeSeconds: raw.max_age_seconds as number,
    maxClockSkewSeconds: raw.max_clock_skew_seconds as number,
    capsuleIds: raw.capsule_ids as string[] | null,
    requirePrevious: raw.require_previous as boolean,
  };
}

// The SHIPPED parser, not a hand-rolled copy of it. The copy that used to live
// here silently dropped a field the moment the state grew one, which is the
// same two-literals-that-must-agree break conformance/canonical_digest.v0.json
// exists for.
function stateFrom(raw: Record<string, unknown> | null): AttestState | null {
  return raw === null ? null : stateFromJSON(raw);
}

function verdictFor(id: string, previous: AttestState | null): AttestVerdict {
  const c = corpusCase(id);
  return verifyAttestation(c.attestation, expectationFrom(c.expect), previous, {
    now: new Date(c.now),
  });
}

describe("exit codes (contract §5) — 2 must never collapse into 1", () => {
  it("a clean attestation exits 0", () => {
    expect(
      cli(write("healthy-full-green"), "--nonce", "sdk-contract-001", "--state", join(dir, "s.json")),
    ).toBe(EXIT_CLEAN);
  });

  it("an abnormal attestation exits 1", () => {
    const statePath = join(dir, "s.json");
    saveState(statePath, stateFrom(corpusCase("silence-same-head-again").previous)!);
    expect(
      cli(write("silence-same-head-again"), "--nonce", "sdk-contract-001", "--state", statePath),
    ).toBe(EXIT_ABNORMAL);
  });

  it("an unsigned attestation exits 1, not 2", () => {
    // An unsigned attestation IS a report — an unverifiable one. Answering 2
    // would file it as "the invocation failed" and route it to whoever fixes
    // pipelines, when what happened is that a boundary produced a statement
    // nobody can authenticate.
    expect(cli(write("unsigned-is-not-verified"), "--allow-unchallenged")).toBe(EXIT_ABNORMAL);
  });

  it("a missing file exits 2", () => {
    expect(cli(join(dir, "nope.json"), "--allow-unchallenged")).toBe(EXIT_NO_REPORT);
  });

  it("empty input exits 2", () => {
    const path = join(dir, "empty.json");
    writeFileSync(path, "", "utf8");
    expect(cli(path, "--allow-unchallenged")).toBe(EXIT_NO_REPORT);
  });

  it("non-JSON input exits 2", () => {
    // Bytes that are not a document are indistinguishable from a failed
    // invocation, so they are reported as one rather than as an anomaly.
    const path = join(dir, "garbage.json");
    writeFileSync(path, "error: could not open capsule root\n", "utf8");
    expect(cli(path, "--allow-unchallenged")).toBe(EXIT_NO_REPORT);
  });

  it("JSON that is not an attestation exits 1", () => {
    // A well-formed document that is not an attestation is a claim that
    // arrived, so it is an anomaly rather than a missing report.
    const path = join(dir, "other.json");
    writeFileSync(path, JSON.stringify({ hello: "world" }), "utf8");
    expect(cli(path, "--allow-unchallenged")).toBe(EXIT_ABNORMAL);
  });

  it("no arguments at all exits 2", () => {
    expect(cli()).toBe(EXIT_NO_REPORT);
  });

  it("the three exit codes are distinct", () => {
    expect(new Set([EXIT_CLEAN, EXIT_ABNORMAL, EXIT_NO_REPORT]).size).toBe(3);
  });
});

describe("the timer, with no attestation at all", () => {
  function stateWith(generatedAt: string): string {
    const path = join(dir, "s.json");
    saveState(path, {
      hostFingerprint: HOST,
      publicKeyHex: PINNED_KEY,
      lastSeq: 12,
      currHash: "ab".repeat(32),
      genesisAnchor: "cd".repeat(32),
      generatedAt,
      observations: 3,
    });
    return path;
  }

  it("reports the report that never came", () => {
    expect(cli("--state", stateWith("2020-01-01T00:00:00+00:00"), "--report-within", "60")).toBe(
      EXIT_ABNORMAL,
    );
  });

  it("is clean when a report did arrive", () => {
    // The accept half of the pair: an always-red timer would pass the test
    // above on its own.
    const recent = new Date(Date.now() - 5000).toISOString().replace(/\.\d+Z$/, "+00:00");
    expect(cli("--state", stateWith(recent), "--report-within", "3600")).toBe(EXIT_CLEAN);
  });
});

describe("the stored baseline", () => {
  it("round-trips", () => {
    const state: AttestState = {
      hostFingerprint: "host_1",
      publicKeyHex: PINNED_KEY,
      lastSeq: 9,
      currHash: "aa".repeat(32),
      genesisAnchor: "bb".repeat(32),
      generatedAt: "2026-09-14T12:00:00+00:00",
      observations: 4,
      ledgerResets: 0,
    };
    const path = join(dir, "nested", "state.json");
    saveState(path, state);
    expect(loadState(path)).toEqual(state);
  });

  it("absent state is null but corrupt state throws", () => {
    // The distinction the whole silence check rests on. If a corrupt state file
    // degraded to "no previous observation", corrupting it would make the
    // silence checks SKIP on every run while the report stayed green.
    expect(loadState(join(dir, "absent.json"))).toBeNull();

    const corrupt = join(dir, "corrupt.json");
    writeFileSync(corrupt, "{not json", "utf8");
    expect(() => loadState(corrupt)).toThrow();

    const wrongSchema = join(dir, "wrong.json");
    writeFileSync(wrongSchema, JSON.stringify({ schema: "something-else" }), "utf8");
    expect(() => loadState(wrongSchema)).toThrow();
  });

  it("the CLI refuses a corrupt state file rather than starting fresh", () => {
    const corrupt = join(dir, "state.json");
    writeFileSync(corrupt, "{not json", "utf8");
    expect(
      cli(write("healthy-full-green"), "--nonce", "sdk-contract-001", "--state", corrupt),
    ).toBe(EXIT_ABNORMAL);
  });

  it("moves forward on a healthy attestation", () => {
    const previous = stateFrom(corpusCase("healthy-full-green").previous)!;
    const moved = advanceState(previous, verdictFor("healthy-full-green", previous));
    expect(moved).not.toBeNull();
    expect(moved!.lastSeq).toBe(12);
    expect(moved!.observations).toBe(previous.observations + 1);
  });

  it("a shrunken ledger does not lower the stored head", () => {
    // A fresh, correctly signed attestation reporting a SMALLER head. It is an
    // anomaly and the report did genuinely arrive — so the last-report axis
    // advances while the head axis holds. If the head followed it down, the
    // truncation would be laundered into a new baseline.
    const previous = stateFrom(corpusCase("ledger-went-backwards").previous)!;
    const verdict = verdictFor("ledger-went-backwards", previous);
    expect(verdict.ok).toBe(false);
    const moved = advanceState(previous, verdict);
    expect(moved).not.toBeNull();
    expect(moved!.lastSeq).toBe(previous.lastSeq);
    expect(moved!.currHash).toBe(previous.currHash);
    expect(moved!.generatedAt).not.toBe(previous.generatedAt);
  });

  it("the head and the last report move independently", () => {
    // A report can arrive without the ledger growing — that is exactly the
    // silence case — so the timer must see a new report while the head check
    // still sees the same head.
    const previous = stateFrom(corpusCase("silence-same-head-again").previous)!;
    const moved = advanceState(previous, verdictFor("silence-same-head-again", previous));
    expect(moved).not.toBeNull();
    expect(moved!.lastSeq).toBe(previous.lastSeq);
    expect(moved!.currHash).toBe(previous.currHash);
    expect(moved!.generatedAt).not.toBe(previous.generatedAt);
  });

  it("a forged document never sets the baseline", () => {
    // Otherwise one forged attestation poisons the baseline and every real one
    // afterwards looks stale.
    for (const id of [
      "signed-by-an-unexpected-key",
      "attestation-about-another-host",
      "signature-bit-flipped",
      "unsigned-is-not-verified",
    ]) {
      const verdict = verdictFor(id, null);
      expect(verdict.nextState, id).toBeNull();
      expect(advanceState(null, verdict), id).toBeNull();
    }
  });

  function stateAt(seq: number, when: string): AttestState {
    return {
      hostFingerprint: HOST,
      publicKeyHex: PINNED_KEY,
      lastSeq: seq,
      currHash: String(seq).padStart(64, "0"),
      genesisAnchor: "cd".repeat(32),
      generatedAt: when,
      observations: 5,
    };
  }

  function verdictCarrying(next: AttestState): AttestVerdict {
    return {
      checks: [],
      signatureVerified: true,
      nextState: next,
      unsignedFieldsPresent: [],
      findings: [],
      skipped: [],
      ok: true,
      exitCode: EXIT_CLEAN,
    };
  }

  const quadrants: Array<[number, string, number, string]> = [
    // head forward, newer report: both axes move.
    [20, "2026-09-14T13:00:00+00:00", 20, "2026-09-14T13:00:00+00:00"],
    // head forward, older report: the head moves, the clock does not.
    [20, "2026-09-14T10:00:00+00:00", 20, "2026-09-14T12:00:00+00:00"],
    // head held, newer report: the clock moves, the head does not.
    [10, "2026-09-14T13:00:00+00:00", 12, "2026-09-14T13:00:00+00:00"],
  ];

  for (const [head, when, expectSeq, expectGenerated] of quadrants) {
    it(`is monotone on each axis independently (head ${head}, at ${when})`, () => {
      const previous = stateAt(12, "2026-09-14T12:00:00+00:00");
      const moved = advanceState(previous, verdictCarrying(stateAt(head, when)));
      expect(moved).not.toBeNull();
      expect(moved!.lastSeq).toBe(expectSeq);
      expect(moved!.generatedAt).toBe(expectGenerated);
    });
  }

  it("a replay that is older on both axes changes nothing", () => {
    // The rollback tool a non-monotone baseline would hand an attacker: replay
    // the genuinely signed attestation from head 4 taken an hour ago, and every
    // attestation between 4 and the real head "advances" again.
    const previous = stateAt(12, "2026-09-14T12:00:00+00:00");
    expect(advanceState(previous, verdictCarrying(stateAt(4, "2026-09-14T11:00:00+00:00")))).toBeNull();
  });

  it("an identical repeat changes nothing", () => {
    const previous = stateAt(12, "2026-09-14T12:00:00+00:00");
    expect(advanceState(previous, verdictCarrying(stateAt(12, previous.generatedAt)))).toBeNull();
  });

  it("the CLI state file only ever moves forward", () => {
    // End to end: verify a head-12 attestation, then replay a head-4 one, and
    // the stored baseline must still read 12.
    const statePath = join(dir, "state.json");
    saveState(statePath, stateFrom(corpusCase("healthy-full-green").previous)!);

    expect(
      cli(write("healthy-full-green"), "--nonce", "sdk-contract-001", "--state", statePath),
    ).toBe(EXIT_CLEAN);
    expect(loadState(statePath)!.lastSeq).toBe(12);

    expect(
      cli(write("ledger-went-backwards"), "--nonce", "sdk-contract-001", "--state", statePath),
    ).toBe(EXIT_ABNORMAL);
    expect(
      loadState(statePath)!.lastSeq,
      "a replayed attestation rolled the baseline back",
    ).toBe(12);
  });
});

describe("the canonical message and the findings digest", () => {
  function finding(capsuleId: string, claimedState: string): CapsuleFinding {
    return {
      capsuleId,
      claimedState,
      payloadPresent: true,
      payloadBytes: 1,
      issue: null,
      terminal: false,
    };
  }

  it("the length prefix separates adjacent fields", () => {
    // Without the 8-byte length prefix, ("ab", "c") and ("a", "bc") hash the
    // same — which is exactly how a rewritten capsule id hides inside an issue
    // string. Asserted on the shipped digest, not on a restatement of it.
    expect(findingsDigest([finding("ab", "c")])).not.toBe(
      findingsDigest([finding("a", "bc")]),
    );
  });

  it("the length prefix counts bytes, not UTF-16 units", () => {
    // Rust's str::len() is a byte count. Two ids with the same number of
    // characters and different UTF-8 lengths must digest differently.
    expect(findingsDigest([finding("abc", "S")])).not.toBe(
      findingsDigest([finding("あいう", "S")]),
    );
  });

  it("every digested part participates", () => {
    // A digest that silently dropped a field would let that field be rewritten
    // in flight, so each of the six is changed in turn.
    const base: CapsuleFinding = {
      capsuleId: "cap",
      claimedState: "Sealed",
      payloadPresent: true,
      payloadBytes: 29,
      issue: null,
      terminal: false,
    };
    const variants: CapsuleFinding[] = [
      { ...base, capsuleId: "cap2" },
      { ...base, claimedState: "Destroyed" },
      { ...base, payloadPresent: false },
      { ...base, payloadBytes: 30 },
      { ...base, payloadBytes: null },
      { ...base, issue: "gone" },
      { ...base, terminal: true },
    ];
    const digests = new Set([base, ...variants].map((f) => findingsDigest([f])));
    expect(digests.size).toBe(variants.length + 1);
  });

  it("the canonical message has the contract's shape", () => {
    const att = parseAttestation(corpusCase("healthy-full-green").attestation);
    const message = canonicalMessage(att);
    expect(message.endsWith("\n")).toBe(true);
    const lines = message.split("\n").slice(0, -1);
    expect(lines[0]).toBe("aegis-attest-v1");
    expect(lines.slice(1).map((l) => l.split("=", 1)[0])).toEqual([
      "generated_at",
      "host",
      "root",
      "nonce",
      "judged",
      "payload_missing",
      "inconsistent",
      "chain_status",
      "chain_last_seq",
      "chain_curr_hash",
      "chain_genesis",
      "chain_records_checked",
      "chain_first_break",
      "skipped_non_capsule",
      "self_limit",
      "findings_sha256",
      "abnormal",
    ]);
  });
});

describe("what the signature covers, measured rather than described", () => {
  // Fields whose value is null in the healthy fixture, and the type to mutate
  // them to. A nullable field this map does not know about fails the test
  // rather than being skipped: a silently skipped field is one nobody checked.
  const NULLABLE_TYPES: Record<string, "string" | "number"> = {
    self_limit_tripped: "string",
    "chain.first_break": "string",
    "findings[1].payload_bytes": "number",
    "findings[0].issue": "string",
    "findings[1].issue": "string",
    "findings[2].issue": "string",
  };

  function leafPaths(node: unknown, prefix = ""): string[] {
    if (Array.isArray(node)) {
      return node.flatMap((v, i) => leafPaths(v, `${prefix}[${i}]`));
    }
    if (typeof node === "object" && node !== null) {
      return Object.entries(node).flatMap(([k, v]) =>
        leafPaths(v, prefix ? `${prefix}.${k}` : k),
      );
    }
    return [prefix];
  }

  function parts(path: string): string[] {
    return path.replace(/\[/g, ".[").split(".").filter((p) => p !== "");
  }

  function get(doc: unknown, path: string): unknown {
    let node: any = doc;
    for (const p of parts(path)) {
      node = p.startsWith("[") ? node[Number(p.slice(1, -1))] : node[p];
    }
    return node;
  }

  function set(doc: unknown, path: string, value: unknown): void {
    const ps = parts(path);
    let node: any = doc;
    for (const p of ps.slice(0, -1)) {
      node = p.startsWith("[") ? node[Number(p.slice(1, -1))] : node[p];
    }
    const last = ps[ps.length - 1];
    if (last.startsWith("[")) node[Number(last.slice(1, -1))] = value;
    else node[last] = value;
  }

  function mutate(value: unknown, path: string): unknown {
    if (typeof value === "boolean") return !value;
    if (typeof value === "number") return value + 1;
    if (typeof value === "string") return value + "X";
    if (value === null) {
      const kind = NULLABLE_TYPES[path];
      expect(
        kind,
        `${path} is null and this test does not know its type; declare it in NULLABLE_TYPES rather than leaving the field unchecked`,
      ).toBeDefined();
      return kind === "number" ? 1 : "X";
    }
    throw new Error(`${path}: unhandled leaf type`);
  }

  function failedChecks(document: unknown, caseId: string): Set<string> {
    const c = corpusCase(caseId);
    const verdict = verifyAttestation(document, expectationFrom(c.expect), null, {
      now: new Date(c.now),
    });
    return new Set(verdict.checks.filter((k) => k.outcome === "fail").map((k) => k.check));
  }

  it("mutating any covered field breaks the signature, and only UNSIGNED_FIELDS survive", () => {
    // This is what keeps UNSIGNED_FIELDS from becoming a stale comment. A
    // contract change that drops a field out of the canonical message turns the
    // first half red; one that adds a field without updating the list turns the
    // second half red.
    const base = corpusCase("healthy-full-green").attestation;
    const covered: string[] = [];
    const uncovered: string[] = [];

    for (const path of leafPaths(base)) {
      // The signature block describes the signature; mutating signature_hex or
      // message_sha256 is tested elsewhere by its own check.
      if (path.startsWith("signature.") && !(UNSIGNED_FIELDS as readonly string[]).includes(path)) {
        continue;
      }
      const document = JSON.parse(JSON.stringify(base));
      set(document, path, mutate(get(base, path), path));
      const failed = failedChecks(document, "healthy-full-green");
      expect(failed.has("document"), `${path}: mutation made the document unparseable`).toBe(false);
      (failed.has("signature_valid") ? covered : uncovered).push(path);
    }

    // An empty list has no leaf to mutate, so append to it instead — otherwise
    // skipped_non_capsule (the field this whole exchange was about) would be
    // silently absent from the scan.
    for (const field of ["skipped_non_capsule", "abnormal"]) {
      expect((base as Record<string, unknown>)[field]).toEqual([]);
      const document = JSON.parse(JSON.stringify(base));
      document[field] = ["injected"];
      const failed = failedChecks(document, "healthy-full-green");
      (failed.has("signature_valid") ? covered : uncovered).push(field);
    }

    expect(uncovered.sort()).toEqual([...UNSIGNED_FIELDS].sort());
    // Non-vacuity: the scan has to have actually found fields to mutate.
    expect(covered.length, `only ${covered.length} fields were scanned`).toBeGreaterThanOrEqual(20);
  });

  it("skipped_non_capsule is now inside the signature", () => {
    // Named on its own because it is the field this contract exchange was
    // about: the only window onto what was NOT counted.
    const c = corpusCase("skipped_non_capsule-rewritten-after-signing");
    expect(c.attestation.skipped_non_capsule).toEqual([]);
    const verdict = verifyAttestation(
      c.attestation,
      expectationFrom(c.expect),
      stateFrom(c.previous),
      { now: new Date(c.now) },
    );
    expect(verdict.findings.map((f) => f.check)).toContain("signature_valid");
  });
});

describe("the one documented way past the monotone baseline", () => {
  function stateAt2(seq: number, when: string): AttestState {
    return {
      hostFingerprint: HOST,
      publicKeyHex: PINNED_KEY,
      lastSeq: seq,
      currHash: String(seq).padStart(64, "0"),
      genesisAnchor: "cd".repeat(32),
      generatedAt: when,
      observations: 5,
      ledgerResets: 0,
    };
  }

  function carrying(next: AttestState): AttestVerdict {
    return {
      checks: [],
      signatureVerified: true,
      nextState: next,
      findings: [],
      skipped: [],
      ok: true,
      exitCode: EXIT_CLEAN,
    };
  }

  it("without the flag a rotated ledger stays red forever", () => {
    // Core's genesis.json survives a rotation, so a sealed-and-rotated ledger
    // keeps its genesis: chain_identity does not notice and the head simply
    // drops. With a monotone baseline that is reported every run from then on.
    let previous = stateAt2(412, "2026-09-14T12:00:00+00:00");
    for (const head of [1, 2, 3]) {
      const moved = advanceState(previous, carrying(stateAt2(head, `2026-09-14T13:0${head}:00+00:00`)));
      expect(moved).not.toBeNull();
      expect(moved!.lastSeq, "the stored head followed the rotation down").toBe(412);
      previous = moved!;
    }
    expect(previous.lastSeq).toBe(412);
    expect(previous.ledgerResets).toBe(0);
  });

  it("the flag rebases and counts the assertion", () => {
    const previous = stateAt2(412, "2026-09-14T12:00:00+00:00");
    const rotated = stateAt2(1, "2026-09-14T13:00:00+00:00");
    const moved = advanceState(previous, carrying(rotated), { acceptLedgerReset: true });
    expect(moved).not.toBeNull();
    expect(moved!.lastSeq).toBe(1);
    expect(moved!.currHash).toBe(rotated.currHash);
    expect(moved!.ledgerResets).toBe(previous.ledgerResets + 1);
    const following = advanceState(moved!, carrying(stateAt2(2, "2026-09-14T13:05:00+00:00")));
    expect(following!.lastSeq).toBe(2);
    expect(following!.ledgerResets, "the count must survive later advances").toBe(1);
  });

  it("the flag does not lower a head that went up", () => {
    // It acknowledges a DROP, not a general override.
    const moved = advanceState(
      stateAt2(10, "2026-09-14T12:00:00+00:00"),
      carrying(stateAt2(20, "2026-09-14T13:00:00+00:00")),
      { acceptLedgerReset: true },
    );
    expect(moved!.lastSeq).toBe(20);
    expect(moved!.ledgerResets, "no reset happened, so nothing to count").toBe(0);
  });

  it("the flag changes nothing about the verdict", () => {
    // The run that sees the drop still reports it. An acknowledgement is not a
    // silencer.
    const previous = stateFrom(corpusCase("ledger-went-backwards").previous)!;
    const verdict = verdictFor("ledger-went-backwards", previous);
    expect(verdict.ok).toBe(false);
    expect(verdict.findings.map((f) => f.check)).toContain("sequence_advanced");
    const moved = advanceState(previous, verdict, { acceptLedgerReset: true });
    expect(moved!.ledgerResets).toBe(1);
    expect(verdictFor("ledger-went-backwards", previous).checks).toEqual(verdict.checks);
  });

  it("a forged document cannot use the flag to set a baseline", () => {
    // The flag loosens the monotone rule, not the authenticity rule.
    for (const id of ["signed-by-an-unexpected-key", "attestation-about-another-host"]) {
      const verdict = verdictFor(id, null);
      expect(
        advanceState(stateAt2(412, "2026-09-14T12:00:00+00:00"), verdict, {
          acceptLedgerReset: true,
        }),
        id,
      ).toBeNull();
    }
  });

  it("state round-trips the reset count, and an older state reads as zero", () => {
    const state = { ...stateAt2(7, "2026-09-14T12:00:00+00:00"), ledgerResets: 3 };
    const path = join(dir, "state.json");
    saveState(path, state);
    expect(loadState(path)).toEqual(state);

    const older = join(dir, "older.json");
    const raw = JSON.parse(readFileSync(path, "utf8"));
    delete raw.ledger_resets;
    writeFileSync(older, JSON.stringify(raw), "utf8");
    expect(loadState(older)!.ledgerResets).toBe(0);
  });
});
