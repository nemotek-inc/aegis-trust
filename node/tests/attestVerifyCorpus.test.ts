/**
 * conformance/attest_verify.v0.json, run through the shipped verifier (Node).
 *
 * The corpus is the single place where "this attestation is verified" is
 * defined. Both SDKs read it, so a change that makes one of them describe an
 * attestation differently from the other fails here or in
 * python/tests/test_attest_verify_corpus.py.
 *
 * This runner feeds the corpus to the real `verifyAttestation` — it does not
 * rebuild a verdict of its own and check its own reconstruction. That tautology
 * has shipped in this repo before (the byte anchor for the idempotency digest
 * hashed its own rebuild and never called the shipped function), which is why
 * conformance/runners.v0.json machine-checks that this file imports and calls
 * the shipped symbol and cannot reach a hashing primitive.
 *
 * Mirror: python/tests/test_attest_verify_corpus.py.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ALL_CHECKS,
  MAX_SAFE_INTEGER,
  canonicalMessage,
  findingsDigest,
  parseAttestation,
  reportArrivedCheck,
  stateFromJSON,
  verifyAttestation,
  type AttestCheck,
  type AttestExpectation,
  type AttestState,
  type CapsuleFinding,
} from "../src/attestVerify.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CORPUS = JSON.parse(
  readFileSync(join(REPO, "conformance", "attest_verify.v0.json"), "utf8"),
) as {
  version: number;
  cases: CorpusCase[];
  timer_cases: TimerCase[];
};

interface ExpectJson {
  public_key_hex: string;
  host_fingerprint: string;
  nonce: string | null;
  allow_unchallenged: boolean;
  key_id: string | null;
  max_age_seconds: number;
  max_clock_skew_seconds: number;
  capsule_ids: string[] | null;
  require_previous: boolean;
}

interface CorpusCase {
  id: string;
  provenance: string;
  now: string;
  expect: ExpectJson;
  previous: Record<string, unknown> | null;
  attestation: Record<string, unknown>;
  must: { fails: string[]; passes?: string[]; skips?: string[] };
  expected: {
    ok: boolean;
    exit_code: number;
    signature_verified: boolean;
    next_state: Record<string, unknown> | null;
    checks: AttestCheck[];
  };
}

interface TimerCase {
  id: string;
  previous: Record<string, unknown> | null;
  interval_seconds: number;
  grace_seconds: number;
  now: string;
  must_outcome: string;
  expected: AttestCheck;
}

function expectation(raw: ExpectJson): AttestExpectation {
  return {
    publicKeyHex: raw.public_key_hex,
    hostFingerprint: raw.host_fingerprint,
    nonce: raw.nonce,
    allowUnchallenged: raw.allow_unchallenged,
    keyId: raw.key_id,
    maxAgeSeconds: raw.max_age_seconds,
    maxClockSkewSeconds: raw.max_clock_skew_seconds,
    capsuleIds: raw.capsule_ids,
    requirePrevious: raw.require_previous,
  };
}

function state(raw: Record<string, unknown> | null): AttestState | null {
  return raw === null ? null : stateFromJSON(raw);
}

function corpusCase(id: string): CorpusCase {
  const found = CORPUS.cases.find((c) => c.id === id);
  if (!found) throw new Error(`no corpus case ${id}`);
  return found;
}

function run(c: CorpusCase) {
  return verifyAttestation(c.attestation, expectation(c.expect), state(c.previous), {
    now: new Date(c.now),
  });
}

describe("attestation verifier corpus", () => {
  it("the corpus is not empty", () => {
    // A runner that silently matched nothing would report a clean pass.
    expect(CORPUS.version).toBe(0);
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(20);
    expect(CORPUS.timer_cases.length).toBeGreaterThanOrEqual(3);
  });

  for (const c of CORPUS.cases) {
    it(`${c.id}: verdict matches the corpus`, () => {
      // Every check, outcome and detail sentence is byte-identical to the pin,
      // so the two SDKs cannot drift into describing one attestation two ways.
      const verdict = run(c);
      expect(verdict.checks).toEqual(c.expected.checks);
      expect(verdict.ok).toBe(c.expected.ok);
      expect(verdict.exitCode).toBe(c.expected.exit_code);
      expect(verdict.signatureVerified).toBe(c.expected.signature_verified);
      if (c.expected.next_state === null) {
        expect(verdict.nextState).toBeNull();
      } else {
        expect(verdict.nextState).not.toBeNull();
        expect(state(c.expected.next_state)).toEqual(verdict.nextState);
      }
    });

    it(`${c.id}: hand-written intent holds`, () => {
      // `must` is the specification; `expected` is only the regression pin.
      // Asserted here too, so a regenerated corpus that quietly recorded a
      // different verdict cannot pass by agreeing with itself.
      const verdict = run(c);
      const failed = verdict.checks.filter((k) => k.outcome === "fail").map((k) => k.check);
      const passed = new Set(
        verdict.checks.filter((k) => k.outcome === "pass").map((k) => k.check),
      );
      const skipped = new Set(
        verdict.checks.filter((k) => k.outcome === "skip").map((k) => k.check),
      );
      expect([...failed].sort()).toEqual([...c.must.fails].sort());
      for (const name of c.must.passes ?? []) expect(passed.has(name), name).toBe(true);
      for (const name of c.must.skips ?? []) expect(skipped.has(name), name).toBe(true);
      // ok is derived from the failures and must stay that way: a verdict that
      // reported findings and still called itself ok is the whole disease.
      expect(verdict.ok).toBe(failed.length === 0);
    });
  }

  it("every check has a reject and an accept", () => {
    // The discipline that makes the rest of this file mean anything. A suite
    // built only from broken material is passed by an implementation that
    // always answers red; one built only from healthy material is passed by one
    // that always answers green.
    const everFailed = new Set<string>();
    const everPassed = new Set<string>();
    for (const c of CORPUS.cases) {
      for (const check of c.expected.checks) {
        if (check.outcome === "fail") everFailed.add(check.check);
        else if (check.outcome === "pass") everPassed.add(check.check);
      }
    }
    const missingRed = ALL_CHECKS.filter((n) => !everFailed.has(n));
    const missingGreen = ALL_CHECKS.filter((n) => !everPassed.has(n));
    expect(missingRed, `no corpus case makes these fail: ${missingRed}`).toEqual([]);
    expect(missingGreen, `no corpus case makes these pass: ${missingGreen}`).toEqual([]);
  });

  it("a clean attestation is actually accepted", () => {
    const green = CORPUS.cases.filter((c) => c.expected.ok);
    expect(green.length, "the corpus contains no attestation that verifies cleanly")
      .toBeGreaterThan(0);
    const full = green.filter((c) => c.expected.checks.every((k) => k.outcome === "pass"));
    expect(full.length, "no corpus case passes every check").toBeGreaterThan(0);
  });

  it("the Core-produced vectors verify", () => {
    // Nothing about the canonical message can be settled by reading the
    // contract: these were produced AND signed by the real aegis-gateway
    // binary, so a message rebuilt one byte differently fails here.
    const coreCases = CORPUS.cases.filter((c) => c.provenance === "core-binary");
    expect(coreCases.length).toBeGreaterThanOrEqual(3);
    const signed = coreCases.filter((c) => c.attestation.signature !== null);
    expect(signed.length).toBeGreaterThan(0);
    for (const c of signed) {
      const verdict = run(c);
      expect(verdict.signatureVerified, c.id).toBe(true);
      expect(verdict.findings.map((f) => f.check), c.id).not.toContain("signature_valid");
    }
  });

  it("a multibyte capsule id is covered", () => {
    // Rust's str::len() counts BYTES. A verifier that length-prefixed the
    // findings digest by UTF-16 unit count agrees with Core on every ASCII
    // capsule and diverges the moment one is not.
    // eslint-disable-next-line no-control-regex
    const ascii = /^[\x00-\x7f]*$/;
    const found = CORPUS.cases.some((c) =>
      ((c.attestation.findings as Array<{ capsule_id: string }> | undefined) ?? []).some(
        (f) => !ascii.test(f.capsule_id),
      ),
    );
    expect(found, "no corpus case carries a capsule id outside ASCII").toBe(true);
  });

  for (const c of CORPUS.timer_cases) {
    it(`${c.id}: report-arrived timer`, () => {
      // The other half of silence: the report that never came. Raised on the
      // SDK's own clock, because a boundary that has stopped reporting cannot
      // be the thing that tells you so.
      const check = reportArrivedCheck(state(c.previous), {
        intervalSeconds: c.interval_seconds,
        graceSeconds: c.grace_seconds,
        now: new Date(c.now),
      });
      expect(check).toEqual(c.expected);
      expect(check.outcome).toBe(c.must_outcome);
    });
  }

  it("the timer corpus has both outcomes", () => {
    const outcomes = new Set(CORPUS.timer_cases.map((c) => c.must_outcome));
    expect([...outcomes].sort()).toEqual(["fail", "pass"]);
  });
});

describe("the contract gate: the SDK and the pinned contract cannot move apart", () => {
  const PIN = (
    JSON.parse(
      readFileSync(join(REPO, "conformance", "attest_verify.v0.json"), "utf8"),
    ) as { contract_pin: Record<string, any> }
  ).contract_pin;

  it("the contract pin is populated", () => {
    // A pin that lost its fields would make every test below vacuous.
    for (const key of [
      "revision",
      "canonical_message_prefix",
      "canonical_message_fields",
      "findings_digest_parts",
      "max_integer",
      "chain_status_vocabulary",
    ]) {
      expect(PIN[key], `contract_pin.${key} is empty`).toBeTruthy();
    }
  });

  it("the canonical message matches the pinned contract", () => {
    // The contract lives in another repository, so nothing in this repo's CI
    // can watch it move — and it moved three times while this verifier was
    // being written, each time found by hand. This is the half that CAN be
    // automated: edit canonicalMessage without updating the pin and this goes
    // red; edit the pin without the code and it goes red too.
    const att = parseAttestation(corpusCase("healthy-full-green").attestation);
    const lines = canonicalMessage(att).split("\n").slice(0, -1);
    expect(lines[0]).toBe(PIN.canonical_message_prefix);
    expect(lines.slice(1).map((l) => l.split("=", 1)[0])).toEqual(
      PIN.canonical_message_fields,
    );
  });

  it("the findings digest parts match the pinned contract", () => {
    // The count is checked as well as the behaviour: a contract that grew a
    // seventh part would leave this at six and the digest would silently stop
    // covering it.
    expect(PIN.findings_digest_parts).toHaveLength(6);
    const base: CapsuleFinding = {
      capsuleId: "cap",
      claimedState: "Sealed",
      payloadPresent: true,
      payloadBytes: 29,
      issue: null,
      terminal: false,
    };
    const changed: Record<string, CapsuleFinding> = {
      capsule_id: { ...base, capsuleId: "cap2" },
      claimed_state: { ...base, claimedState: "Destroyed" },
      payload_present: { ...base, payloadPresent: false },
      terminal: { ...base, terminal: true },
      payload_bytes: { ...base, payloadBytes: 30 },
      issue: { ...base, issue: "gone" },
    };
    expect(Object.keys(changed).sort()).toEqual([...PIN.findings_digest_parts].sort());
    for (const [name, variant] of Object.entries(changed)) {
      expect(
        findingsDigest([base]),
        `${name} is declared as a digested part but changing it does not change the digest`,
      ).not.toBe(findingsDigest([variant]));
    }
  });

  it("the integer bound matches the pinned contract", () => {
    // Core's fields are usize/u64, which are wider — a contract promise, not a
    // type guarantee, so it is pinned on both sides.
    expect(MAX_SAFE_INTEGER).toBe(PIN.max_integer);
  });

  it("every pinned chain status appears in the corpus", () => {
    // The vocabulary is closed today. The verifier is still written as
    // `!== "valid"` rather than a match over these five, so a sixth value lands
    // on the abnormal side instead of falling through.
    const seen = new Set(
      CORPUS.cases
        .map((c) => (c.attestation.chain as Record<string, unknown> | undefined)?.status)
        .filter((s): s is string => typeof s === "string"),
    );
    const missing = (PIN.chain_status_vocabulary as string[]).filter((s) => !seen.has(s));
    expect(missing, `pinned chain statuses with no corpus case: ${missing}`).toEqual([]);
  });

  it("the pin names the revision the vectors came from", () => {
    // Provenance, so a regenerated corpus cannot quietly keep an old claim.
    expect(PIN.vectors_generated_from).toContain(PIN.revision);
    expect(CORPUS.cases.filter((c) => c.provenance === "core-binary").length)
      .toBeGreaterThan(0);
  });

  it("every pinned chain status has a stated meaning", () => {
    // The vocabulary pins the tokens; this pins what they assert. A meaning can
    // move while a shape holds still — if `valid` were narrowed or widened, the
    // pin, the gate and the vocabulary would all stay green and this verifier
    // would go on answering a question nobody is asking. Nothing mechanical
    // closes that; what this does is make the sentence part of the artifact, so
    // the change shows up in a diff.
    const meaning = PIN.chain_status_meaning as Record<string, string>;
    const vocabulary = PIN.chain_status_vocabulary as string[];
    const missing = vocabulary.filter((v) => !(v in meaning));
    expect(missing, `pinned statuses with no stated meaning: ${missing}`).toEqual([]);
    const extra = Object.keys(meaning).filter((v) => !vocabulary.includes(v));
    expect(extra, `meanings for statuses not in the vocabulary: ${extra}`).toEqual([]);
    for (const [status, text] of Object.entries(meaning)) {
      expect(text.length, `${status}: meaning too thin to be worth diffing`).toBeGreaterThan(40);
    }
  });

  it("the empty-ledger dependency is pinned, not assumed", () => {
    // Contract §4: an EMPTY ledger is `valid`. So a deployment holding capsules
    // whose ledger has never recorded anything verifies clean on a first
    // observation. That is a limit, not a check, and it is written down as a
    // case so it cannot quietly become something this verifier is believed to
    // catch.
    const c = corpusCase("empty-ledger-not-independently-caught");
    const chain = c.attestation.chain as Record<string, unknown>;
    expect(chain.status).toBe("valid");
    expect(chain.records_checked).toBe(0);
    expect(c.attestation.judged as number).toBeGreaterThan(0);
    expect(
      c.expected.ok,
      "if this stopped verifying clean, the SDK grew an independent check — say which",
    ).toBe(true);
    // Core reports the state itself; the finding must live in `abnormal` and
    // not be smuggled into `chain.status`, which would change what `valid`
    // means for every other caller.
    const reported = corpusCase("empty-ledger-core-reports-it");
    expect((reported.attestation.chain as Record<string, unknown>).status).toBe("valid");
    const failed = reported.expected.checks
      .filter((k) => k.outcome === "fail")
      .map((k) => k.check);
    expect(failed).toEqual(["core_abnormal"]);
    expect((PIN.chain_status_meaning as Record<string, string>).valid.toLowerCase()).toContain("empty");
  });
});
