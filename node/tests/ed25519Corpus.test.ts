/**
 * conformance/ed25519_vectors.v0.json, run through the shipped verifier (Node).
 *
 * This SDK calls OpenSSL; the Python SDK implements RFC 8032 itself, because
 * its LITE install is dependency-free by contract and Python has no Ed25519 in
 * its standard library. Two implementations of one primitive stop agreeing
 * silently, so the agreement is a corpus both read.
 *
 * Mirror: python/tests/test_ed25519_corpus.py.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ed25519Verify } from "../src/ed25519.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CORPUS = JSON.parse(
  readFileSync(join(REPO, "conformance", "ed25519_vectors.v0.json"), "utf8"),
) as {
  version: number;
  vectors: Array<{
    id: string;
    source: string;
    public_key_hex: string;
    message_hex: string;
    signature_hex: string;
    expected_valid: boolean;
  }>;
};

const VECTORS = CORPUS.vectors;

function check(v: (typeof VECTORS)[number]): boolean {
  return ed25519Verify(
    Buffer.from(v.public_key_hex, "hex"),
    Buffer.from(v.message_hex, "hex"),
    Buffer.from(v.signature_hex, "hex"),
  );
}

describe("ed25519 verification corpus", () => {
  it("the corpus is not empty and is two-sided", () => {
    // A vector set that is all-accept or all-reject is passed by a constant
    // function, which is the failure mode this suite exists to remove.
    expect(CORPUS.version).toBe(0);
    expect(VECTORS.length).toBeGreaterThanOrEqual(10);
    expect(VECTORS.filter((v) => v.expected_valid).length).toBeGreaterThanOrEqual(4);
    expect(VECTORS.filter((v) => !v.expected_valid).length).toBeGreaterThanOrEqual(6);
  });

  for (const v of VECTORS) {
    it(`${v.id}: ${v.expected_valid ? "verifies" : "does not verify"}`, () => {
      expect(check(v)).toBe(v.expected_valid);
    });
  }

  it("the RFC 8032 known answers are present", () => {
    // The only inputs in this repo whose correct answer was decided elsewhere.
    const rfc = VECTORS.filter((v) => v.source === "rfc8032-7.1");
    expect(rfc.length).toBeGreaterThanOrEqual(4);
    expect(rfc.every((v) => v.expected_valid)).toBe(true);
  });

  it("a real ed25519-dalek signature is present", () => {
    // An implementation can pass every RFC vector and still disagree with the
    // signer that actually produces attestations.
    const core = VECTORS.filter((v) => v.source === "core-binary");
    expect(core.length).toBeGreaterThan(0);
    expect(core.every((v) => v.expected_valid)).toBe(true);
  });

  it("the unreduced scalar S+L is rejected", () => {
    // It satisfies the verification equation. Accepting it gives one message
    // two valid signatures by the same key.
    const v = VECTORS.find((x) => x.id === "unreduced-scalar-s-plus-l");
    expect(v).toBeDefined();
    expect(v!.expected_valid).toBe(false);
    expect(check(v!)).toBe(false);
  });

  it("the verifier is not a constant function", () => {
    // Asserted on the shipped function rather than inferred from the corpus.
    const results = new Set(VECTORS.map(check));
    expect([...results].sort()).toEqual([false, true]);
  });

  it("malformed input returns false rather than throwing", () => {
    // "Not verified" must never arrive as an exception a caller can turn into
    // "could not check".
    expect(ed25519Verify(Buffer.alloc(0), Buffer.from("m"), Buffer.alloc(0))).toBe(false);
    expect(ed25519Verify(Buffer.alloc(32), Buffer.from("m"), Buffer.alloc(63))).toBe(false);
    expect(ed25519Verify(Buffer.alloc(31), Buffer.from("m"), Buffer.alloc(64))).toBe(false);
  });
});
