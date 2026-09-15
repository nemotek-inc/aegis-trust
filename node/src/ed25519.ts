// Ed25519 signature **verification** — the Node half of the attestation
// verifier's signature check. Parity target:
// python/src/aegis_trust/_ed25519.py.
//
// The two SDKs get here by different routes and must agree on the answer. This
// one hands the work to OpenSSL through `node:crypto`, which is available in
// every supported runtime (engines: node >= 18). The Python SDK cannot do the
// same: `pip install aegis-trust` is dependency-free by contract
// (python/tests/test_lite_zero_dep.py), and Python has no Ed25519 in its
// standard library — so the Python side implements RFC 8032 verification in
// `int` arithmetic instead. Both are pinned by the same vectors in
// conformance/ed25519_vectors.v0.json, which is what keeps two different
// implementations answering one question the same way.
//
// WHAT THEY AGREE ON. Both use the cofactorless verification equation of
// RFC 8032 §5.1.7 and both reject an unreduced scalar `S >= L` (the
// malleability window), a key or signature of the wrong length, and a point
// that is not on the curve. Neither rejects a small-order public key: OpenSSL
// does not, so adding the rejection on the Python side alone would mean the two
// SDKs disagreed about what "valid" means. The attestation verifier never
// depends on that property — it pins the expected public key by value.
//
// VERIFICATION ONLY. There is no signing code here and there must not be:
// the SDK verifies Core's statements, it does not produce them.

import { createPublicKey, verify as nodeVerify } from "node:crypto";

/**
 * DER SubjectPublicKeyInfo header for an Ed25519 key, to which the raw 32-byte
 * key is appended. `node:crypto` has no raw-key import for Ed25519, so the
 * wrapping is done here rather than asking callers to carry DER around.
 *
 *   30 2a                SEQUENCE (42 bytes)
 *     30 05              SEQUENCE (5 bytes) — AlgorithmIdentifier
 *       06 03 2b 65 70   OID 1.3.101.112 (id-Ed25519)
 *     03 21 00           BIT STRING (33 bytes, 0 unused bits)
 */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * True when `signature` is a valid Ed25519 signature by `publicKey` over
 * `message`.
 *
 * Never throws: a malformed key, a malformed signature and a genuine mismatch
 * are all the same answer to the only question being asked — is this message
 * authenticated? A verifier that threw on some of them would push callers into
 * a `catch` where "not verified" quietly becomes "could not check".
 */
export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}
