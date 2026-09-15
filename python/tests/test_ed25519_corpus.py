"""conformance/ed25519_vectors.v0.json, run through the shipped verifier (Python).

The Python SDK implements RFC 8032 verification itself, because the LITE install
is dependency-free by contract and Python has no Ed25519 in its standard
library. The Node SDK calls OpenSSL. Two implementations of one primitive stop
agreeing silently, so the agreement is a corpus both read.

Mirror: node/tests/ed25519Corpus.test.ts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust.attest_verify import ed25519_verify

REPO = Path(__file__).resolve().parents[2]
CORPUS = json.loads(
    (REPO / "conformance" / "ed25519_vectors.v0.json").read_text(encoding="utf-8")
)
VECTORS = CORPUS["vectors"]


def test_corpus_is_not_empty_and_is_two_sided() -> None:
    """A vector set that is all-accept or all-reject is passed by a constant
    function, which is the failure mode this suite exists to remove."""
    assert CORPUS["version"] == 0
    assert len(VECTORS) >= 10
    accepted = [v for v in VECTORS if v["expected_valid"]]
    rejected = [v for v in VECTORS if not v["expected_valid"]]
    assert len(accepted) >= 4, "too few must-verify vectors"
    assert len(rejected) >= 6, "too few must-not-verify vectors"


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vector: dict) -> None:
    got = ed25519_verify(
        bytes.fromhex(vector["public_key_hex"]),
        bytes.fromhex(vector["message_hex"]),
        bytes.fromhex(vector["signature_hex"]),
    )
    assert got is vector["expected_valid"], vector["id"]


def test_rfc8032_known_answers_are_present() -> None:
    """The only inputs in this repo whose correct answer was decided elsewhere."""
    rfc = [v for v in VECTORS if v["source"] == "rfc8032-7.1"]
    assert len(rfc) >= 4
    assert all(v["expected_valid"] for v in rfc)


def test_the_real_dalek_signature_is_present() -> None:
    """An implementation can pass every RFC vector and still disagree with the
    signer that actually produces attestations."""
    core = [v for v in VECTORS if v["source"] == "core-binary"]
    assert core, "no ed25519-dalek-produced vector"
    assert all(v["expected_valid"] for v in core)


def test_the_unreduced_scalar_is_rejected() -> None:
    """S + L satisfies the verification equation. Accepting it gives one message
    two valid signatures by the same key, which breaks anything that treats a
    signature as an identifier."""
    vector = next(v for v in VECTORS if v["id"] == "unreduced-scalar-s-plus-l")
    assert vector["expected_valid"] is False
    assert (
        ed25519_verify(
            bytes.fromhex(vector["public_key_hex"]),
            bytes.fromhex(vector["message_hex"]),
            bytes.fromhex(vector["signature_hex"]),
        )
        is False
    )


def test_verifier_is_not_a_constant_function() -> None:
    """Asserted directly on the shipped function rather than inferred from the
    corpus: a verifier that returns True for everything, or False for
    everything, must fail this file."""
    results = {
        ed25519_verify(
            bytes.fromhex(v["public_key_hex"]),
            bytes.fromhex(v["message_hex"]),
            bytes.fromhex(v["signature_hex"]),
        )
        for v in VECTORS
    }
    assert results == {True, False}


def test_malformed_input_returns_false_rather_than_raising() -> None:
    """ "Not verified" must never arrive as an exception a caller can turn into
    "could not check"."""
    assert ed25519_verify(b"", b"message", b"") is False
    assert ed25519_verify(b"\x00" * 32, b"message", b"\x00" * 63) is False
    assert ed25519_verify(b"\x00" * 31, b"message", b"\x00" * 64) is False
    assert ed25519_verify("not bytes", b"message", b"\x00" * 64) is False  # type: ignore[arg-type]
