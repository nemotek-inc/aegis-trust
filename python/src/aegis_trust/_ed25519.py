"""Ed25519 signature **verification** (RFC 8032), stdlib only.

WHY THIS EXISTS AT ALL. The Python SDK's headline install is dependency-free —
``pip install aegis-trust`` pulls nothing (python/tests/test_lite_zero_dep.py
pins it). Verifying a Core attestation needs Ed25519, and adding
``cryptography`` as a runtime dependency to get it would break the invariant for
every user who never touches an attestation. So the verification half of
RFC 8032 lives here, in ``int`` arithmetic, and the packaging contract holds.

WHAT IS AND IS NOT CLAIMED.

* **Verification only.** There is no signing code here and there must never be.
  Signing needs a secret scalar, and secret-dependent arithmetic in Python
  ``int`` leaks through timing and through the allocator. Verification touches
  no secret: the public key, the message and the signature are all values an
  attacker already has, so the absence of constant-time behaviour costs
  nothing. That asymmetry is the whole reason this file is safe to write and
  a signing counterpart would not be.
* **Not a general-purpose crypto library.** It is an internal detail of
  :mod:`aegis_trust.attest_verify`. It is pinned by the RFC 8032 test vectors
  and by real ed25519-dalek signatures produced by the Core binary
  (conformance/ed25519_vectors.v0.json) — it is not pinned by "it looked right".

STRICTNESS. Rejected as unverified, rather than accepted:

* a public key or signature of the wrong length;
* a non-canonical field element (``y >= p``) in either the key or ``R``;
* a point that is not on the curve;
* a scalar ``S >= L`` (the malleability window RFC 8032 §5.1.7 closes).

The verification equation is the cofactorless ``[S]B == R + [H(R,A,M)]A`` of
RFC 8032 §5.1.7 — the same equation ``ed25519-dalek``'s ``verify`` and OpenSSL's
``ED25519_verify`` use, so the Node SDK (which calls OpenSSL through
``node:crypto``) and this module agree on which signatures are valid.

Small-order public keys are deliberately NOT rejected here, because OpenSSL does
not reject them either and a divergence between the two SDKs about what "valid"
means would be worse than the property is worth. The attestation verifier never
relies on that property: it pins the expected public key by value, so a
small-order key could only be reached by an operator pinning one.
"""

from __future__ import annotations

import hashlib

__all__ = ["ed25519_verify"]

# Curve constants (RFC 8032 §5.1).
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
_Point = tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    """The ``x`` matching ``y`` with the requested sign bit, or None.

    Returns None for a non-canonical ``y`` (``y >= p``) and for a ``y`` with no
    curve point, so a caller that checks for None has rejected both.
    """
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        # x == 0 has only one square root, so a requested sign of 1 is a
        # contradiction rather than a point.
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # y is on no curve point
    if (x & 1) != sign:
        x = _P - x
    return x


# Base point B: y = 4/5, x the even root (RFC 8032 §5.1).
_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None  # curve constant; a failure here is a corrupted module
_BASE: _Point = (_BX, _BY, 1, _BX * _BY % _P)


def _point_add(p: _Point, q: _Point) -> _Point:
    """Twisted Edwards addition, RFC 8032 §5.1.4 (complete: no special cases)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: _Point) -> _Point:
    """``[s]p`` by double-and-add.

    Not constant time, and it does not need to be: every input to this function
    on the verification path is public (see the module docstring).
    """
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: _Point, q: _Point) -> bool:
    """Projective equality: ``x``/``y`` compared after clearing ``Z``."""
    if (p[0] * q[2] - q[0] * p[2]) % _P:
        return False
    return not (p[1] * q[2] - q[1] * p[2]) % _P


def _decompress(s: bytes) -> _Point | None:
    """Decode a 32-byte point encoding, or None when it is not a point."""
    if len(s) != 32:
        return None
    raw = int.from_bytes(s, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid Ed25519 signature by ``public_key``.

    Never raises: malformed key material, a malformed signature and a genuine
    mismatch are all the same answer to the only question being asked — is this
    message authenticated? — and a verifier that raised on some of them would
    push callers into an ``except`` branch where "not verified" quietly becomes
    "could not check".
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    public_key = bytes(public_key)
    signature = bytes(signature)

    a = _decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        # RFC 8032 §5.1.7: an unreduced S is the malleability window — the same
        # message/key would then have a second valid signature.
        return False

    k = (
        int.from_bytes(
            hashlib.sha512(r_bytes + public_key + bytes(message)).digest(), "little"
        )
        % _L
    )
    return _point_equal(_point_mul(s, _BASE), _point_add(r, _point_mul(k, a)))
