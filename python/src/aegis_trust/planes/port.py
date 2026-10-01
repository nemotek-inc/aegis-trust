"""PlaneAdapter port interface and cross-plane enforcement (Issue #284).

SDK defines the port; adapters implement it. SDK logic remains unaware
of cloud-provider-specific hardware APIs or quote parsers.
"""

from __future__ import annotations

import abc
from aegis_trust.planes.types import (
    PlaneEvidence,
    PlaneError,
    PlaneErrorKind,
    PlaneHealthStatus,
    PlaneKind,
    PlaneVerdict,
)


class PlaneAdapter(abc.ABC):
    """Abstract port for execution plane adapters.

    Every concrete adapter implements this port contract:
      1. attest(nonce) -> PlaneEvidence
      2. verify(evidence, expected_nonce) -> PlaneVerdict
      3. health_check() -> PlaneHealthStatus
      4. plane_kind() -> PlaneKind
    """

    @abc.abstractmethod
    def attest(self, nonce: bytes) -> PlaneEvidence:
        """Generate attestation evidence bound to a cryptographic nonce."""
        raise NotImplementedError

    def verify(self, evidence: PlaneEvidence, expected_nonce: bytes) -> PlaneVerdict:
        """Verify attestation evidence against expected nonce.

        Enforces cross-plane rejection: evidence produced by a different plane
        MUST fail closed with PlaneErrorKind.CROSS_PLANE_MISMATCH.
        """
        if evidence.plane != self.plane_kind():
            raise PlaneError(PlaneErrorKind.CROSS_PLANE_MISMATCH)

        if evidence.nonce != expected_nonce:
            raise PlaneError(PlaneErrorKind.NONCE_MISMATCH)

        return self._do_verify(evidence, expected_nonce)

    @abc.abstractmethod
    def _do_verify(
        self, evidence: PlaneEvidence, expected_nonce: bytes
    ) -> PlaneVerdict:
        """Plane-specific verification implementation after cross-plane and nonce gates."""
        raise NotImplementedError

    @abc.abstractmethod
    def health_check(self) -> PlaneHealthStatus:
        """Probe platform/device health without generating full attestation evidence."""
        raise NotImplementedError

    @abc.abstractmethod
    def plane_kind(self) -> PlaneKind:
        """Execution plane identifier served by this adapter."""
        raise NotImplementedError
