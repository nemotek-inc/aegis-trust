"""Local / development execution plane adapter."""

from __future__ import annotations

import hashlib
from aegis_trust.planes.port import PlaneAdapter
from aegis_trust.planes.types import (
    PlaneAssurance,
    PlaneEvidence,
    PlaneHealthStatus,
    PlaneKind,
    PlaneVerdict,
)


class LocalPlaneAdapter(PlaneAdapter):
    """Local development execution plane adapter.

    Produces declared assurance attestation evidence for local simulation,
    self-hosted TPM testing, or offline verification.
    """

    def __init__(self, node_id: str = "local-host-01") -> None:
        self.node_id = node_id

    def plane_kind(self) -> PlaneKind:
        return PlaneKind.LOCAL

    def attest(self, nonce: bytes) -> PlaneEvidence:
        sealed = hashlib.sha256(
            b"local-plane:" + self.node_id.encode("utf-8") + b":" + nonce
        ).digest()
        return PlaneEvidence(
            plane=self.plane_kind(),
            assurance=PlaneAssurance.DECLARED,
            nonce=nonce,
            sealed_blob=sealed,
        )

    def _do_verify(
        self, evidence: PlaneEvidence, expected_nonce: bytes
    ) -> PlaneVerdict:
        return PlaneVerdict(
            valid=True,
            assurance=evidence.assurance,
            plane=self.plane_kind(),
            evidence_ref=evidence.evidence_ref(),
        )

    def health_check(self) -> PlaneHealthStatus:
        return PlaneHealthStatus.HEALTHY
