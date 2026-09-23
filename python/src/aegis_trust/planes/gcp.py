"""GCP Confidential execution plane adapter."""

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


class GcpConfidentialPlaneAdapter(PlaneAdapter):
    """GCP Confidential Space execution plane adapter.

    Standard SDK port for GCP execution plane attestation. Opaque sealed_blob
    models Google Cloud Confidential Space OIDC / Instance Identity token.
    """

    def __init__(self, project_id: str = "default-project") -> None:
        self.project_id = project_id

    def plane_kind(self) -> PlaneKind:
        return PlaneKind.GCP

    def attest(self, nonce: bytes) -> PlaneEvidence:
        sealed = hashlib.sha256(
            b"gcp-confidential-token:" + self.project_id.encode("utf-8") + b":" + nonce
        ).digest()
        return PlaneEvidence(
            plane=self.plane_kind(),
            assurance=PlaneAssurance.HARDWARE_ATTESTED,
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
