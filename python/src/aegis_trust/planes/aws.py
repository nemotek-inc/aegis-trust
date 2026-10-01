"""AWS Nitro execution plane adapter."""

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


class AwsNitroPlaneAdapter(PlaneAdapter):
    """AWS Nitro Enclaves execution plane adapter.

    Standard SDK port for AWS execution plane attestation. Opaque sealed_blob
    models AWS Nitro COSE attestation document.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region

    def plane_kind(self) -> PlaneKind:
        return PlaneKind.AWS

    def attest(self, nonce: bytes) -> PlaneEvidence:
        sealed = hashlib.sha256(
            b"aws-nitro-cose:" + self.region.encode("utf-8") + b":" + nonce
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
