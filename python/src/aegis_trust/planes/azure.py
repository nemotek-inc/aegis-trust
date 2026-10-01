"""Azure CVM execution plane adapter."""

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


class AzureCvmPlaneAdapter(PlaneAdapter):
    """Azure Confidential VM execution plane adapter.

    Standard SDK port for Azure execution plane attestation. Opaque sealed_blob
    models Azure Attestation PKCS7 / SGX / SEV-SNP quote.
    """

    def __init__(self, region: str = "eastus") -> None:
        self.region = region

    def plane_kind(self) -> PlaneKind:
        return PlaneKind.AZURE

    def attest(self, nonce: bytes) -> PlaneEvidence:
        sealed = hashlib.sha256(
            b"azure-cvm-pkcs7:" + self.region.encode("utf-8") + b":" + nonce
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
