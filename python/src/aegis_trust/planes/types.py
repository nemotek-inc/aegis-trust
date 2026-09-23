"""Execution plane types and error definitions (Issue #284).

Following the port discipline established in aegis-boundary-core (PR #331),
this module defines:
  1. Closed enum PlaneKind with canonical snake_case serialization and aliases.
  2. PlaneAssurance enum (declared, platform_attested, hardware_attested).
  3. Opaque PlaneEvidence struct containing sealed_blob.
  4. PlaneVerdict verification result.
  5. AO-002 opaque PlaneError and internal PlaneErrorKind.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PlaneKind(str, Enum):
    """Closed enumeration of supported execution planes.

    Serializes to canonical snake_case identifiers:
      'aws', 'azure', 'gcp', 'oracle', 'local'.
    Accepts detailed aliases for forward/backward compatibility.
    """

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ORACLE = "oracle"
    LOCAL = "local"

    @classmethod
    def from_str(cls, val: str) -> PlaneKind:
        """Parse from canonical name or known alias (case-insensitive)."""
        normalized = val.strip().lower()
        aliases = {
            "aws_nitro": cls.AWS,
            "azure_cvm": cls.AZURE,
            "gcp_confidential": cls.GCP,
            "oracle_cloud": cls.ORACLE,
            "local_dev": cls.LOCAL,
        }
        if normalized in aliases:
            return aliases[normalized]
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown plane kind: {val!r}")

    @property
    def is_hardware_attested_capable(self) -> bool:
        """Whether this plane is capable of hardware-rooted attestation."""
        return self in (PlaneKind.AWS, PlaneKind.AZURE, PlaneKind.GCP, PlaneKind.LOCAL)


class PlaneAssurance(str, Enum):
    """Attestation assurance levels."""

    DECLARED = "declared"
    PLATFORM_ATTESTED = "platform_attested"
    HARDWARE_ATTESTED = "hardware_attested"

    @property
    def is_attested(self) -> bool:
        return self in (
            PlaneAssurance.PLATFORM_ATTESTED,
            PlaneAssurance.HARDWARE_ATTESTED,
        )

    @property
    def is_hardware(self) -> bool:
        return self == PlaneAssurance.HARDWARE_ATTESTED


class PlaneHealthStatus(str, Enum):
    """Execution plane availability and device status."""

    HEALTHY = "healthy"
    REGISTRATION_REQUIRED = "registration_required"
    THROTTLED = "throttled"
    UNAVAILABLE = "unavailable"


class PlaneErrorKind(str, Enum):
    """Internal classification of plane errors for audit logging.

    Never surfaced directly to external callers via PlaneError.__str__.
    """

    PLANE_UNAVAILABLE = "plane_unavailable"
    POLICY_DENIED = "policy_denied"
    CROSS_PLANE_MISMATCH = "cross_plane_mismatch"
    NONCE_MISMATCH = "nonce_mismatch"
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"
    MALFORMED_EVIDENCE = "malformed_evidence"
    EVIDENCE_EXPIRED = "evidence_expired"
    PLATFORM_CALL_FAILED = "platform_call_failed"
    UNKNOWN = "unknown"


class PlaneError(Exception):
    """Opaque external error for plane attestation operations (AO-002 enforcement).

    In accordance with the security discipline, all external errors collapse to
    a zero-information exception whose __str__ yields an empty string (''),
    preventing external error oracles from probing platform state.
    """

    def __init__(
        self, kind: PlaneErrorKind = PlaneErrorKind.UNKNOWN, details: Any = None
    ) -> None:
        super().__init__()
        self.kind = kind
        self.details = details

    def __str__(self) -> str:
        # AO-002: empty string. External callers MUST NOT receive diagnostic details.
        return ""

    def __repr__(self) -> str:
        return "PlaneError()"


@dataclass(frozen=True)
class PlaneEvidence:
    """Attestation evidence produced by PlaneAdapter.attest().

    The sealed_blob and metadata payloads are plane-specific and opaque to core/SDK logic.
    Cross-plane verification is rejected at the PlaneAdapter port layer.
    """

    plane: PlaneKind
    assurance: PlaneAssurance
    nonce: bytes
    sealed_blob: bytes
    version: int = 1
    metadata: bytes | None = None

    def evidence_ref(self) -> str:
        """SHA-256 hex digest of the sealed blob, suitable for audit logs."""
        return hashlib.sha256(self.sealed_blob).hexdigest()


@dataclass(frozen=True)
class PlaneVerdict:
    """Verdict returned from PlaneAdapter.verify()."""

    valid: bool
    assurance: PlaneAssurance
    plane: PlaneKind
    evidence_ref: str
