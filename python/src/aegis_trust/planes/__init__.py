"""Execution plane adapters and attestation port abstraction (Issue #284).

Provides hardware and platform attestation abstraction across execution planes:
  - PlaneKind: closed enum of supported cloud / local execution planes
  - PlaneAssurance: declared, platform_attested, hardware_attested levels
  - PlaneAdapter: abstract port for plane attestation implementations
  - PlaneRegistry: centralized dispatcher and lifecycle registry
  - LocalPlaneAdapter, AwsNitroPlaneAdapter, AzureCvmPlaneAdapter, GcpConfidentialPlaneAdapter
"""

from aegis_trust.planes.types import (
    PlaneAssurance,
    PlaneError,
    PlaneErrorKind,
    PlaneEvidence,
    PlaneHealthStatus,
    PlaneKind,
    PlaneVerdict,
)
from aegis_trust.planes.port import PlaneAdapter
from aegis_trust.planes.registry import PlaneRegistry
from aegis_trust.planes.local import LocalPlaneAdapter
from aegis_trust.planes.aws import AwsNitroPlaneAdapter
from aegis_trust.planes.azure import AzureCvmPlaneAdapter
from aegis_trust.planes.gcp import GcpConfidentialPlaneAdapter

__all__ = [
    "PlaneKind",
    "PlaneAssurance",
    "PlaneEvidence",
    "PlaneVerdict",
    "PlaneHealthStatus",
    "PlaneError",
    "PlaneErrorKind",
    "PlaneAdapter",
    "PlaneRegistry",
    "LocalPlaneAdapter",
    "AwsNitroPlaneAdapter",
    "AzureCvmPlaneAdapter",
    "GcpConfidentialPlaneAdapter",
]
