"""Dynamic registry and dispatcher for execution plane adapters."""

from __future__ import annotations

from typing import Dict
from aegis_trust.planes.port import PlaneAdapter
from aegis_trust.planes.types import (
    PlaneError,
    PlaneErrorKind,
    PlaneEvidence,
    PlaneHealthStatus,
    PlaneKind,
    PlaneVerdict,
)


class PlaneRegistry:
    """Registry and dispatcher managing execution plane adapters.

    Provides centralized routing for attestation generation, verification,
    and health status probes across supported execution planes.
    """

    def __init__(self) -> None:
        self._adapters: Dict[PlaneKind, PlaneAdapter] = {}

    def register(self, adapter: PlaneAdapter) -> None:
        """Register a plane adapter. Replaces any existing adapter for same plane."""
        self._adapters[adapter.plane_kind()] = adapter

    def get(self, plane: PlaneKind) -> PlaneAdapter | None:
        """Retrieve registered adapter for given plane kind."""
        return self._adapters.get(plane)

    def contains(self, plane: PlaneKind) -> bool:
        """Check whether an adapter is registered for given plane kind."""
        return plane in self._adapters

    def __len__(self) -> int:
        return len(self._adapters)

    def attest(self, plane: PlaneKind, nonce: bytes) -> PlaneEvidence:
        """Generate attestation on the specified plane."""
        adapter = self._adapters.get(plane)
        if adapter is None:
            raise PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE)
        return adapter.attest(nonce)

    def verify(self, evidence: PlaneEvidence, expected_nonce: bytes) -> PlaneVerdict:
        """Verify attestation evidence by dispatching to the adapter for evidence.plane."""
        adapter = self._adapters.get(evidence.plane)
        if adapter is None:
            raise PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE)
        return adapter.verify(evidence, expected_nonce)

    def health_check(self, plane: PlaneKind) -> PlaneHealthStatus:
        """Probe health status of the specified plane."""
        adapter = self._adapters.get(plane)
        if adapter is None:
            raise PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE)
        return adapter.health_check()
