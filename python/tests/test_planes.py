"""Test suite for execution plane adapters, cross-plane rejection, and error opacity (Issue #284)."""

import pytest
from aegis_trust.planes import (
    AwsNitroPlaneAdapter,
    AzureCvmPlaneAdapter,
    GcpConfidentialPlaneAdapter,
    LocalPlaneAdapter,
    PlaneAdapter,
    PlaneAssurance,
    PlaneError,
    PlaneErrorKind,
    PlaneEvidence,
    PlaneHealthStatus,
    PlaneKind,
    PlaneRegistry,
)


def test_plane_error_ao002_opacity():
    """AO-002: PlaneError Display / str MUST be empty string."""
    err = PlaneError(PlaneErrorKind.CROSS_PLANE_MISMATCH, "internal debug info")
    assert str(err) == "", "AO-002: PlaneError string representation must be empty"
    assert repr(err) == "PlaneError()"


def test_plane_kind_aliases():
    """Ensure PlaneKind resolves aliases correctly."""
    assert PlaneKind.from_str("aws") == PlaneKind.AWS
    assert PlaneKind.from_str("aws_nitro") == PlaneKind.AWS
    assert PlaneKind.from_str("azure_cvm") == PlaneKind.AZURE
    assert PlaneKind.from_str("gcp_confidential") == PlaneKind.GCP
    assert PlaneKind.from_str("oracle_cloud") == PlaneKind.ORACLE
    assert PlaneKind.from_str("local_dev") == PlaneKind.LOCAL

    with pytest.raises(ValueError):
        PlaneKind.from_str("unknown_plane")


def test_plane_assurance():
    """Ensure PlaneAssurance levels and properties work as expected."""
    assert PlaneAssurance.DECLARED == "declared"
    assert PlaneAssurance.PLATFORM_ATTESTED == "platform_attested"
    assert PlaneAssurance.HARDWARE_ATTESTED == "hardware_attested"
    assert PlaneAssurance.DECLARED.is_attested is False
    assert PlaneAssurance.PLATFORM_ATTESTED.is_attested is True
    assert PlaneAssurance.HARDWARE_ATTESTED.is_hardware is True


def test_plane_evidence_ref():
    """Ensure evidence_ref is 64-char sha256 hex."""
    adapter = LocalPlaneAdapter()
    evidence = adapter.attest(b"nonce-1234")
    eref = evidence.evidence_ref()
    assert len(eref) == 64
    assert all(c in "0123456789abcdef" for c in eref)


def test_all_adapters_satisfy_port():
    """All adapters must implement PlaneAdapter port methods."""
    adapters = [
        LocalPlaneAdapter(),
        AwsNitroPlaneAdapter(),
        AzureCvmPlaneAdapter(),
        GcpConfidentialPlaneAdapter(),
    ]
    nonce = b"test-nonce-12345678"

    for adapter in adapters:
        assert isinstance(adapter, PlaneAdapter)
        assert adapter.health_check() == PlaneHealthStatus.HEALTHY

        evidence = adapter.attest(nonce)
        assert isinstance(evidence, PlaneEvidence)
        assert evidence.plane == adapter.plane_kind()
        assert evidence.nonce == nonce

        verdict = adapter.verify(evidence, nonce)
        assert verdict.valid is True
        assert verdict.plane == adapter.plane_kind()
        assert verdict.evidence_ref == evidence.evidence_ref()


def test_cross_plane_rejection_at_port_layer():
    """Cross-plane verification MUST be rejected fail-closed with PlaneError.

    Passing AWS evidence to Azure/GCP/Local adapter must fail.
    """
    adapters = {
        PlaneKind.LOCAL: LocalPlaneAdapter(),
        PlaneKind.AWS: AwsNitroPlaneAdapter(),
        PlaneKind.AZURE: AzureCvmPlaneAdapter(),
        PlaneKind.GCP: GcpConfidentialPlaneAdapter(),
    }
    nonce = b"uniform-nonce-9999"

    for source_kind, source_adapter in adapters.items():
        evidence = source_adapter.attest(nonce)

        for target_kind, target_adapter in adapters.items():
            if source_kind == target_kind:
                continue

            with pytest.raises(PlaneError) as exc_info:
                target_adapter.verify(evidence, nonce)

            assert exc_info.value.kind == PlaneErrorKind.CROSS_PLANE_MISMATCH
            assert str(exc_info.value) == ""  # AO-002 check


def test_nonce_mismatch_rejected():
    """Nonce mismatch must fail closed."""
    adapter = LocalPlaneAdapter()
    evidence = adapter.attest(b"nonce-AAA")

    with pytest.raises(PlaneError) as exc_info:
        adapter.verify(evidence, b"nonce-BBB")

    assert exc_info.value.kind == PlaneErrorKind.NONCE_MISMATCH
    assert str(exc_info.value) == ""


def test_registry_dispatch():
    """PlaneRegistry registers, retrieves, and dispatches across planes."""
    reg = PlaneRegistry()
    reg.register(LocalPlaneAdapter())
    reg.register(AwsNitroPlaneAdapter())
    reg.register(AzureCvmPlaneAdapter())
    reg.register(GcpConfidentialPlaneAdapter())

    assert len(reg) == 4
    assert reg.contains(PlaneKind.AWS)
    assert reg.contains(PlaneKind.LOCAL)
    assert not reg.contains(PlaneKind.ORACLE)

    nonce = b"registry-nonce"
    for plane in [PlaneKind.LOCAL, PlaneKind.AWS, PlaneKind.AZURE, PlaneKind.GCP]:
        ev = reg.attest(plane, nonce)
        verdict = reg.verify(ev, nonce)
        assert verdict.valid is True
        assert verdict.plane == plane
        assert reg.health_check(plane) == PlaneHealthStatus.HEALTHY

    # Unregistered plane fails closed
    with pytest.raises(PlaneError) as exc_info:
        reg.attest(PlaneKind.ORACLE, nonce)
    assert exc_info.value.kind == PlaneErrorKind.PLANE_UNAVAILABLE
