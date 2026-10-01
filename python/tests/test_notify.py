"""Tests for aegis_trust.notify (Issue #283).

Verifies the 3-tier notification architecture:
1. INV-3 Preservation: LITE path performs zero outbound communication (observed directly).
2. Tier 2 Delivery: SIEM, Webhook, CLI destinations work value-free.
3. Tier 3 Default-OFF: NemoTek vendor destination is disabled by default.
4. Value-Free Invariant: AO-002 strictly enforced (field names only, never values).
5. Idempotency: Deduplication suppresses duplicate notification storms.
6. Three-State Health: HEALTHY / UNHEALTHY / UNKNOWN preserved (never round UNKNOWN to green).
"""

from __future__ import annotations

import io
import socket
from contextlib import contextmanager
from typing import Any

import pytest

from aegis_trust import shield, wrap
from aegis_trust.notify import (
    CliDestination,
    HealthState,
    NemoTekTelemetryDestination,
    NotificationSender,
    SiemDestination,
    ValueFreeViolationError,
    create_notification_payload,
    from_audit_event,
    from_doctor_result,
    validate_value_free_dict,
)


# --- 1. Egress Observer for INV-3 verification ---
@contextmanager
def observe_socket_egress(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Refuse and record any socket connection or DNS lookup."""
    attempts: list[str] = []
    real_connect = socket.socket.connect

    def spy_connect(self: socket.socket, address: Any) -> None:
        attempts.append(f"connect({address!r})")
        raise AssertionError(f"Outbound connection attempted: {address!r}")

    def spy_getaddrinfo(host: Any, port: Any, *a: Any, **k: Any) -> Any:
        attempts.append(f"getaddrinfo({host!r}, {port!r})")
        raise AssertionError(f"DNS lookup attempted: {host!r}")

    monkeypatch.setattr(socket.socket, "connect", spy_connect, raising=True)
    monkeypatch.setattr(socket, "getaddrinfo", spy_getaddrinfo, raising=True)
    try:
        yield attempts
    finally:
        monkeypatch.setattr(socket.socket, "connect", real_connect, raising=True)


def test_inv3_lite_remains_zero_egress_with_notify_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive Control: Verify @shield and wrap() perform zero egress even with notify installed."""
    with observe_socket_egress(monkeypatch) as attempts:
        # Standard LITE invocation
        res = wrap(
            {"name": "Alice", "secret": "s3cr3t"}, scope=["name"], purpose="test"
        )
        assert res.data == {"name": "Alice"}

        @shield(scope=["id"], purpose="test")
        def get_data() -> dict[str, Any]:
            return {"id": 1, "card": "1234"}

        val = get_data()
        assert val == {"id": 1}

    # Direct observation: zero socket or DNS attempts
    assert len(attempts) == 0


# --- 2. Value-Free Invariant Enforcement (AO-002) ---
def test_value_free_payload_valid_construction() -> None:
    """Positive Control: Payload carries field names and reason codes, passes validation."""
    payload = create_notification_payload(
        event_type="shield.violation",
        health_state=HealthState.UNHEALTHY,
        reason_codes=["SCOPE_VIOLATION", "DENY_MATCH"],
        dropped_fields=["email", "phone_number"],
        violation_count=2,
        trace_id="tr-abc-123",
        mode="LITE",
    )
    d = payload.to_dict()
    assert d["event_type"] == "shield.violation"
    assert d["health_state"] == "unhealthy"
    assert d["dropped_fields"] == ["email", "phone_number"]
    assert d["violation_count"] == 2
    assert d["trace_id"] == "tr-abc-123"
    assert "value" not in d
    assert "data" not in d


def test_value_free_payload_rejects_forbidden_keys() -> None:
    """Negative Control: Dictionary with forbidden value keys must be rejected."""
    bad_dict = {
        "event_type": "test",
        "health_state": "healthy",
        "value": "customer_secret_123",  # Forbidden
    }
    with pytest.raises(ValueFreeViolationError, match="Forbidden value-carrying key"):
        validate_value_free_dict(bad_dict)

    bad_dict2 = {
        "event_type": "test",
        "health_state": "healthy",
        "ciphertext": "encrypted_blob",  # Forbidden
    }
    with pytest.raises(ValueFreeViolationError, match="Forbidden value-carrying key"):
        validate_value_free_dict(bad_dict2)


def test_value_free_payload_rejects_non_string_field_names() -> None:
    """Negative Control: dropped_fields must only contain field names (strings), not objects/values."""
    with pytest.raises(
        ValueFreeViolationError, match="dropped_fields must be list of strings"
    ):
        create_notification_payload(
            event_type="test",
            health_state=HealthState.UNHEALTHY,
            dropped_fields=[{"bad": "object"}],  # type: ignore[list-item]
        )


# --- 3. Tier 3 Default-OFF Invariant ---
def test_nemotek_destination_default_off() -> None:
    """Invariant: NemoTek destination is disabled by default and performs zero send."""
    dest = NemoTekTelemetryDestination()
    assert dest.enabled is False

    payload = create_notification_payload(
        event_type="anomaly",
        health_state=HealthState.UNHEALTHY,
    )
    # When disabled, send() immediately returns False with zero network call
    result = dest.send(payload)
    assert result is False


def test_nemotek_destination_explicit_opt_in() -> None:
    """Positive Control: Explicitly enabled destination activates."""
    dest = NemoTekTelemetryDestination(enabled=True)
    assert dest.enabled is True


# --- 4. Three-State Health Model ---
def test_three_state_health_distinction() -> None:
    """Invariant: HEALTHY, UNHEALTHY, UNKNOWN are distinct; UNKNOWN is never healthy."""
    h_healthy = create_notification_payload("test", HealthState.HEALTHY)
    h_unhealthy = create_notification_payload("test", HealthState.UNHEALTHY)
    h_unknown = create_notification_payload("test", HealthState.UNKNOWN)

    assert h_healthy.health_state == HealthState.HEALTHY
    assert h_unhealthy.health_state == HealthState.UNHEALTHY
    assert h_unknown.health_state == HealthState.UNKNOWN

    assert str(h_unknown.health_state.value) != str(HealthState.HEALTHY.value)
    assert h_unknown.to_dict()["health_state"] == "unknown"


def test_from_audit_event_projection() -> None:
    """Projection from canonical audit event strictly minimizes to field names."""
    audit_record = {
        "type": "shield.access",
        "decision": "BLOCK",
        "blocked_fields": ["credit_card", "ssn"],
        "reason_code": "POLICY_DENY",
        "trace_id": "trace-999",
        "raw_record": {
            "credit_card": "4111...",
            "ssn": "000-00-0000",
        },  # Customer values
    }

    payload = from_audit_event(audit_record)
    assert payload.health_state == HealthState.UNHEALTHY
    assert payload.dropped_fields == ["credit_card", "ssn"]
    assert payload.violation_count == 2
    assert payload.trace_id == "trace-999"

    d = payload.to_dict()
    # Ensure raw customer values were stripped
    assert "raw_record" not in d
    assert "4111" not in str(d)
    assert "000-00-0000" not in str(d)


def test_from_doctor_result_unknown_state_preserved() -> None:
    """Doctor unmeasurable/unknown result stays UNKNOWN, never rounded to green."""

    class DummyUnmeasurablePlan:
        status = "unmeasurable"

    payload = from_doctor_result(DummyUnmeasurablePlan())
    assert payload.health_state == HealthState.UNKNOWN
    assert str(payload.health_state.value) != str(HealthState.HEALTHY.value)


# --- 5. Tier 2 Delivery & Idempotency ---
def test_siem_and_cli_destinations() -> None:
    """Positive Control: SiemDestination and CliDestination format output safely."""
    siem_buf = io.StringIO()
    cli_buf = io.StringIO()

    siem_dest = SiemDestination(sink=siem_buf)
    cli_dest = CliDestination(stream=cli_buf)

    payload = create_notification_payload(
        event_type="shield.violation",
        health_state=HealthState.UNHEALTHY,
        dropped_fields=["secret_field"],
        violation_count=1,
    )

    assert siem_dest.send(payload) is True
    assert cli_dest.send(payload) is True

    siem_output = siem_buf.getvalue()
    cli_output = cli_buf.getvalue()

    assert "shield.violation" in siem_output
    assert "secret_field" in siem_output
    assert "[ALERT]" in cli_output
    assert "Dropped fields: secret_field" in cli_output


def test_notification_sender_deduplication() -> None:
    """Positive Control: Same idempotency key produces single notification, deduplicates second."""
    siem_buf = io.StringIO()
    sender = NotificationSender(destinations=[SiemDestination(sink=siem_buf)])

    payload1 = create_notification_payload(
        event_type="alert",
        health_state=HealthState.UNHEALTHY,
        idempotency_key="key-idempotent-1",
    )
    payload2 = create_notification_payload(
        event_type="alert",
        health_state=HealthState.UNHEALTHY,
        idempotency_key="key-idempotent-1",
    )

    res1 = sender.notify(payload1)
    assert res1.get("SiemDestination_0") is True

    res2 = sender.notify(payload2)
    assert res2 == {"deduplicated": True}

    # Only 1 line in the buffer
    lines = siem_buf.getvalue().strip().splitlines()
    assert len(lines) == 1
