"""aegis_trust.notify — Value-free product status notification system (Issue #283).

Three-Tier Separation Architecture:
- Tier 1: Observation (history / doctor, strictly zero outbound communication, INV-3 satisfied)
- Tier 2: Emitter & Delivery components (SIEM / Webhook / CLI triad, optional dependency)
- Tier 3: Vendor Telemetry destination (default OFF, customer explicit opt-in only)

Value-free guarantee (AO-002):
- Notifications carry field names, reason codes, trace ids, and health state only.
- Never values, ciphertext, or customer records.
"""

from __future__ import annotations

from aegis_trust.notify.destinations import (
    CliDestination,
    NemoTekTelemetryDestination,
    NotificationDestination,
    SiemDestination,
    WebhookDestination,
)
from aegis_trust.notify.payload import (
    create_notification_payload,
    from_audit_event,
    from_doctor_result,
)
from aegis_trust.notify.sender import IdempotencyCache, NotificationSender
from aegis_trust.notify.types import (
    FORBIDDEN_VALUE_KEYS,
    VALUE_FREE_ALLOWED_KEYS,
    HealthState,
    NotificationPayload,
    ValueFreeViolationError,
    validate_value_free_dict,
)

__all__ = [
    "CliDestination",
    "FORBIDDEN_VALUE_KEYS",
    "HealthState",
    "IdempotencyCache",
    "NemoTekTelemetryDestination",
    "NotificationDestination",
    "NotificationPayload",
    "NotificationSender",
    "SiemDestination",
    "VALUE_FREE_ALLOWED_KEYS",
    "ValueFreeViolationError",
    "WebhookDestination",
    "create_notification_payload",
    "from_audit_event",
    "from_doctor_result",
    "validate_value_free_dict",
]
