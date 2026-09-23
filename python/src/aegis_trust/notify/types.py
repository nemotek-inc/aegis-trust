"""Notification types and invariants for aegis_trust.

Implements the 3-tier notification architecture (Issue #283):
- Tier 1: Observation (invariants preserved, zero egress, INV-3 satisfied)
- Tier 2: Emitter & Delivery components (optional dependency, customer destinations)
- Tier 3: Vendor Telemetry destination (default OFF, explicit customer opt-in only)

Value-free guarantee (AO-002):
- Field names and metadata ONLY, never values or ciphertext.
- Three-state health model: HEALTHY / UNHEALTHY / UNKNOWN (never round UNKNOWN to green).
"""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class HealthState(str, enum.Enum):
    """Three-value health representation per aegis-boundary-core#281 and Issue #283.

    - HEALTHY: normal operation, zero violations
    - UNHEALTHY: observed policy violation, access denial, or degraded state
    - UNKNOWN: unmeasurable, disconnected, or inconclusive (MUST NEVER be rounded to green)
    """

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# Allowed top-level fields for value-free notification payloads (AO-002 strict allowlist)
VALUE_FREE_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "timestamp",
        "event_type",
        "health_state",
        "reason_codes",
        "dropped_fields",
        "violation_count",
        "trace_id",
        "mode",
        "idempotency_key",
        "summary",
    }
)

# Forbidden keys that could carry customer data or values
FORBIDDEN_VALUE_KEYS = frozenset(
    {
        "value",
        "values",
        "payload",
        "data",
        "raw",
        "content",
        "ciphertext",
        "record",
        "row",
        "body",
        "secret",
        "key",
    }
)


class ValueFreeViolationError(ValueError):
    """Raised when a notification payload contains raw field values or disallowed keys."""


@dataclass(frozen=True)
class NotificationPayload:
    """Strictly value-free notification payload (AO-002).

    Carries metadata, field names, and health state only. Never values or secrets.
    """

    event_type: str
    health_state: HealthState
    reason_codes: list[str] = field(default_factory=list)
    dropped_fields: list[str] = field(default_factory=list)
    violation_count: int = 0
    trace_id: str | None = None
    mode: str = "LITE"
    idempotency_key: str | None = None
    summary: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: int = 1

    def __post_init__(self) -> None:
        # Validate that dropped_fields contains only field names (strings)
        for f in self.dropped_fields:
            if not isinstance(f, str):
                raise ValueFreeViolationError(
                    f"dropped_fields must be list of strings, got {type(f).__name__}"
                )
        # Validate health state is valid enum
        if not isinstance(self.health_state, HealthState):
            raise ValueFreeViolationError(f"Invalid health_state: {self.health_state}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["health_state"] = self.health_state.value
        # Check against value-free invariant
        validate_value_free_dict(d)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def validate_value_free_dict(data: dict[str, Any]) -> None:
    """Enforce AO-002: verify that a dictionary contains ONLY permitted value-free keys.

    Raises ValueFreeViolationError if forbidden keys or unknown keys are present.
    """
    for k in data:
        if k in FORBIDDEN_VALUE_KEYS:
            raise ValueFreeViolationError(f"Forbidden value-carrying key detected: {k}")
        if k not in VALUE_FREE_ALLOWED_KEYS:
            raise ValueFreeViolationError(f"Key not in value-free allowlist: {k}")
