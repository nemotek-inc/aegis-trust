"""Notification payload constructors and projections (Issue #283).

Strictly value-free projection from internal observation models:
- canonical audit event -> value-free notification
- doctor diagnostic results -> value-free notification (three-state: HEALTHY/UNHEALTHY/UNKNOWN)
"""

from __future__ import annotations

import hashlib
from typing import Any

from aegis_trust.notify.types import (
    HealthState,
    NotificationPayload,
    validate_value_free_dict,
)


def compute_idempotency_key(
    event_type: str, reason_codes: list[str], trace_id: str | None, state: str
) -> str:
    """Compute deterministic idempotency key for deduplication."""
    content = f"{event_type}:{','.join(sorted(reason_codes))}:{trace_id or ''}:{state}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]


def create_notification_payload(
    event_type: str,
    health_state: HealthState,
    *,
    reason_codes: list[str] | None = None,
    dropped_fields: list[str] | None = None,
    violation_count: int = 0,
    trace_id: str | None = None,
    mode: str = "LITE",
    idempotency_key: str | None = None,
    summary: str = "",
) -> NotificationPayload:
    """Create a strictly value-free NotificationPayload.

    Raises ValueFreeViolationError if forbidden values or invalid types are supplied.
    """
    reasons = list(reason_codes or [])
    fields = list(dropped_fields or [])

    # Idempotency key generation if not supplied
    if not idempotency_key:
        idempotency_key = compute_idempotency_key(
            event_type, reasons, trace_id, health_state.value
        )

    payload = NotificationPayload(
        event_type=event_type,
        health_state=health_state,
        reason_codes=reasons,
        dropped_fields=fields,
        violation_count=violation_count,
        trace_id=trace_id,
        mode=mode,
        idempotency_key=idempotency_key,
        summary=summary,
    )
    # Double check dict representation against allowlist
    validate_value_free_dict(payload.to_dict())
    return payload


def from_audit_event(event: dict[str, Any]) -> NotificationPayload:
    """Project a canonical audit event record into a value-free notification payload.

    Extracts field names, reason codes, trace id, and event metadata.
    NEVER forwards values or data payloads.
    """
    event_type = str(event.get("event_type") or event.get("type") or "audit.event")
    trace_id = event.get("trace_id")
    mode = str(event.get("mode") or "LITE")

    # Extract field names safely (AO-002: field names only)
    dropped: list[str] = []
    if "blocked_fields" in event and isinstance(event["blocked_fields"], (list, tuple)):
        dropped.extend(str(f) for f in event["blocked_fields"])
    if "deny_fields" in event and isinstance(event["deny_fields"], (list, tuple)):
        dropped.extend(str(f) for f in event["deny_fields"])

    reasons: list[str] = []
    if "reason_code" in event and event["reason_code"]:
        reasons.append(str(event["reason_code"]))
    if "reasons" in event and isinstance(event["reasons"], (list, tuple)):
        reasons.extend(str(r) for r in event["reasons"])

    violation_count = len(dropped)

    # Determine health state
    decision = str(event.get("decision") or "").upper()
    if decision in ("BLOCK", "DENY") or violation_count > 0:
        health_state = HealthState.UNHEALTHY
    elif decision in ("ALLOW", "PERMIT", "OK"):
        health_state = HealthState.HEALTHY
    else:
        # Inconclusive or unmeasurable - NEVER round to green
        health_state = HealthState.UNKNOWN

    return create_notification_payload(
        event_type=event_type,
        health_state=health_state,
        reason_codes=reasons,
        dropped_fields=dropped,
        violation_count=violation_count,
        trace_id=trace_id,
        mode=mode,
        idempotency_key=event.get("idempotency_key"),
        summary=f"Audit event {event_type} with {violation_count} blocked field(s)",
    )


def from_doctor_result(plan: Any) -> NotificationPayload:
    """Project an ActionPlan from aegis_trust.doctor into a value-free notification.

    Preserves 3-state health model (HEALTHY / UNHEALTHY / UNKNOWN).
    """
    # Safely inspect ActionPlan attributes
    actions = getattr(plan, "actions", [])
    errors = getattr(plan, "errors", [])
    status = getattr(plan, "status", None)

    reason_codes: list[str] = []
    if hasattr(plan, "reason_code") and plan.reason_code:
        reason_codes.append(str(plan.reason_code))

    for act in actions:
        code = getattr(act, "code", None) or getattr(act, "name", None)
        if code:
            reason_codes.append(str(code))

    # Health state evaluation
    if errors or (
        actions and any(getattr(a, "severity", "warning") == "error" for a in actions)
    ):
        health_state = HealthState.UNHEALTHY
    elif (
        status == "unmeasurable" or status == "unknown" or not hasattr(plan, "actions")
    ):
        # Unmeasurable diagnosis - never round to healthy
        health_state = HealthState.UNKNOWN
    elif not actions and not errors:
        health_state = HealthState.HEALTHY
    else:
        health_state = HealthState.UNHEALTHY

    return create_notification_payload(
        event_type="doctor.diagnosis",
        health_state=health_state,
        reason_codes=reason_codes,
        dropped_fields=[],
        violation_count=len(errors) + len(actions),
        summary=f"Doctor report: {len(actions)} action(s), {len(errors)} error(s)",
    )
