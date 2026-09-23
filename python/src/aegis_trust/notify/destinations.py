"""Notification destinations for Issue #283 (SIEM / Webhook / CLI triad).

Tier 2 & Tier 3 Delivery components:
- WebhookDestination: HTTP POST to customer endpoint (optional httpx)
- SiemDestination: Stream/Syslog output for SIEM ingestion (JSON lines)
- CliDestination: Formatted human/agent diagnostics
- NemoTekTelemetryDestination: Tier 3 vendor telemetry (default OFF, explicit opt-in only)
"""

from __future__ import annotations

import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import TextIO

from aegis_trust.notify.types import NotificationPayload

logger = logging.getLogger("aegis.notify")


class NotificationDestination(ABC):
    """Abstract destination sink for value-free notifications."""

    @abstractmethod
    def send(self, payload: NotificationPayload) -> bool:
        """Deliver payload. Returns True if successfully accepted/sent."""


class WebhookDestination(NotificationDestination):
    """Sends notification JSON via HTTP POST to a customer-controlled webhook.

    Requires optional 'httpx' dependency.
    """

    def __init__(
        self,
        endpoint_url: str,
        *,
        timeout_sec: float = 5.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.timeout_sec = timeout_sec
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def send(self, payload: NotificationPayload) -> bool:
        try:
            import httpx
        except ImportError as e:
            raise ImportError(
                "WebhookDestination requires 'httpx'. Install via `pip install 'aegis-trust[full]'` "
                "or `pip install 'aegis-trust[notify]'`"
            ) from e

        json_data = payload.to_dict()
        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                resp = client.post(
                    self.endpoint_url, json=json_data, headers=self.headers
                )
                return resp.is_success
        except Exception as exc:
            logger.warning(
                "Failed to send notification to webhook %s: %s", self.endpoint_url, exc
            )
            return False


class SiemDestination(NotificationDestination):
    """Formats notification as canonical JSON-lines for SIEM/logging collectors."""

    def __init__(self, sink: TextIO | None = None) -> None:
        self.sink = sink or sys.stderr

    def send(self, payload: NotificationPayload) -> bool:
        try:
            line = payload.to_json() + "\n"
            self.sink.write(line)
            self.sink.flush()
            return True
        except Exception as exc:
            logger.warning("Failed to write to SIEM sink: %s", exc)
            return False


class CliDestination(NotificationDestination):
    """Formats notification for CLI diagnostic output."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stderr

    def send(self, payload: NotificationPayload) -> bool:
        try:
            status_symbol = {
                "healthy": "[OK]",
                "unhealthy": "[ALERT]",
                "unknown": "[UNKNOWN]",
            }.get(payload.health_state.value, "[NOTICE]")

            msg = (
                f"{status_symbol} Aegis Notification: {payload.event_type} "
                f"(state={payload.health_state.value}, violations={payload.violation_count})\n"
            )
            if payload.dropped_fields:
                msg += f"  Dropped fields: {', '.join(payload.dropped_fields)}\n"
            if payload.reason_codes:
                msg += f"  Reason codes: {', '.join(payload.reason_codes)}\n"
            self.stream.write(msg)
            self.stream.flush()
            return True
        except Exception as exc:
            logger.warning("Failed to output CLI notification: %s", exc)
            return False


class NemoTekTelemetryDestination(NotificationDestination):
    """Tier 3 Destination for vendor anomaly reporting.

    DEFAULT OFF: Customer must explicitly opt in via enable_nemotek=True
    or AEGIS_TELEMETRY_NEMOTEK=1 environment variable.

    Payload is strictly value-free (field names, reason codes, trace id only).
    """

    DEFAULT_TELEMETRY_ENDPOINT = "https://telemetry.aegisagentcontrol.com/v0/reports"

    def __init__(
        self,
        *,
        enabled: bool = False,
        endpoint_url: str | None = None,
        timeout_sec: float = 3.0,
    ) -> None:
        # Explicit argument takes precedence; otherwise environment variable. Default is False.
        env_enabled = os.environ.get("AEGIS_TELEMETRY_NEMOTEK", "0").lower() in (
            "1",
            "true",
            "yes",
        )
        self.enabled = enabled or env_enabled
        self.endpoint_url = endpoint_url or self.DEFAULT_TELEMETRY_ENDPOINT
        self.timeout_sec = timeout_sec

    def send(self, payload: NotificationPayload) -> bool:
        if not self.enabled:
            # Invariant 3: Zero egress when not opted-in
            return False

        try:
            import httpx
        except ImportError:
            # If dependency is absent, fail-closed without network attempt
            return False

        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                resp = client.post(
                    self.endpoint_url,
                    json=payload.to_dict(),
                    headers={"Content-Type": "application/json"},
                )
                return resp.is_success
        except Exception as exc:
            logger.debug("NemoTek telemetry dispatch failed: %s", exc)
            return False
