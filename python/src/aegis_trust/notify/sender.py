"""Tier 2 Notification Sender with Idempotency Tracking (Issue #283).

Dispatches strictly value-free payloads across customer and optional vendor destinations.
Deduplicates via idempotency_key to prevent alerting storms.
"""

from __future__ import annotations

import collections
import logging
from typing import Iterable

from aegis_trust.notify.destinations import (
    NemoTekTelemetryDestination,
    NotificationDestination,
)
from aegis_trust.notify.types import NotificationPayload

logger = logging.getLogger("aegis.notify")


class IdempotencyCache:
    """In-memory bounded set for idempotency tracking."""

    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = capacity
        self._keys: collections.OrderedDict[str, bool] = collections.OrderedDict()

    def record_if_new(self, key: str) -> bool:
        """Returns True if key is new and recorded, False if already seen."""
        if key in self._keys:
            return False
        if len(self._keys) >= self.capacity:
            self._keys.popitem(last=False)
        self._keys[key] = True
        return True

    def clear(self) -> None:
        self._keys.clear()


class NotificationSender:
    """Coordinates notification delivery across configured destinations."""

    def __init__(
        self,
        destinations: Iterable[NotificationDestination] | None = None,
        *,
        enable_nemotek: bool = False,
        nemotek_endpoint: str | None = None,
        idempotency_capacity: int = 1000,
    ) -> None:
        self.destinations: list[NotificationDestination] = list(destinations or [])
        # Tier 3 NemoTek vendor telemetry is explicitly configured, default OFF
        self.nemotek_destination = NemoTekTelemetryDestination(
            enabled=enable_nemotek,
            endpoint_url=nemotek_endpoint,
        )
        self._idempotency = IdempotencyCache(capacity=idempotency_capacity)

    def add_destination(self, dest: NotificationDestination) -> None:
        self.destinations.append(dest)

    def notify(self, payload: NotificationPayload) -> dict[str, bool]:
        """Dispatch payload to all active destinations.

        Returns mapping of destination name/index to delivery success status.
        """
        # Deduplication check
        if payload.idempotency_key:
            is_new = self._idempotency.record_if_new(payload.idempotency_key)
            if not is_new:
                logger.debug(
                    "Suppressed duplicate notification key=%s", payload.idempotency_key
                )
                return {"deduplicated": True}

        results: dict[str, bool] = {}

        # 1. Deliver to customer destinations (Tier 2)
        for i, dest in enumerate(self.destinations):
            name = dest.__class__.__name__
            key = f"{name}_{i}"
            try:
                results[key] = dest.send(payload)
            except Exception as e:
                logger.warning("Error in destination %s: %s", key, e)
                results[key] = False

        # 2. Deliver to NemoTek Telemetry if explicitly enabled (Tier 3)
        if self.nemotek_destination.enabled:
            try:
                results["NemoTekTelemetry"] = self.nemotek_destination.send(payload)
            except Exception as e:
                logger.warning("Error in NemoTek telemetry: %s", e)
                results["NemoTekTelemetry"] = False

        return results
