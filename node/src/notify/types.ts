/**
 * Notification types and invariants for aegis-trust (Node/TypeScript parity).
 *
 * Implements the 3-tier notification architecture (Issue #283):
 * - Tier 1: Observation (invariants preserved, zero egress, INV-3 satisfied)
 * - Tier 2: Emitter & Delivery components (optional dependency, customer destinations)
 * - Tier 3: Vendor Telemetry destination (default OFF, explicit customer opt-in only)
 *
 * Value-free guarantee (AO-002):
 * - Field names and metadata ONLY, never values or ciphertext.
 * - Three-state health model: HEALTHY / UNHEALTHY / UNKNOWN (never round UNKNOWN to green).
 */

export enum HealthState {
  HEALTHY = "healthy",
  UNHEALTHY = "unhealthy",
  UNKNOWN = "unknown",
}

export const VALUE_FREE_ALLOWED_KEYS = new Set([
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
]);

export const FORBIDDEN_VALUE_KEYS = new Set([
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
]);

export class ValueFreeViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValueFreeViolationError";
  }
}

export interface NotificationPayload {
  schema_version: number;
  timestamp: string;
  event_type: string;
  health_state: HealthState;
  reason_codes: string[];
  dropped_fields: string[];
  violation_count: number;
  trace_id?: string | null;
  mode: string;
  idempotency_key?: string | null;
  summary: string;
}

export function validateValueFreeDict(record: Record<string, unknown>): void {
  for (const k of Object.keys(record)) {
    if (FORBIDDEN_VALUE_KEYS.has(k)) {
      throw new ValueFreeViolationError(`Forbidden value-carrying key detected: ${k}`);
    }
    if (!VALUE_FREE_ALLOWED_KEYS.has(k)) {
      throw new ValueFreeViolationError(`Key not in value-free allowlist: ${k}`);
    }
  }
}
