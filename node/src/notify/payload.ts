/**
 * Notification payload constructors and projections (Issue #283).
 */

import { createHash } from "node:crypto";
import {
  HealthState,
  NotificationPayload,
  ValueFreeViolationError,
  validateValueFreeDict,
} from "./types.js";

export function computeIdempotencyKey(
  eventType: string,
  reasonCodes: string[],
  traceId: string | null | undefined,
  state: string,
): string {
  const sortedReasons = [...reasonCodes].sort().join(",");
  const content = `${eventType}:${sortedReasons}:${traceId ?? ""}:${state}`;
  return createHash("sha256").update(content, "utf8").digest("hex").slice(0, 32);
}

export interface CreateNotificationPayloadOptions {
  eventType: string;
  healthState: HealthState;
  reasonCodes?: string[];
  droppedFields?: string[];
  violationCount?: number;
  traceId?: string | null;
  mode?: string;
  idempotencyKey?: string | null;
  summary?: string;
  timestamp?: string;
  schemaVersion?: number;
}

export function createNotificationPayload(
  options: CreateNotificationPayloadOptions,
): NotificationPayload {
  const reasons = options.reasonCodes ?? [];
  const fields = options.droppedFields ?? [];

  for (const f of fields) {
    if (typeof f !== "string") {
      throw new ValueFreeViolationError(
        `dropped_fields must be list of strings, got ${typeof f}`,
      );
    }
  }

  const idempotencyKey =
    options.idempotencyKey ??
    computeIdempotencyKey(
      options.eventType,
      reasons,
      options.traceId,
      options.healthState,
    );

  const payload: NotificationPayload = {
    schema_version: options.schemaVersion ?? 1,
    timestamp: options.timestamp ?? new Date().toISOString(),
    event_type: options.eventType,
    health_state: options.healthState,
    reason_codes: reasons,
    dropped_fields: fields,
    violation_count: options.violationCount ?? fields.length,
    trace_id: options.traceId ?? null,
    mode: options.mode ?? "LITE",
    idempotency_key: idempotencyKey,
    summary: options.summary ?? "",
  };

  validateValueFreeDict(payload as unknown as Record<string, unknown>);
  return payload;
}

export function fromAuditEvent(event: Record<string, unknown>): NotificationPayload {
  const eventType = String(event.event_type ?? event.type ?? "audit.event");
  const traceId = typeof event.trace_id === "string" ? event.trace_id : null;
  const mode = String(event.mode ?? "LITE");

  const dropped: string[] = [];
  if (Array.isArray(event.blocked_fields)) {
    dropped.push(...event.blocked_fields.map(String));
  }
  if (Array.isArray(event.deny_fields)) {
    dropped.push(...event.deny_fields.map(String));
  }

  const reasons: string[] = [];
  if (event.reason_code) {
    reasons.push(String(event.reason_code));
  }
  if (Array.isArray(event.reasons)) {
    reasons.push(...event.reasons.map(String));
  }

  const violationCount = dropped.length;
  const decision = String(event.decision ?? "").toUpperCase();
  let healthState: HealthState;

  if (decision === "BLOCK" || decision === "DENY" || violationCount > 0) {
    healthState = HealthState.UNHEALTHY;
  } else if (decision === "ALLOW" || decision === "PERMIT" || decision === "OK") {
    healthState = HealthState.HEALTHY;
  } else {
    // Inconclusive: NEVER round to healthy
    healthState = HealthState.UNKNOWN;
  }

  return createNotificationPayload({
    eventType,
    healthState,
    reasonCodes: reasons,
    droppedFields: dropped,
    violationCount,
    traceId,
    mode,
    idempotencyKey:
      typeof event.idempotency_key === "string" ? event.idempotency_key : null,
    summary: `Audit event ${eventType} with ${violationCount} blocked field(s)`,
  });
}

export function fromDoctorResult(plan: unknown): NotificationPayload {
  const obj = (plan && typeof plan === "object" ? plan : {}) as Record<string, unknown>;
  const actions = Array.isArray(obj.actions) ? obj.actions : [];
  const errors = Array.isArray(obj.errors) ? obj.errors : [];
  const status = typeof obj.status === "string" ? obj.status : null;

  const reasonCodes: string[] = [];
  if (obj.reason_code) {
    reasonCodes.push(String(obj.reason_code));
  }

  for (const act of actions) {
    if (act && typeof act === "object") {
      const code = (act as Record<string, unknown>).code ?? (act as Record<string, unknown>).name;
      if (code) reasonCodes.push(String(code));
    }
  }

  let healthState: HealthState;
  if (errors.length > 0 || actions.some((a) => (a as Record<string, unknown>)?.severity === "error")) {
    healthState = HealthState.UNHEALTHY;
  } else if (status === "unmeasurable" || status === "unknown" || !("actions" in obj)) {
    healthState = HealthState.UNKNOWN;
  } else if (actions.length === 0 && errors.length === 0) {
    healthState = HealthState.HEALTHY;
  } else {
    healthState = HealthState.UNHEALTHY;
  }

  return createNotificationPayload({
    eventType: "doctor.diagnosis",
    healthState,
    reasonCodes,
    droppedFields: [],
    violationCount: errors.length + actions.length,
    summary: `Doctor report: ${actions.length} action(s), ${errors.length} error(s)`,
  });
}
