/**
 * Tests for aegis-trust notify (Node).
 */

import { describe, expect, it } from "vitest";
import {
  CliDestination,
  HealthState,
  NemoTekTelemetryDestination,
  NotificationSender,
  SiemDestination,
  ValueFreeViolationError,
  createNotificationPayload,
  fromAuditEvent,
  fromDoctorResult,
  validateValueFreeDict,
} from "../src/notify/index.js";

describe("notify (Node)", () => {
  it("creates valid value-free payload", () => {
    const payload = createNotificationPayload({
      eventType: "shield.violation",
      healthState: HealthState.UNHEALTHY,
      reasonCodes: ["SCOPE_VIOLATION"],
      droppedFields: ["email"],
      violationCount: 1,
      traceId: "tr-node-1",
    });

    expect(payload.event_type).toBe("shield.violation");
    expect(payload.health_state).toBe(HealthState.UNHEALTHY);
    expect(payload.dropped_fields).toEqual(["email"]);
    expect(payload.violation_count).toBe(1);
    expect(payload.trace_id).toBe("tr-node-1");
  });

  it("rejects forbidden value-carrying keys", () => {
    expect(() => {
      validateValueFreeDict({
        event_type: "test",
        health_state: HealthState.HEALTHY,
        value: "customer_secret",
      });
    }).toThrow(ValueFreeViolationError);

    expect(() => {
      validateValueFreeDict({
        event_type: "test",
        health_state: HealthState.HEALTHY,
        ciphertext: "encrypted_blob",
      });
    }).toThrow(ValueFreeViolationError);
  });

  it("tier 3 NemoTek destination is disabled by default", async () => {
    const dest = new NemoTekTelemetryDestination();
    expect(dest.enabled).toBe(false);

    const payload = createNotificationPayload({
      eventType: "anomaly",
      healthState: HealthState.UNHEALTHY,
    });

    const res = await dest.send(payload);
    expect(res).toBe(false);
  });

  it("three-state health: UNKNOWN is never healthy", () => {
    const hUnknown = createNotificationPayload({
      eventType: "test",
      healthState: HealthState.UNKNOWN,
    });
    expect(hUnknown.health_state).toBe(HealthState.UNKNOWN);
    expect(hUnknown.health_state).not.toBe(HealthState.HEALTHY);
  });

  it("projects canonical audit event value-free", () => {
    const auditRecord = {
      type: "shield.access",
      decision: "BLOCK",
      blocked_fields: ["credit_card", "ssn"],
      reason_code: "POLICY_DENY",
      trace_id: "trace-999",
      raw_record: { credit_card: "4111...", ssn: "000-00-0000" },
    };

    const payload = fromAuditEvent(auditRecord);
    expect(payload.health_state).toBe(HealthState.UNHEALTHY);
    expect(payload.dropped_fields).toEqual(["credit_card", "ssn"]);
    expect(payload.violation_count).toBe(2);

    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain("raw_record");
    expect(serialized).not.toContain("4111");
    expect(serialized).not.toContain("000-00-0000");
  });

  it("projects unmeasurable doctor result as UNKNOWN", () => {
    const plan = { status: "unmeasurable" };
    const payload = fromDoctorResult(plan);
    expect(payload.health_state).toBe(HealthState.UNKNOWN);
  });

  it("SIEM and CLI destinations format output", () => {
    let siemOutput = "";
    let cliOutput = "";

    const siem = new SiemDestination({ write: (s) => (siemOutput += s) });
    const cli = new CliDestination({ write: (s) => (cliOutput += s) });

    const payload = createNotificationPayload({
      eventType: "shield.violation",
      healthState: HealthState.UNHEALTHY,
      droppedFields: ["secret_field"],
    });

    expect(siem.send(payload)).toBe(true);
    expect(cli.send(payload)).toBe(true);

    expect(siemOutput).toContain("shield.violation");
    expect(siemOutput).toContain("secret_field");
    expect(cliOutput).toContain("[ALERT]");
    expect(cliOutput).toContain("Dropped fields: secret_field");
  });

  it("deduplicates identical notification keys", async () => {
    let out = "";
    const sender = new NotificationSender({
      destinations: [new SiemDestination({ write: (s) => (out += s) })],
    });

    const p1 = createNotificationPayload({
      eventType: "alert",
      healthState: HealthState.UNHEALTHY,
      idempotencyKey: "key-123",
    });
    const p2 = createNotificationPayload({
      eventType: "alert",
      healthState: HealthState.UNHEALTHY,
      idempotencyKey: "key-123",
    });

    const r1 = await sender.notify(p1);
    expect(r1["SiemDestination_0"]).toBe(true);

    const r2 = await sender.notify(p2);
    expect(r2).toEqual({ deduplicated: true });

    const lines = out.trim().split("\n");
    expect(lines.length).toBe(1);
  });
});
