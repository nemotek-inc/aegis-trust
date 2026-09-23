/**
 * Notification destinations for Node (SIEM / Webhook / CLI triad).
 */

import { NotificationPayload } from "./types.js";

export interface NotificationDestination {
  send(payload: NotificationPayload): Promise<boolean> | boolean;
}

export class SiemDestination implements NotificationDestination {
  constructor(private readonly sink: { write(chunk: string): void } = process.stderr) {}

  send(payload: NotificationPayload): boolean {
    try {
      const line = JSON.stringify(payload) + "\n";
      this.sink.write(line);
      return true;
    } catch {
      return false;
    }
  }
}

export class CliDestination implements NotificationDestination {
  constructor(private readonly stream: { write(chunk: string): void } = process.stderr) {}

  send(payload: NotificationPayload): boolean {
    try {
      const symbol =
        payload.health_state === "healthy"
          ? "[OK]"
          : payload.health_state === "unhealthy"
            ? "[ALERT]"
            : "[UNKNOWN]";

      let msg = `${symbol} Aegis Notification: ${payload.event_type} (state=${payload.health_state}, violations=${payload.violation_count})\n`;
      if (payload.dropped_fields.length > 0) {
        msg += `  Dropped fields: ${payload.dropped_fields.join(", ")}\n`;
      }
      if (payload.reason_codes.length > 0) {
        msg += `  Reason codes: ${payload.reason_codes.join(", ")}\n`;
      }
      this.stream.write(msg);
      return true;
    } catch {
      return false;
    }
  }
}

export class WebhookDestination implements NotificationDestination {
  constructor(
    public readonly endpointUrl: string,
    public readonly options: { timeoutMs?: number; headers?: Record<string, string> } = {},
  ) {}

  async send(payload: NotificationPayload): Promise<boolean> {
    try {
      const resp = await fetch(this.endpointUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.options.headers ?? {}),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 5000),
      });
      return resp.ok;
    } catch {
      return false;
    }
  }
}

export class NemoTekTelemetryDestination implements NotificationDestination {
  public static readonly DEFAULT_TELEMETRY_ENDPOINT =
    "https://telemetry.aegisagentcontrol.com/v0/reports";

  public readonly enabled: boolean;
  public readonly endpointUrl: string;

  constructor(options: { enabled?: boolean; endpointUrl?: string } = {}) {
    const envEnabled =
      process.env.AEGIS_TELEMETRY_NEMOTEK === "1" ||
      process.env.AEGIS_TELEMETRY_NEMOTEK?.toLowerCase() === "true";
    this.enabled = options.enabled ?? envEnabled ?? false;
    this.endpointUrl =
      options.endpointUrl ?? NemoTekTelemetryDestination.DEFAULT_TELEMETRY_ENDPOINT;
  }

  async send(payload: NotificationPayload): Promise<boolean> {
    if (!this.enabled) {
      // Invariant 3: Zero egress when disabled
      return false;
    }
    try {
      const resp = await fetch(this.endpointUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(3000),
      });
      return resp.ok;
    } catch {
      return false;
    }
  }
}
