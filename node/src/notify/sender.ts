/**
 * Notification sender with idempotency tracking (Node).
 */

import {
  NemoTekTelemetryDestination,
  NotificationDestination,
} from "./destinations.js";
import { NotificationPayload } from "./types.js";

export class IdempotencyCache {
  private readonly keys = new Set<string>();
  private readonly queue: string[] = [];

  constructor(public readonly capacity: number = 1000) {}

  recordIfNew(key: string): boolean {
    if (this.keys.has(key)) {
      return false;
    }
    if (this.queue.length >= this.capacity) {
      const oldest = this.queue.shift();
      if (oldest) this.keys.delete(oldest);
    }
    this.keys.add(key);
    this.queue.push(key);
    return true;
  }

  clear(): void {
    this.keys.clear();
    this.queue.length = 0;
  }
}

export interface NotificationSenderOptions {
  destinations?: NotificationDestination[];
  enableNemoTek?: boolean;
  nemoTekEndpoint?: string;
  idempotencyCapacity?: number;
}

export class NotificationSender {
  public readonly destinations: NotificationDestination[];
  public readonly nemoTekDestination: NemoTekTelemetryDestination;
  private readonly idempotency: IdempotencyCache;

  constructor(options: NotificationSenderOptions = {}) {
    this.destinations = [...(options.destinations ?? [])];
    this.nemoTekDestination = new NemoTekTelemetryDestination({
      enabled: options.enableNemoTek,
      endpointUrl: options.nemoTekEndpoint,
    });
    this.idempotency = new IdempotencyCache(options.idempotencyCapacity ?? 1000);
  }

  addDestination(dest: NotificationDestination): void {
    this.destinations.push(dest);
  }

  async notify(payload: NotificationPayload): Promise<Record<string, boolean>> {
    if (payload.idempotency_key) {
      const isNew = this.idempotency.recordIfNew(payload.idempotency_key);
      if (!isNew) {
        return { deduplicated: true };
      }
    }

    const results: Record<string, boolean> = {};

    for (let i = 0; i < this.destinations.length; i++) {
      const dest = this.destinations[i];
      const key = `${dest.constructor.name}_${i}`;
      try {
        results[key] = await Promise.resolve(dest.send(payload));
      } catch {
        results[key] = false;
      }
    }

    if (this.nemoTekDestination.enabled) {
      try {
        results["NemoTekTelemetry"] = await this.nemoTekDestination.send(payload);
      } catch {
        results["NemoTekTelemetry"] = false;
      }
    }

    return results;
  }
}
