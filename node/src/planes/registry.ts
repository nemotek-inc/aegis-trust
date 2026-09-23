/**
 * Centralized registry and dispatcher for execution plane adapters.
 */

import type { PlaneAdapter } from "./port.js";
import {
  PlaneError,
  PlaneErrorKind,
  type PlaneEvidence,
  type PlaneHealthStatus,
  type PlaneKind,
  type PlaneVerdict,
} from "./types.js";

export class PlaneRegistry {
  private readonly adapters = new Map<PlaneKind, PlaneAdapter>();

  register(adapter: PlaneAdapter): void {
    this.adapters.set(adapter.planeKind(), adapter);
  }

  get(plane: PlaneKind): PlaneAdapter | undefined {
    return this.adapters.get(plane);
  }

  contains(plane: PlaneKind): boolean {
    return this.adapters.has(plane);
  }

  get size(): number {
    return this.adapters.size;
  }

  async attest(plane: PlaneKind, nonce: Uint8Array): Promise<PlaneEvidence> {
    const adapter = this.adapters.get(plane);
    if (!adapter) {
      throw new PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE);
    }
    return adapter.attest(nonce);
  }

  async verify(evidence: PlaneEvidence, expectedNonce: Uint8Array): Promise<PlaneVerdict> {
    const adapter = this.adapters.get(evidence.plane);
    if (!adapter) {
      throw new PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE);
    }
    return adapter.verify(evidence, expectedNonce);
  }

  async healthCheck(plane: PlaneKind): Promise<PlaneHealthStatus> {
    const adapter = this.adapters.get(plane);
    if (!adapter) {
      throw new PlaneError(PlaneErrorKind.PLANE_UNAVAILABLE);
    }
    return adapter.healthCheck();
  }
}
