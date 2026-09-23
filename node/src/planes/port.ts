/**
 * PlaneAdapter port interface and base class (Issue #284).
 */

import {
  PlaneError,
  PlaneErrorKind,
  type PlaneEvidence,
  type PlaneHealthStatus,
  type PlaneKind,
  type PlaneVerdict,
} from "./types.js";

export interface PlaneAdapter {
  attest(nonce: Uint8Array): Promise<PlaneEvidence> | PlaneEvidence;
  verify(evidence: PlaneEvidence, expectedNonce: Uint8Array): Promise<PlaneVerdict> | PlaneVerdict;
  healthCheck(): Promise<PlaneHealthStatus> | PlaneHealthStatus;
  planeKind(): PlaneKind;
}

export abstract class BasePlaneAdapter implements PlaneAdapter {
  abstract attest(nonce: Uint8Array): Promise<PlaneEvidence> | PlaneEvidence;
  abstract healthCheck(): Promise<PlaneHealthStatus> | PlaneHealthStatus;
  abstract planeKind(): PlaneKind;

  verify(evidence: PlaneEvidence, expectedNonce: Uint8Array): Promise<PlaneVerdict> | PlaneVerdict {
    if (evidence.plane !== this.planeKind()) {
      throw new PlaneError(PlaneErrorKind.CROSS_PLANE_MISMATCH);
    }

    if (
      evidence.nonce.length !== expectedNonce.length ||
      !evidence.nonce.every((val, idx) => val === expectedNonce[idx])
    ) {
      throw new PlaneError(PlaneErrorKind.NONCE_MISMATCH);
    }

    return this.doVerify(evidence, expectedNonce);
  }

  protected abstract doVerify(
    evidence: PlaneEvidence,
    expectedNonce: Uint8Array,
  ): Promise<PlaneVerdict> | PlaneVerdict;
}
