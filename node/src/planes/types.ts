/**
 * Execution plane types and error definitions (Issue #284).
 */

import { createHash } from "node:crypto";

export enum PlaneKind {
  AWS = "aws",
  AZURE = "azure",
  GCP = "gcp",
  ORACLE = "oracle",
  LOCAL = "local",
}

export function parsePlaneKind(val: string): PlaneKind {
  const normalized = val.trim().toLowerCase();
  const aliases: Record<string, PlaneKind> = {
    aws_nitro: PlaneKind.AWS,
    azure_cvm: PlaneKind.AZURE,
    gcp_confidential: PlaneKind.GCP,
    oracle_cloud: PlaneKind.ORACLE,
    local_dev: PlaneKind.LOCAL,
  };
  if (normalized in aliases) {
    return aliases[normalized];
  }
  for (const member of Object.values(PlaneKind)) {
    if (member === normalized) {
      return member;
    }
  }
  throw new Error(`Unknown plane kind: ${val}`);
}

export enum PlaneAssurance {
  DECLARED = "declared",
  PLATFORM_ATTESTED = "platform_attested",
  HARDWARE_ATTESTED = "hardware_attested",
}

export enum PlaneHealthStatus {
  HEALTHY = "healthy",
  REGISTRATION_REQUIRED = "registration_required",
  THROTTLED = "throttled",
  UNAVAILABLE = "unavailable",
}

export enum PlaneErrorKind {
  PLANE_UNAVAILABLE = "plane_unavailable",
  POLICY_DENIED = "policy_denied",
  CROSS_PLANE_MISMATCH = "cross_plane_mismatch",
  NONCE_MISMATCH = "nonce_mismatch",
  SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed",
  MALFORMED_EVIDENCE = "malformed_evidence",
  EVIDENCE_EXPIRED = "evidence_expired",
  PLATFORM_CALL_FAILED = "platform_call_failed",
  UNKNOWN = "unknown",
}

export class PlaneError extends Error {
  readonly kind: PlaneErrorKind;
  readonly details?: unknown;

  constructor(kind: PlaneErrorKind = PlaneErrorKind.UNKNOWN, details?: unknown) {
    // AO-002: message is empty string to prevent external error oracles.
    super("");
    this.name = "PlaneError";
    this.kind = kind;
    this.details = details;
    Object.setPrototypeOf(this, PlaneError.prototype);
  }

  toString(): string {
    return "";
  }
}

export interface PlaneEvidence {
  version: number;
  plane: PlaneKind;
  assurance: PlaneAssurance;
  nonce: Uint8Array;
  sealedBlob: Uint8Array;
  metadata?: Uint8Array;
}

export function computeEvidenceRef(sealedBlob: Uint8Array): string {
  return createHash("sha256").update(sealedBlob).digest("hex");
}

export interface PlaneVerdict {
  valid: boolean;
  assurance: PlaneAssurance;
  plane: PlaneKind;
  evidenceRef: string;
}
