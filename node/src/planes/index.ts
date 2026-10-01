/**
 * Execution plane adapters and attestation port abstraction (Issue #284).
 */

export {
  PlaneKind,
  PlaneAssurance,
  PlaneHealthStatus,
  PlaneErrorKind,
  PlaneError,
  parsePlaneKind,
  computeEvidenceRef,
  type PlaneEvidence,
  type PlaneVerdict,
} from "./types.js";

export { type PlaneAdapter, BasePlaneAdapter } from "./port.js";
export { PlaneRegistry } from "./registry.js";
export {
  LocalPlaneAdapter,
  AwsNitroPlaneAdapter,
  AzureCvmPlaneAdapter,
  GcpConfidentialPlaneAdapter,
} from "./adapters.js";
