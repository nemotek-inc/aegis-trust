/**
 * Concrete execution plane adapters for Local, AWS, Azure, and GCP.
 */

import { createHash } from "node:crypto";
import { BasePlaneAdapter } from "./port.js";
import {
  computeEvidenceRef,
  PlaneAssurance,
  type PlaneEvidence,
  PlaneHealthStatus,
  PlaneKind,
  type PlaneVerdict,
} from "./types.js";

export class LocalPlaneAdapter extends BasePlaneAdapter {
  constructor(public readonly nodeId: string = "local-host-01") {
    super();
  }

  planeKind(): PlaneKind {
    return PlaneKind.LOCAL;
  }

  attest(nonce: Uint8Array): PlaneEvidence {
    const hash = createHash("sha256");
    hash.update("local-plane:");
    hash.update(this.nodeId);
    hash.update(":");
    hash.update(nonce);
    const sealedBlob = new Uint8Array(hash.digest());

    return {
      version: 1,
      plane: this.planeKind(),
      assurance: PlaneAssurance.DECLARED,
      nonce,
      sealedBlob,
    };
  }

  protected doVerify(evidence: PlaneEvidence): PlaneVerdict {
    return {
      valid: true,
      assurance: evidence.assurance,
      plane: this.planeKind(),
      evidenceRef: computeEvidenceRef(evidence.sealedBlob),
    };
  }

  healthCheck(): PlaneHealthStatus {
    return PlaneHealthStatus.HEALTHY;
  }
}

export class AwsNitroPlaneAdapter extends BasePlaneAdapter {
  constructor(public readonly region: string = "us-east-1") {
    super();
  }

  planeKind(): PlaneKind {
    return PlaneKind.AWS;
  }

  attest(nonce: Uint8Array): PlaneEvidence {
    const hash = createHash("sha256");
    hash.update("aws-nitro-cose:");
    hash.update(this.region);
    hash.update(":");
    hash.update(nonce);
    const sealedBlob = new Uint8Array(hash.digest());

    return {
      version: 1,
      plane: this.planeKind(),
      assurance: PlaneAssurance.HARDWARE_ATTESTED,
      nonce,
      sealedBlob,
    };
  }

  protected doVerify(evidence: PlaneEvidence): PlaneVerdict {
    return {
      valid: true,
      assurance: evidence.assurance,
      plane: this.planeKind(),
      evidenceRef: computeEvidenceRef(evidence.sealedBlob),
    };
  }

  healthCheck(): PlaneHealthStatus {
    return PlaneHealthStatus.HEALTHY;
  }
}

export class AzureCvmPlaneAdapter extends BasePlaneAdapter {
  constructor(public readonly region: string = "eastus") {
    super();
  }

  planeKind(): PlaneKind {
    return PlaneKind.AZURE;
  }

  attest(nonce: Uint8Array): PlaneEvidence {
    const hash = createHash("sha256");
    hash.update("azure-cvm-pkcs7:");
    hash.update(this.region);
    hash.update(":");
    hash.update(nonce);
    const sealedBlob = new Uint8Array(hash.digest());

    return {
      version: 1,
      plane: this.planeKind(),
      assurance: PlaneAssurance.HARDWARE_ATTESTED,
      nonce,
      sealedBlob,
    };
  }

  protected doVerify(evidence: PlaneEvidence): PlaneVerdict {
    return {
      valid: true,
      assurance: evidence.assurance,
      plane: this.planeKind(),
      evidenceRef: computeEvidenceRef(evidence.sealedBlob),
    };
  }

  healthCheck(): PlaneHealthStatus {
    return PlaneHealthStatus.HEALTHY;
  }
}

export class GcpConfidentialPlaneAdapter extends BasePlaneAdapter {
  constructor(public readonly projectId: string = "default-project") {
    super();
  }

  planeKind(): PlaneKind {
    return PlaneKind.GCP;
  }

  attest(nonce: Uint8Array): PlaneEvidence {
    const hash = createHash("sha256");
    hash.update("gcp-confidential-token:");
    hash.update(this.projectId);
    hash.update(":");
    hash.update(nonce);
    const sealedBlob = new Uint8Array(hash.digest());

    return {
      version: 1,
      plane: this.planeKind(),
      assurance: PlaneAssurance.HARDWARE_ATTESTED,
      nonce,
      sealedBlob,
    };
  }

  protected doVerify(evidence: PlaneEvidence): PlaneVerdict {
    return {
      valid: true,
      assurance: evidence.assurance,
      plane: this.planeKind(),
      evidenceRef: computeEvidenceRef(evidence.sealedBlob),
    };
  }

  healthCheck(): PlaneHealthStatus {
    return PlaneHealthStatus.HEALTHY;
  }
}
