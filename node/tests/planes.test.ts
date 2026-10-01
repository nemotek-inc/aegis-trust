/**
 * Test suite for execution plane adapters, cross-plane rejection, and error opacity (Issue #284).
 */

import { describe, expect, it } from "vitest";
import {
  AwsNitroPlaneAdapter,
  AzureCvmPlaneAdapter,
  GcpConfidentialPlaneAdapter,
  LocalPlaneAdapter,
  PlaneAssurance,
  PlaneError,
  PlaneErrorKind,
  PlaneHealthStatus,
  PlaneKind,
  PlaneRegistry,
  computeEvidenceRef,
  parsePlaneKind,
} from "../src/planes/index.js";

describe("execution planes", () => {
  it("AO-002: PlaneError string representation is empty", () => {
    const err = new PlaneError(PlaneErrorKind.CROSS_PLANE_MISMATCH, "internal debug info");
    expect(err.message).toBe("");
    expect(err.toString()).toBe("");
    expect(err.kind).toBe(PlaneErrorKind.CROSS_PLANE_MISMATCH);
  });

  it("PlaneKind parses canonical names and aliases", () => {
    expect(parsePlaneKind("aws")).toBe(PlaneKind.AWS);
    expect(parsePlaneKind("aws_nitro")).toBe(PlaneKind.AWS);
    expect(parsePlaneKind("azure_cvm")).toBe(PlaneKind.AZURE);
    expect(parsePlaneKind("gcp_confidential")).toBe(PlaneKind.GCP);
    expect(parsePlaneKind("oracle_cloud")).toBe(PlaneKind.ORACLE);
    expect(parsePlaneKind("local_dev")).toBe(PlaneKind.LOCAL);

    expect(() => parsePlaneKind("unknown_plane")).toThrow();
  });

  it("computeEvidenceRef produces 64-char sha256 hex", () => {
    const ref = computeEvidenceRef(new TextEncoder().encode("test-blob-1234"));
    expect(ref.length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(ref)).toBe(true);
  });

  it("all adapters satisfy PlaneAdapter port", async () => {
    const adapters = [
      new LocalPlaneAdapter(),
      new AwsNitroPlaneAdapter(),
      new AzureCvmPlaneAdapter(),
      new GcpConfidentialPlaneAdapter(),
    ];
    const nonce = new TextEncoder().encode("test-nonce-12345678");

    for (const adapter of adapters) {
      expect(await adapter.healthCheck()).toBe(PlaneHealthStatus.HEALTHY);

      const evidence = await adapter.attest(nonce);
      expect(evidence.plane).toBe(adapter.planeKind());
      expect(evidence.nonce).toEqual(nonce);

      const verdict = await adapter.verify(evidence, nonce);
      expect(verdict.valid).toBe(true);
      expect(verdict.plane).toBe(adapter.planeKind());
      expect(verdict.evidenceRef).toBe(computeEvidenceRef(evidence.sealedBlob));
    }
  });

  it("cross-plane verification is rejected fail-closed", async () => {
    const adapters = {
      [PlaneKind.LOCAL]: new LocalPlaneAdapter(),
      [PlaneKind.AWS]: new AwsNitroPlaneAdapter(),
      [PlaneKind.AZURE]: new AzureCvmPlaneAdapter(),
      [PlaneKind.GCP]: new GcpConfidentialPlaneAdapter(),
    };
    const nonce = new TextEncoder().encode("cross-plane-nonce-9999");

    for (const [sourceKind, sourceAdapter] of Object.entries(adapters)) {
      const evidence = await sourceAdapter.attest(nonce);

      for (const [targetKind, targetAdapter] of Object.entries(adapters)) {
        if (sourceKind === targetKind) continue;

        let threw = false;
        try {
          await targetAdapter.verify(evidence, nonce);
        } catch (e) {
          threw = true;
          expect(e).toBeInstanceOf(PlaneError);
          expect((e as PlaneError).kind).toBe(PlaneErrorKind.CROSS_PLANE_MISMATCH);
          expect((e as PlaneError).message).toBe(""); // AO-002 check
        }
        expect(threw, `Expected cross-plane verification from ${sourceKind} to ${targetKind} to fail`).toBe(true);
      }
    }
  });

  it("nonce mismatch is rejected fail-closed", async () => {
    const adapter = new LocalPlaneAdapter();
    const evidence = await adapter.attest(new TextEncoder().encode("nonce-AAA"));

    expect(() =>
      adapter.verify(evidence, new TextEncoder().encode("nonce-BBB")),
    ).toThrowError(PlaneError);
  });

  it("PlaneRegistry registers, retrieves, and dispatches across planes", async () => {
    const reg = new PlaneRegistry();
    reg.register(new LocalPlaneAdapter());
    reg.register(new AwsNitroPlaneAdapter());
    reg.register(new AzureCvmPlaneAdapter());
    reg.register(new GcpConfidentialPlaneAdapter());

    expect(reg.size).toBe(4);
    expect(reg.contains(PlaneKind.AWS)).toBe(true);
    expect(reg.contains(PlaneKind.LOCAL)).toBe(true);
    expect(reg.contains(PlaneKind.ORACLE)).toBe(false);

    const nonce = new TextEncoder().encode("registry-nonce");
    for (const plane of [PlaneKind.LOCAL, PlaneKind.AWS, PlaneKind.AZURE, PlaneKind.GCP]) {
      const ev = await reg.attest(plane, nonce);
      const verdict = await reg.verify(ev, nonce);
      expect(verdict.valid).toBe(true);
      expect(verdict.plane).toBe(plane);
      expect(await reg.healthCheck(plane)).toBe(PlaneHealthStatus.HEALTHY);
    }

    // Unregistered plane fails closed
    await expect(reg.attest(PlaneKind.ORACLE, nonce)).rejects.toThrowError(PlaneError);
  });
});
