// Declared action (read / write) on the flat check-boundary wire and the
// AI-native tool-call wire, and the response kept as received (receipt and
// keys the view interface does not declare). House pattern (client.test.ts):
// override globalThis.fetch, restore afterEach.

import { afterEach, describe, expect, it } from "vitest";

import { AegisClient } from "../src/client.js";

const origFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = origFetch;
});

function mockFetch(impl: (url: string, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) =>
    impl(String(input), init)) as unknown as typeof fetch;
}

function client(): AegisClient {
  return new AegisClient({ baseUrl: "https://localhost:8443/api/v1", token: "t" });
}

const VIEW = {
  source: "CORE",
  outcome: "PROTECTED",
  purpose_label: "p",
  allowed_fields: ["name"],
  withheld_fields: [],
  reason_code: "minimum_disclosure",
  reason_label: "Minimum disclosure",
  evidence_available: true,
  evidence: null,
};

const DECISION_OK = { outcome: "PROTECTED", ledgered: true, decision_id: "d-1" };

function capture(respond: unknown): { body: () => Record<string, unknown> } {
  let body: Record<string, unknown> = {};
  mockFetch(async (_url, init) => {
    body = JSON.parse(String(init?.body));
    return new Response(JSON.stringify(respond), { status: 200 });
  });
  return { body: () => body };
}

describe("checkBoundary action", () => {
  it("omits action when unset (byte-identical body)", async () => {
    const cap = capture(VIEW);
    await client().checkBoundary({ purpose: "p", scope: [], destination: "https://x.example/a" });
    expect("action" in cap.body()).toBe(false);
  });

  it.each(["read", "write", " read ", "Read", ""])("sends %j verbatim", async (action) => {
    const cap = capture(VIEW);
    await client().checkBoundary({
      purpose: "p",
      scope: [],
      destination: "https://facts.example/c/1",
      action,
    });
    expect(cap.body().action).toBe(action);
  });
});

describe("checkBoundary keeps the body as received", () => {
  it("keeps undeclared keys and the receipt", async () => {
    const receipt = { schema: "aegis-span-crypto.v0", envelope_id: "e".repeat(64) };
    const body = {
      ...VIEW,
      policy_generation: 7,
      policy_digest: "sha256:abc",
      response_policy: { tone: "formal" },
      boundary_receipt: receipt,
    };
    capture(body);
    const view = await client().checkBoundary({ purpose: "p", scope: ["name"] });
    expect(view).toEqual(body);
    expect(view.boundary_receipt).toEqual(receipt);
  });

  it("carries a null receipt and its reason", async () => {
    capture({ ...VIEW, boundary_receipt: null, boundary_receipt_error: "commitment_unavailable" });
    const view = await client().checkBoundary({ purpose: "p", scope: ["name"] });
    expect(view.boundary_receipt).toBeNull();
    expect(view.boundary_receipt_error).toBe("commitment_unavailable");
  });
});

describe("toolCall / toolAllowed action", () => {
  it("sends action verbatim only when given", async () => {
    const cap = capture({ decision: DECISION_OK, enforcement: null });
    await client().toolCall({ tool: "t", purpose: "p", owner: "o" });
    expect("action" in cap.body()).toBe(false);
    await client().toolCall({ tool: "t", purpose: "p", owner: "o", action: "read" });
    expect(cap.body().action).toBe("read");
    await client().toolCall({ tool: "t", purpose: "p", owner: "o", action: " Read " });
    expect(cap.body().action).toBe(" Read ");
  });

  it("toolAllowed passes action through", async () => {
    const cap = capture({ decision: DECISION_OK, enforcement: null });
    expect(
      await client().toolAllowed({ tool: "t", purpose: "p", owner: "o", action: "read" }),
    ).toBe(true);
    expect(cap.body().action).toBe("read");
  });

  it("returns the body with its receipt", async () => {
    const receipt = { schema: "aegis-span-crypto.v0", envelope_id: "e".repeat(64) };
    capture({ decision: DECISION_OK, enforcement: null, boundary_receipt: receipt });
    const out = await client().toolCall({ tool: "t", purpose: "p", owner: "o" });
    expect(out.boundary_receipt).toEqual(receipt);
  });
});
