// shield-proxy FULL-mode gate — real subprocess + real stub gateway over HTTP.
// Mirror of python/tests/test_mcp_proxy_full.py (same spec => cross-SDK parity
// for the enforcement point). The proxy consults the gateway BEFORE forwarding
// a gated call: a policy deny means the tool NEVER runs, and a gateway outage
// is a deny, never a pass-through.

import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const PROXY = new URL("../dist/mcpProxy.js", import.meta.url).pathname;

// The fake server logs the tools it ran to argv[2]; the test reads that file
// after the proxy exits. (A custom "tools/seen" method no longer works: the
// proxy withholds replies to methods it has no projection for.)
const FAKE_SERVER = `
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";
const RECORD = { name: "ACME", company: "ACME Inc", email: "ceo@acme.test", ssn: "123-45-6789" };
const log = process.argv[2];
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (!("id" in msg)) return;
  let result;
  if (msg.method === "tools/call") {
    if (log) appendFileSync(log, msg.params.name + "\\n");
    result = { structuredContent: RECORD, content: [] };
  } else {
    result = { ok: true };
  }
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
});
`;

const POLICY = {
  policy_schema_version: 0,
  policy_id: "proxy-full-test-policy",
  purposes: {
    customer_data: { scope: ["name", "company"] },
    denied_purpose: { scope: [] },
  },
  tools: {
    query_business_data: "customer_data",
    blocked_tool: "denied_purpose",
    other_tool: "customer_data",
  },
  defaults: { unknown_tool: "block" },
};

const DECISION_OK = { outcome: "PROTECTED", ledgered: true, decision_id: "d-1" };
const DECISION_BLOCKED = { outcome: "BLOCKED", ledgered: true, decision_id: "d-2" };

let gateways: Server[] = [];
afterEach(() => {
  for (const g of gateways) g.close();
  gateways = [];
});

function stubGateway(): Promise<{ port: number; calls: Array<{ path: string; body: Record<string, unknown> }> }> {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  const srv = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      calls.push({ path: req.url ?? "", body });
      let payload: Record<string, unknown> = {};
      if ((req.url ?? "").endsWith("/check-access")) {
        payload = { allowed: body.purpose !== "denied_purpose" };
      } else if ((req.url ?? "").endsWith("/tool-call")) {
        payload = {
          decision: body.tool === "query_business_data" ? DECISION_OK : DECISION_BLOCKED,
          enforcement: null,
        };
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    });
  });
  gateways.push(srv);
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      resolve({ port: typeof addr === "object" && addr ? addr.port : 0, calls });
    });
  });
}

function runProxy(
  requests: Array<Record<string, unknown>>,
  env: Record<string, string>,
  gate: string,
): Promise<{ byId: Map<number, Record<string, unknown>>; events: Array<Record<string, unknown>>; seen: string[] }> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-proxy-full-"));
  const serverPath = join(dir, "server.mjs");
  const seenPath = join(dir, "seen.log");
  const policyPath = join(dir, "policy.json");
  const auditPath = join(dir, "events.jsonl");
  writeFileSync(serverPath, FAKE_SERVER);
  writeFileSync(policyPath, JSON.stringify(POLICY));
  // S109: a tools/call needs an argument rule (no rule = refused).
  const rulesPath = join(dir, "rules.json");
  writeFileSync(
    rulesPath,
    JSON.stringify(
      Object.fromEntries(
        Object.keys(POLICY.tools)
          .filter((t) => !t.includes("/"))
          .map((t) => [t, { access: "read", arguments: { allow: ["purpose", "q"] } }]),
      ),
    ),
  );

  const proc = spawn(
    process.execPath,
    [PROXY, "--policy", policyPath, "--tool-rules", rulesPath, "--agent-id", "full-gate-test", "--audit-path", auditPath,
      "--gate", gate, "--", process.execPath, serverPath, seenPath],
    { stdio: ["pipe", "pipe", "inherit"], env: { PATH: process.env.PATH ?? "", ...env } },
  );

  let out = "";
  proc.stdout.on("data", (d) => (out += d.toString()));
  proc.stdin.write(requests.map((r) => JSON.stringify(r)).join("\n") + "\n");
  proc.stdin.end();

  return new Promise((resolve) => {
    proc.on("exit", () => {
      const byId = new Map<number, Record<string, unknown>>();
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        const m = JSON.parse(line) as Record<string, unknown>;
        byId.set(m.id as number, m);
      }
      let events: Array<Record<string, unknown>> = [];
      try {
        events = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean)
          .map((l) => JSON.parse(l) as Record<string, unknown>);
      } catch {
        events = [];
      }
      const seen = existsSync(seenPath)
        ? readFileSync(seenPath, "utf8").split("\n").filter(Boolean)
        : [];
      resolve({ byId, events, seen });
    });
  });
}

const call = (id: number, name: string) => ({
  jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} },
});

function resultOf(byId: Map<number, Record<string, unknown>>, id: number): Record<string, unknown> {
  return (byId.get(id) as { result: Record<string, unknown> }).result;
}

describe("FULL gate: check-access", () => {
  it("allows via the gateway, still minimizes locally, denies never run", async () => {
    const gw = await stubGateway();
    const env = {
      AEGIS_MODE: "full",
      AEGIS_URL: `http://127.0.0.1:${gw.port}`,
      AEGIS_TOKEN: "t",
    };
    const { byId, events, seen } = await runProxy(
      [call(1, "query_business_data"), call(2, "blocked_tool")],
      env, "check-access",
    );
    expect(resultOf(byId, 1).structuredContent).toEqual({ name: "ACME", company: "ACME Inc" });
    const denied = resultOf(byId, 2);
    expect(denied.isError).toBe(true);
    expect(JSON.stringify(denied)).toContain("gateway_denied");
    expect(seen).not.toContain("blocked_tool");
    expect(events.some((e) => e.reason_code === "gateway_denied")).toBe(true);
    // finding B: one scope per /check-access call
    const ca = gw.calls.filter((c) => c.path.endsWith("/check-access"));
    expect(ca.length).toBeGreaterThanOrEqual(POLICY.purposes.customer_data.scope.length);
  });

  it("gateway outage is a deny (gateway_unavailable), never a pass-through", async () => {
    const env = { AEGIS_MODE: "full", AEGIS_URL: "http://127.0.0.1:1", AEGIS_TOKEN: "t" };
    const { byId, events, seen } = await runProxy(
      [call(1, "query_business_data")], env, "check-access",
    );
    const denied = resultOf(byId, 1);
    expect(denied.isError).toBe(true);
    expect(JSON.stringify(denied)).toContain("gateway_unavailable");
    expect(seen).not.toContain("query_business_data");
    expect(events.some((e) => e.reason_code === "gateway_unavailable")).toBe(true);
  });
});

describe("FULL gate: tool-call (AI-native)", () => {
  it("uses /tool-call and blocks non-passing decisions pre-call", async () => {
    const gw = await stubGateway();
    const env = {
      AEGIS_MODE: "full",
      AEGIS_URL: `http://127.0.0.1:${gw.port}`,
      AEGIS_TOKEN: "t",
    };
    const { byId, seen } = await runProxy(
      [call(1, "query_business_data"), call(2, "other_tool")],
      env, "tool-call",
    );
    expect(resultOf(byId, 1).structuredContent).toEqual({ name: "ACME", company: "ACME Inc" });
    const denied = resultOf(byId, 2);
    expect(denied.isError).toBe(true);
    expect(JSON.stringify(denied)).toContain("gateway_denied");
    expect(seen).not.toContain("other_tool");
    const tc = gw.calls.filter((c) => c.path.endsWith("/tool-call"));
    expect(tc[0]?.body.tool).toBe("query_business_data");
    expect(tc[0]?.body.purpose).toBe("customer_data");
    expect(tc[0]?.body.owner).toBe("full-gate-test");
    expect(tc[0]?.body.fields).toEqual(["name", "company"]);
  });
});

describe("LITE unchanged", () => {
  it("no AEGIS_MODE -> no gateway traffic, local filtering only", async () => {
    const gw = await stubGateway();
    const { byId } = await runProxy([call(1, "query_business_data")], {}, "check-access");
    expect(resultOf(byId, 1).structuredContent).toEqual({ name: "ACME", company: "ACME Inc" });
    expect(gw.calls.length).toBe(0);
  });
});
