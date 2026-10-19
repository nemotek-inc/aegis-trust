// shield-proxy end-to-end tests (Node) — mirror of python/tests/test_mcp_proxy.py.
// Real subprocess, real stdio framing: a fake MCP server returns an over-broad
// record; the proxy must deliver only the policy scope to the host (for both
// tools/call AND resources/read), withhold what it cannot inspect, block unknown
// tools without forwarding, refuse server-to-host requests, and emit
// schema-valid canonical v0 audit events. Line-level classification is covered
// case by case by the shared corpus (mcpRelayCorpus.test.ts); this file proves
// the stdio pumps carry it.
//
// Requests are written in one batch and all responses collected after the proxy
// exits (matched by JSON-RPC id), robust across test-runner stdio scheduling.

import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const PROXY = fileURLToPath(new URL("../dist/mcpProxy.js", import.meta.url));
const EVENT_SCHEMA = JSON.parse(
  readFileSync(new URL("../../schemas/v0/aegis-audit-event.v0.schema.json", import.meta.url), "utf8"),
);

const FAKE_SERVER = `
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";
const RECORD = { name: "ACME", company: "ACME Inc", email: "ceo@acme.test", ssn: "123-45-6789" };
const log = process.argv[2];
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  if (log) appendFileSync(log, line + "\\n");
  const msg = JSON.parse(line);
  if (!("id" in msg) || !("method" in msg)) return;
  let result;
  if (msg.method === "initialize") {
    result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "0" } };
  } else if (msg.method === "tools/call" && msg.params.name === "query_with_sampling") {
    send({ jsonrpc: "2.0", id: "srv-1", method: "sampling/createMessage",
      params: { messages: [{ role: "user", content: { type: "text", text: "ssn=123-45-6789" } }] } });
    result = { structuredContent: RECORD };
  } else if (msg.method === "tools/call") {
    result = { structuredContent: RECORD,
      content: [{ type: "text", text: JSON.stringify(RECORD) }, { type: "text", text: "plain note ssn=123-45-6789" }] };
  } else if (msg.method === "resources/read") {
    result = { contents: [{ uri: msg.params.uri, text: JSON.stringify(RECORD) }] };
  } else {
    result = { ok: true };
  }
  send({ jsonrpc: "2.0", id: msg.id, result });
});
`;

const POLICY = {
  policy_schema_version: 0,
  policy_id: "proxy-test-policy",
  purposes: { customer_data: { scope: ["name", "company"] }, everything: { deny_fields: ["ssn"] } },
  tools: {
    query_business_data: "customer_data",
    query_with_sampling: "customer_data",
    "resources/read": "customer_data",
  },
  defaults: { unknown_tool: "block" },
};

const REQUESTS = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
  { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "query_business_data", arguments: {} } },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "exfiltrate_everything", arguments: {} } },
  { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "query_business_data", arguments: { purpose: "everything" } } },
  { jsonrpc: "2.0", id: 5, method: "resources/read", params: { uri: "file://customer/acme" } },
  { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "query_with_sampling", arguments: {} } },
  { jsonrpc: "2.0", id: 7, method: "custom/export", params: {} },
];

interface Run {
  byId: Map<number, Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  seen: Array<Record<string, unknown>>;
}

function runProxy(extra: string[] = []): Promise<Run> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-proxy-"));
  const serverPath = join(dir, "server.mjs");
  const policyPath = join(dir, "policy.json");
  const auditPath = join(dir, "events.jsonl");
  const seenPath = join(dir, "server_saw.jsonl");
  writeFileSync(serverPath, FAKE_SERVER);
  writeFileSync(policyPath, JSON.stringify(POLICY));

  const proc = spawn(
    process.execPath,
    [PROXY, "--policy", policyPath, "--agent-id", "cursor-test", "--audit-path", auditPath, ...extra,
      "--", process.execPath, serverPath, seenPath],
    { stdio: ["pipe", "pipe", "inherit"] },
  );

  // stdin stays open until every request has its reply: the server's sampling
  // request arrives mid-stream, and the proxy's refusal must still reach it.
  let out = "";
  const want = new Set(REQUESTS.map((r) => r.id));
  proc.stdout.on("data", (d) => {
    out += d.toString();
    for (const line of out.split("\n")) {
      if (!line.trim()) continue;
      try {
        want.delete((JSON.parse(line) as { id: number }).id);
      } catch {
        // a partial line; the rest arrives with the next chunk
      }
    }
    if (want.size === 0 && !proc.stdin.writableEnded) proc.stdin.end();
  });
  proc.stdin.write(REQUESTS.map((r) => JSON.stringify(r)).join("\n") + "\n");

  return new Promise((resolve) => {
    proc.on("exit", () => {
      const byId = new Map<number, Record<string, unknown>>();
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        const m = JSON.parse(line) as Record<string, unknown>;
        byId.set(m.id as number, m);
      }
      const events = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
      const seen = existsSync(seenPath)
        ? readFileSync(seenPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
        : [];
      resolve({ byId, events, seen });
    });
  });
}

const SECRETS = ["ceo@acme.test", "123-45-6789"];

describe("shield-proxy (Node) — MCP enforcement point", () => {
  it("minimizes, withholds, blocks and refuses over real stdio", { timeout: 20000 }, async () => {
    const { byId, events, seen } = await runProxy();

    expect((byId.get(1)!.result as Record<string, unknown>).protocolVersion).toBe("2025-06-18");

    // mapped tool: structuredContent and JSON text minimized; free text withheld
    const result = byId.get(2)!.result as Record<string, unknown>;
    expect(result.structuredContent).toEqual({ name: "ACME", company: "ACME Inc" });
    const content = result.content as Array<{ text: string }>;
    expect(JSON.parse(content[0].text)).toEqual({ name: "ACME", company: "ACME Inc" });
    expect(content[1].text.startsWith("[Aegis: withheld")).toBe(true);

    // unknown tool and a broader declared purpose: blocked, never forwarded
    const br = byId.get(3)!.result as { isError: boolean; content: Array<{ text: string }> };
    expect(br.isError).toBe(true);
    expect(br.content[0].text).toContain("unknown_tool");
    expect(JSON.stringify(byId.get(4))).toContain("declared_purpose_refused");
    const forwardedCalls = seen.filter((m) => m.method === "tools/call").map((m) => (m.params as { name: string }).name);
    expect(forwardedCalls).toEqual(["query_business_data", "query_with_sampling"]);

    // resources/read is a sibling data path on the same boundary — also minimized
    const res = byId.get(5)!.result as { contents: Array<{ text: string }> };
    expect(JSON.parse(res.contents[0].text)).toEqual({ name: "ACME", company: "ACME Inc" });

    // the server's sampling request never reached the host; the server was told -32601
    expect(byId.get(6)!.result).toEqual({ structuredContent: { name: "ACME", company: "ACME Inc" } });
    const refusal = seen.find((m) => m.id === "srv-1") as { error: { code: number } } | undefined;
    expect(refusal?.error.code).toBe(-32601);

    // the reply to a method with no projection is withheld
    expect((byId.get(7)!.error as { code: number }).code).toBe(-32603);

    for (const reply of byId.values()) {
      for (const s of SECRETS) expect(JSON.stringify(reply)).not.toContain(s);
    }

    const allow = events.filter((e) => e.decision === "allow");
    expect(allow[0].outcome).toBe("access_reduced");
    expect([...(allow[0].blocked_fields as string[])].sort()).toEqual(["<withheld:content[1].text>", "email", "ssn"]);
    const reasons = events.map((e) => e.reason_code);
    expect(reasons).toContain("server_request_refused");
    expect(reasons).toContain("declared_purpose_refused");
    expect(events.every((e) => e.enforcement_point === "mcp_proxy")).toBe(true);

    const validate = new Ajv2020({ strict: false }).compile(EVENT_SCHEMA);
    for (const e of events) {
      expect(validate(e), JSON.stringify(validate.errors)).toBe(true);
      for (const s of SECRETS) expect(JSON.stringify(e)).not.toContain(s);
    }
  });

  it("--uninspected pass relays free text and names it, never protected", { timeout: 20000 }, async () => {
    const { byId, events } = await runProxy(["--uninspected", "pass"]);
    const content = (byId.get(2)!.result as { content: Array<{ text: string }> }).content;
    expect(content[1].text).toBe("plain note ssn=123-45-6789");
    const allow = events.filter((e) => e.decision === "allow" && e.operation === "query_business_data")[0];
    expect(allow.outcome).toBe("access_reduced");
    expect(allow.reason_code).toBe("unfiltered_passthrough");
    expect(allow.allowed_fields).toEqual(["<unfiltered:content[1].text>"]);
  });
});
