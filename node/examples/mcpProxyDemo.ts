// The agent on the tool path: aegis-mcp-proxy minimizes tool output before the
// model sees it. Node mirror of python/examples/mcp_proxy_demo.py.
//
// Point any MCP host (Claude Code, Cursor, codex, agy) at `aegis-mcp-proxy`
// instead of the raw server and every tools/call result is filtered to policy
// before it can enter the agent's model context. This script plays the host and
// runs the same call twice — straight against the server, then through the proxy.
//
//   npm install aegis-trust && npm run build
//   npx tsx examples/mcpProxyDemo.ts

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const PROXY = fileURLToPath(new URL("../dist/mcpProxy.js", import.meta.url));

// A stand-in MCP server whose tool returns an over-broad customer record.
const FAKE_SERVER = `
import { createInterface } from "node:readline";
const RECORD = { name: "ACME", company: "ACME Inc", email: "ceo@acme.test",
  ssn: "123-45-6789", card_number: "4242-4242-4242-4242" };
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (!("id" in msg)) return;
  const result = msg.method === "tools/call"
    ? { structuredContent: RECORD }
    : { ok: true };
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
});
`;

const POLICY = {
  policy_schema_version: 0,
  policy_id: "demo",
  purposes: { customer_data: { scope: ["name", "company"] } },
  tools: { query_business_data: "customer_data" },
  defaults: { unknown_tool: "block" },
};

// The argument rule: this read tool takes no arguments the operator did not list.
const RULES = { query_business_data: { access: "read", arguments: { allow: ["customer_id"] } } };

const CALL = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "query_business_data", arguments: {} } };
const BAD = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "exfiltrate_everything", arguments: {} } };

function collect(args: string[], input: string): Promise<{ out: string; auditPath?: string }> {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, args, { stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stdin.write(input);
    proc.stdin.end();
    proc.on("exit", () => resolve({ out }));
  });
}

function byId(out: string): Map<number, Record<string, unknown>> {
  const m = new Map<number, Record<string, unknown>>();
  for (const line of out.split("\n")) {
    if (!line.trim()) continue;
    const o = JSON.parse(line);
    m.set(o.id, o);
  }
  return m;
}

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-demo-"));
  const server = join(dir, "server.mjs");
  const policy = join(dir, "policy.json");
  const audit = join(dir, "events.jsonl");
  writeFileSync(server, FAKE_SERVER);
  writeFileSync(policy, JSON.stringify(POLICY));
  const rules = join(dir, "rules.json");
  writeFileSync(rules, JSON.stringify(RULES));

  // 1) WITHOUT the proxy: the agent talks straight to the server.
  const raw = await collect([server], JSON.stringify(CALL) + "\n");
  const got = byId(raw.out).get(1)!.result as Record<string, unknown>;
  const gotData = (got.structuredContent ?? got) as Record<string, unknown>;
  console.log("WITHOUT proxy — what the agent's model receives:");
  console.log("  ", gotData);
  console.log("   -> ssn/card in agent context:", "ssn" in gotData || "card_number" in gotData);

  // 2) WITH aegis-mcp-proxy on the path (server unmodified).
  const through = await collect(
    [PROXY, "--policy", policy, "--tool-rules", rules, "--agent-id", "demo-host", "--audit-path", audit, "--", process.execPath, server],
    JSON.stringify(CALL) + "\n" + JSON.stringify(BAD) + "\n",
  );
  const m = byId(through.out);
  const thru = (m.get(1)!.result as Record<string, unknown>).structuredContent as Record<string, unknown>;
  console.log("\nWITH aegis-mcp-proxy — what the agent's model receives:");
  console.log("  ", thru);
  console.log("   -> ssn/card in agent context:", "ssn" in thru || "card_number" in thru, "(stripped at the process boundary)");

  const blocked = m.get(2)!.result as { isError?: boolean; content: Array<{ text: string }> };
  console.log("\nA tool the policy does not allow never even runs:");
  console.log("   exfiltrate_everything ->", blocked.isError ? "BLOCKED" : "forwarded", "-", blocked.content[0].text);

  const events = readFileSync(audit, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  console.log("\nCanonical audit events emitted:", events.map((e) => [e.enforcement_point, e.decision]));

  console.log(
    "\nTakeaway: the agent is on the tool path through the proxy. It cannot see " +
      "fields outside the declared scope, and cannot call a tool the policy does " +
      "not map — one line of MCP config, server unmodified.",
  );
}

main();
