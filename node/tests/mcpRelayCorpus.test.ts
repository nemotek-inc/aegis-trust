// MCP relay conformance — Node runner.
//
// Feeds each case of the shared corpus (conformance/mcp_relay.v0.json), line by
// line, to the shipped ShieldProxy and asserts the lines it sends each side and
// the events it writes. The Python SDK runs the SAME corpus
// (python/tests/test_mcp_relay_corpus.py), so both classify a server->host
// line the same way.

import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CanonicalEmitter, ENFORCEMENT_MCP_PROXY, loadCanonicalPolicy } from "../src/canonical.js";
import { ShieldProxy, type ToolRules } from "../src/mcpProxy.js";

interface Step {
  from: "host" | "server";
  msg: unknown;
  expect_host: unknown[];
  expect_server: unknown[];
}
interface Case {
  id: string;
  policy: string;
  flags?: {
    uninspected?: "withhold" | "pass";
    allow_declared_purpose?: boolean;
    tool_rules?: ToolRules;
    no_tool_rules?: boolean;
    unchecked_arguments?: "refuse" | "pass";
    interface_pins?: Record<string, unknown>;
  };
  steps: Step[];
  expect_events: Array<Record<string, unknown>>;
  host_may_contain?: string[];
}

const corpus = JSON.parse(
  readFileSync(new URL("../../conformance/mcp_relay.v0.json", import.meta.url), "utf8"),
) as {
  version: number;
  policies: Record<string, unknown>;
  tool_rules?: Record<string, ToolRules>;
  cases: Case[];
};

const EVENT_KEYS = ["purpose", "operation", "decision", "outcome", "reason_code", "blocked_fields", "allowed_fields"];

function asJson(v: unknown): unknown {
  if (typeof v !== "string") return undefined;
  try {
    const p = JSON.parse(v);
    return typeof p === "object" && p !== null ? p : undefined;
  } catch {
    return undefined;
  }
}

function match(expected: unknown, actual: unknown, handles: Map<string, string>, where: string): void {
  if (typeof expected === "string" && expected.startsWith("$H:")) {
    expect(typeof actual === "string" && actual.startsWith("aegis-"), `${where}: want a proxy handle, got ${JSON.stringify(actual)}`).toBe(true);
    const bound = handles.get(expected) ?? (actual as string);
    handles.set(expected, bound);
    expect(actual, `${where}: handle ${expected}`).toBe(bound);
    return;
  }
  if (Array.isArray(expected)) {
    expect(Array.isArray(actual) && actual.length === expected.length, `${where}: want ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`).toBe(true);
    expected.forEach((e, i) => match(e, (actual as unknown[])[i], handles, `${where}[${i}]`));
    return;
  }
  if (typeof expected === "object" && expected !== null) {
    expect(typeof actual === "object" && actual !== null && !Array.isArray(actual), `${where}: want object, got ${JSON.stringify(actual)}`).toBe(true);
    const a = actual as Record<string, unknown>;
    expect(Object.keys(a).sort(), `${where}: keys`).toEqual(Object.keys(expected).sort());
    for (const [k, v] of Object.entries(expected)) match(v, a[k], handles, `${where}.${k}`);
    return;
  }
  if (asJson(expected) !== undefined && asJson(actual) !== undefined) {
    match(asJson(expected), asJson(actual), handles, `${where}(json)`);
    return;
  }
  expect(actual, where).toStrictEqual(expected);
}

function substitute(v: unknown, handles: Map<string, string>): unknown {
  if (typeof v === "string" && v.startsWith("$H:")) return handles.get(v);
  if (Array.isArray(v)) return v.map((x) => substitute(x, handles));
  if (typeof v === "object" && v !== null) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substitute(x, handles)]));
  }
  return v;
}

function lines(raw: string | undefined): unknown[] {
  if (!raw) return [];
  return raw.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

describe("MCP relay corpus", () => {
  it("corpus is present and versioned", () => {
    expect(corpus.version).toBe(0);
    expect(corpus.cases.length).toBeGreaterThan(0);
  });

  for (const c of corpus.cases) {
    it(`relay: ${c.id}`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "aegis-relay-corpus-"));
      const policyPath = join(dir, "policy.json");
      const eventsPath = join(dir, "events.jsonl");
      writeFileSync(policyPath, JSON.stringify(corpus.policies[c.policy]));
      const policy = loadCanonicalPolicy(policyPath);
      const emitter = new CanonicalEmitter(ENFORCEMENT_MCP_PROXY, "corpus", eventsPath, policy.policyId);
      const proxy = new ShieldProxy(policy, emitter, "corpus-host", null, null, {
        uninspected: c.flags?.uninspected ?? "withhold",
        allowDeclaredPurpose: c.flags?.allow_declared_purpose ?? false,
        toolRules: c.flags?.no_tool_rules ? {} : (c.flags?.tool_rules ?? corpus.tool_rules?.[c.policy] ?? {}),
        uncheckedArguments: c.flags?.unchecked_arguments ?? "refuse",
        interfacePins: c.flags?.interface_pins ?? null,
      });
      const handles = new Map<string, string>();
      const hostBound: string[] = [];
      for (const [n, step] of c.steps.entries()) {
        const where = `${c.id} step ${n} (${step.from})`;
        const msg = substitute(step.msg, handles);
        let toHost: unknown[];
        let toServer: unknown[];
        if (step.from === "host") {
          const { forward, reply } = await proxy.handleClientLine(JSON.stringify(msg));
          toServer = lines(forward);
          toHost = lines(reply);
        } else {
          toHost = lines(proxy.handleServerLine(JSON.stringify(msg)));
          toServer = proxy.drainToServer().map((l) => JSON.parse(l));
        }
        match(step.expect_host, toHost, handles, `${where} host`);
        match(step.expect_server, toServer, handles, `${where} server`);
        hostBound.push(...toHost.map((m) => JSON.stringify(m)));
      }

      for (const l of hostBound) {
        let rest = l;
        for (const ok of c.host_may_contain ?? []) rest = rest.split(ok).join("");
        expect(rest.includes("LEAK-"), `${c.id}: an excluded value reached the host: ${l}`).toBe(false);
      }

      const events = existsSync(eventsPath)
        ? readFileSync(eventsPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>)
        : [];
      expect(events.length, `${c.id}: events ${JSON.stringify(events)}`).toBe(c.expect_events.length);
      c.expect_events.forEach((want, i) => {
        const got = events[i];
        for (const key of EVENT_KEYS) {
          if (want[key] === null || want[key] === undefined) {
            expect(key in got, `${c.id} event ${i}: ${key} should be absent`).toBe(false);
          } else if (key === "blocked_fields" || key === "allowed_fields") {
            expect([...((got[key] as string[]) ?? [])].sort(), `${c.id} event ${i}: ${key}`).toEqual(want[key]);
          } else {
            expect(got[key], `${c.id} event ${i}: ${key}`).toBe(want[key]);
          }
        }
        expect(JSON.stringify(got).includes("LEAK-"), `${c.id} event ${i} carries a value`).toBe(false);
      });
    });
  }
});
