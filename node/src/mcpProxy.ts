#!/usr/bin/env node
// shield-proxy: MCP process-boundary enforcement point (canonical contract v0).
// Faithful port of python/src/aegis_trust/mcp_proxy.py.
//
//     host  <--stdio-->  aegis-mcp-proxy  <--stdio-->  real MCP server
//
// Every tools/call result (plus resources/read, prompts/get,
// completion/complete) is filtered to the policy's scope before the host's
// model sees it; unmapped tools are blocked fail-closed; JSON-RPC batches and
// non-JSON server stdout are dropped. A canonical v0 audit event
// (enforcement_point=mcp_proxy) is emitted per call.
//
// Every server->host line is classified and rebuilt from a projection:
// what the field rule cannot inspect is withheld (--uninspected withhold, the
// default) or relayed and named as unfiltered (--uninspected pass), never
// recorded as protected; server requests other than ping / roots/list are
// refused; a declared arguments.purpose that differs from the tools map is
// refused unless --allow-declared-purpose. Interface metadata is relayed only as
// the operator pinned it (--interface-pins): an unpinned or differing entry is
// withheld (a tool keeps its policy-known name only) and named. Progress numbers
// are the proxy's own count. A tools/call's arguments pass only by the tool's
// rule (--tool-rules); a tool with no rule is refused unless
// --unchecked-arguments pass. Named limit: the presence and timing of lines.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, realpathSync, renameSync, writeSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import {
  CanonicalEmitter,
  CanonicalPolicy,
  CanonicalPurpose,
  ENFORCEMENT_MCP_PROXY,
  loadCanonicalPolicy,
} from "./canonical.js";
import { AegisClient, detectMode, getModuleClient } from "./client.js";
import { VERSION } from "./index.js";

const PROXY_RUNTIME = `mcp-proxy/${VERSION}`;

// Data-bearing host->server methods: each needs a purpose in the policy's
// tools map, and its reply goes through the field rule or the error rule.
const GATED_METHODS = new Set(["tools/call", "resources/read", "prompts/get", "completion/complete"]);

// FULL-mode per-call gate (the third PEP grows teeth). LITE keeps today's
// behavior; in FULL the proxy consults the gateway BEFORE forwarding a gated
// call, so a policy deny stops the tool from ever running. Gate kind is
// EXPLICIT (never auto-probed — a silent up/downgrade of the enforcement
// primitive is exactly the drift Aegis refuses):
//   check-access = @shield-parity purpose gate (every live gateway serves it);
//   tool-call    = AI-native per-tool-call gate (AI_NATIVE_V1_CONTRACT.md).
// Faithful mirror of python mcp_proxy.GatewayGate.
export class GatewayGate {
  constructor(
    private client: AegisClient,
    readonly kind: "check-access" | "tool-call",
    private owner: string,
  ) {}

  /** Returns [allowed, reasonCode]. Fail-closed on every error path. */
  async check(tool: string, purpose: CanonicalPurpose): Promise<[boolean, string]> {
    const scope = [...(purpose.scope ?? [])];
    if (this.kind === "tool-call") {
      // toolAllowed() is fail-closed internally (transport / non-200 /
      // malformed / non-passing / unledgered are all a deny).
      const allowed = await this.client.toolAllowed({
        tool,
        purpose: purpose.name,
        owner: this.owner,
        fields: scope,
      });
      return allowed ? [true, ""] : [false, "gateway_denied"];
    }
    // checkAccess (not authorize): authorize() swallows transport errors into
    // false, which would collapse "policy denied" and "gateway down" into one
    // audit reason. Both deny — but they must stay distinguishable.
    try {
      if (scope.length > 0) {
        for (const s of scope) {
          const resp = await this.client.checkAccess(purpose.name, [s]);
          if (resp.allowed !== true) return [false, "gateway_denied"];
        }
        return [true, ""];
      }
      const resp = await this.client.checkAccess(purpose.name, []);
      return resp.allowed === true ? [true, ""] : [false, "gateway_denied"];
    } catch {
      return [false, "gateway_unavailable"];
    }
  }
}

/** Notice put in place of a text the proxy could not check against the purpose. */
export const WITHHELD_NOTICE = (purpose: string): string =>
  `[Aegis: withheld — content could not be checked against purpose '${purpose}']`;
/** Message put in place of an upstream error message the proxy could not check. */
export const UPSTREAM_ERROR_NOTICE = "upstream error (withheld by Aegis)";

// (ii-a) The finite sets a relayed protocol value must belong to. A value that
// merely matches a grammar can still carry a server-chosen string, so
// membership is the rule, never a pattern.
const PROTOCOL_VERSIONS = new Set(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]);
const MEDIA_TYPES = new Set([
  "application/json",
  "text/plain",
  "text/markdown",
  "text/csv",
  "text/html",
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "audio/wav",
  "audio/mpeg",
  "application/pdf",
]);
const ERROR_CODES = new Set([-32700, -32600, -32601, -32602, -32603, -32002]);
const LOG_LEVELS = new Set([
  "debug",
  "info",
  "notice",
  "warning",
  "error",
  "critical",
  "alert",
  "emergency",
]);
const ROLES = new Set(["user", "assistant"]);
const CAPABILITY_FLAGS: Record<string, string[]> = {
  logging: [],
  completions: [],
  prompts: ["listChanged"],
  resources: ["subscribe", "listChanged"],
  tools: ["listChanged"],
};
const TOOL_HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];
// Listing replies are interface metadata, projected per method: the result key
// holding the entries, and the data method that must be mapped for the family
// to be listed at all ("tools/call" is checked per tool name).
const LISTING_METHODS: Record<string, [string, string]> = {
  "tools/list": ["tools", "tools/call"],
  "resources/list": ["resources", "resources/read"],
  "resources/templates/list": ["resourceTemplates", "resources/read"],
  "prompts/list": ["prompts", "prompts/get"],
};
const EMPTY_RESULT_METHODS = new Set([
  "ping",
  "resources/subscribe",
  "resources/unsubscribe",
  "logging/setLevel",
]);
const RELAYED_SERVER_REQUESTS = new Set(["ping", "roots/list"]);
const LIST_CHANGED = new Set([
  "notifications/tools/list_changed",
  "notifications/resources/list_changed",
  "notifications/prompts/list_changed",
]);

// The pin file's section for each listing, and the key that names an entry.
const PIN_SECTIONS: Record<string, [string, string]> = {
  "tools/list": ["tools", "name"],
  "prompts/list": ["prompts", "name"],
  "resources/list": ["resources", "uri"],
  "resources/templates/list": ["resourceTemplates", "uriTemplate"],
};
const NEUTRAL_SERVER_INFO = { name: "mcp-server", version: "0" };

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A copy with object keys sorted at every level (stable candidate files). */
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (isObj(v)) {
    const out: Obj = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
    return out;
  }
  return v;
}

/** Equality of two parsed JSON values, the same in the three implementations:
 * numbers by value, a boolean never equal to a number, objects by key set,
 * arrays in order. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (typeof a === "boolean" || typeof b === "boolean") return a === b;
  if (typeof a === "number" || typeof b === "number") return a === b;
  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every((x, i) => jsonEqual(x, b[i]));
  }
  if (isObj(a)) {
    if (!isObj(b)) return false;
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return ka.length === kb.length && ka.every((k, i) => k === kb[i] && jsonEqual(a[k], b[k]));
  }
  return a === b;
}

export class ProxyConfigError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

export type ToolRule = { access?: "read" | "write"; arguments?: { allow: string[] } };
export type ToolRules = Record<string, ToolRule>;

/** The --tool-rules document, checked: `{tool: {access, arguments: {allow}}}`.
 * `query` and `fields` rules are judged by aegis-mcp-relay only; a document that
 * has them is refused rather than read as if they were enforced here. */
export function validateToolRules(raw: unknown): ToolRules {
  if (!isObj(raw)) throw new ProxyConfigError("tool rules must be a JSON object", "aegis.mcp_proxy.tool_rules_invalid");
  for (const [tool, rule] of Object.entries(raw)) {
    if (!tool || !isObj(rule)) {
      throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)} must be an object`, "aegis.mcp_proxy.tool_rules_invalid");
    }
    const unknown = Object.keys(rule).filter((k) => k !== "access" && k !== "arguments");
    if (unknown.length > 0) {
      throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)}: unknown keys ${unknown.sort()}`, "aegis.mcp_proxy.tool_rules_invalid");
    }
    const access = rule.access ?? "write";
    if (access !== "read" && access !== "write") {
      throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)}: access must be read or write`, "aegis.mcp_proxy.tool_rules_invalid");
    }
    if (rule.arguments !== undefined) {
      const args = rule.arguments;
      if (!isObj(args)) {
        throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)}: arguments must be an object`, "aegis.mcp_proxy.tool_rules_invalid");
      }
      const relayOnly = Object.keys(args).filter((k) => k === "query" || k === "fields");
      if (relayOnly.length > 0) {
        throw new ProxyConfigError(
          `tool rule ${JSON.stringify(tool)}: ${relayOnly.sort()} are judged by aegis-mcp-relay only; this proxy does not enforce them`,
          "aegis.mcp_proxy.tool_rules_relay_only",
        );
      }
      const other = Object.keys(args).filter((k) => k !== "allow");
      if (other.length > 0) {
        throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)}: unknown argument keys ${other.sort()}`, "aegis.mcp_proxy.tool_rules_invalid");
      }
      const allow = args.allow;
      if (!Array.isArray(allow) || !allow.every((p) => typeof p === "string" && p.length > 0)) {
        throw new ProxyConfigError(`tool rule ${JSON.stringify(tool)}: arguments.allow must be a list of paths`, "aegis.mcp_proxy.tool_rules_invalid");
      }
    }
  }
  return raw as ToolRules;
}

/** The --interface-pins document: `{version: 0, initialize, tools, prompts,
 * resources, resourceTemplates}`, each value a projected entry. */
export function validateInterfacePins(raw: unknown): Obj {
  if (!isObj(raw) || raw.version !== 0) {
    throw new ProxyConfigError("interface pins must be an object with version 0", "aegis.mcp_proxy.interface_pins_invalid");
  }
  const sections = new Set(Object.values(PIN_SECTIONS).map(([s]) => s));
  const unknown = Object.keys(raw).filter((k) => !sections.has(k) && k !== "version" && k !== "initialize");
  if (unknown.length > 0) {
    throw new ProxyConfigError(`interface pins: unknown keys ${unknown.sort()}`, "aegis.mcp_proxy.interface_pins_invalid");
  }
  for (const s of sections) {
    if (s in raw && !isObj(raw[s])) throw new ProxyConfigError(`interface pins: ${s} must be an object`, "aegis.mcp_proxy.interface_pins_invalid");
  }
  if ("initialize" in raw && !isObj(raw.initialize)) {
    throw new ProxyConfigError("interface pins: initialize must be an object", "aegis.mcp_proxy.interface_pins_invalid");
  }
  return raw;
}

/** Every leaf path of a tool call's arguments (an array or an empty object is a
 * leaf). A key that is empty or contains '.' cannot be named by a path and is
 * reported in `bad`. */
function leafPaths(value: unknown, prefix: string, out: string[], bad: string[]): void {
  if (isObj(value) && Object.keys(value).length > 0) {
    for (const [key, item] of Object.entries(value)) {
      if (!key || key.includes(".")) {
        bad.push(prefix ? `${prefix}.${key}` : key);
        continue;
      }
      leafPaths(item, prefix ? `${prefix}.${key}` : key, out, bad);
    }
  } else if (prefix) {
    out.push(prefix);
  }
}

/** The argument rule of one tools/call: null = passes, else [reason, refused
 * names]. The same rule as aegis-mcp-relay's: a read tool and a write tool alike
 * pass only with every leaf on arguments.allow. */
export function checkArguments(rule: ToolRule | undefined, args: unknown): [string, string[]] | null {
  if (rule === undefined) return ["argument_rule_missing", []];
  const allow = isObj(rule.arguments) ? rule.arguments.allow : undefined;
  if (!Array.isArray(allow)) return ["argument_rule_missing", []];
  if (args === undefined || args === null) return null;
  if (!isObj(args)) return ["argument_not_allowed", ["<arguments>"]];
  const paths: string[] = [];
  const bad: string[] = [];
  leafPaths(args, "", paths, bad);
  const refused = [...bad, ...paths.filter((p) => !allow.some((a) => p === a || p.startsWith(`${a}.`)))];
  return refused.length > 0 ? ["argument_not_allowed", [...new Set(refused)].sort()] : null;
}

function obj(v: unknown): Obj {
  return isObj(v) ? v : {};
}

function isNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/** A JSON-RPC id usable as a map key, or null when it cannot name a request. */
function idKey(v: unknown): string | null {
  if (typeof v === "string") return `s:${v}`;
  if (isNum(v)) return `n:${v}`;
  return null;
}

function line(msg: unknown): string {
  return JSON.stringify(msg) + "\n";
}

function errorReply(id: unknown, code: number, message: string): string {
  return line({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
}

function errorCode(code: unknown): number {
  return isNum(code) && ERROR_CODES.has(code) ? code : -32603;
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

interface HostRequest {
  method: string;
  operation: string;
  purpose: string | null; // set only for gated methods
  uri: string | null; // resources/read: the URI the host asked for
  declaredOverride: boolean; // the purpose came from arguments.purpose
  argumentsUnchecked?: boolean; // forwarded without a rule (--unchecked-arguments pass)
}

/** What one gated reply released, removed, withheld, or passed uninspected. */
class Disclosure {
  readonly passMode: boolean;
  readonly blocked: string[] = [];
  readonly unfiltered: string[] = [];

  constructor(
    readonly purpose: string,
    uninspected: "withhold" | "pass",
  ) {
    this.passMode = uninspected === "pass";
  }

  /** Record a carrier the field rule cannot apply to. true = relay it. */
  uninspected(path: string): boolean {
    if (this.passMode) {
      this.unfiltered.push(`<unfiltered:${path}>`);
      return true;
    }
    this.blocked.push(`<withheld:${path}>`);
    return false;
  }

  notice(): string {
    return WITHHELD_NOTICE(this.purpose);
  }

  // `protected` only when every carrier was inspected and nothing was removed.
  verdict(): { outcome: string | null; reason: string | null; blocked: string[]; unfiltered: string[] } {
    const blocked = [...new Set(this.blocked)].sort();
    const unfiltered = [...new Set(this.unfiltered)].sort();
    if (unfiltered.length > 0) {
      return {
        outcome: blocked.length > 0 ? "access_reduced" : null,
        reason: "unfiltered_passthrough",
        blocked,
        unfiltered,
      };
    }
    if (blocked.length > 0) {
      return { outcome: "access_reduced", reason: "minimum_disclosure", blocked, unfiltered };
    }
    return { outcome: "protected", reason: null, blocked, unfiltered };
  }
}

export interface ShieldProxyOptions {
  uninspected?: "withhold" | "pass";
  allowDeclaredPurpose?: boolean;
  toolRules?: ToolRules;
  uncheckedArguments?: "refuse" | "pass";
  interfacePins?: Obj | null;
  candidatesPath?: string | null;
}

// No server line is relayed as the server wrote it: every relayed line is
// rebuilt from a projection fixed per kind of line, and anything the proxy does
// not recognise is dropped. A value in a projection is inspected by the
// purpose's field rule, is a protocol value that carries no server-chosen
// string (a member of a finite set, an echo of a host value, or a handle the
// proxy owns), or is uninspected and handled by `uninspected`. Faithful mirror
// of python mcp_proxy.ShieldProxy; both run conformance/mcp_relay.v0.json.
export class ShieldProxy {
  readonly uninspected: "withhold" | "pass";
  readonly allowDeclaredPurpose: boolean;
  readonly toolRules: ToolRules;
  readonly uncheckedArguments: "refuse" | "pass";
  readonly interfacePins: Obj;
  /** Projected server entries that were not relayed as pinned, for the operator
   * to review and approve (--interface-candidates). */
  readonly candidates: Obj = { version: 0 };
  private candidatesPath: string | null;
  private progressCounts = new Map<string, number>();
  private pending = new Map<string, HostRequest>();
  private cursors = new Map<string, [string, string]>(); // handle -> [method, server cursor]
  private serverRequests = new Map<string, unknown>(); // proxy id -> server id
  private serverIds = new Map<string, string>(); // server id key -> proxy id
  private progressTokens = new Set<string>();
  private subscriptions = new Set<string>();
  private toServer: string[] = [];
  private logEventPending = true;

  constructor(
    private policy: CanonicalPolicy,
    private emitter: CanonicalEmitter,
    private agentId: string,
    private sessionId: string | null = null,
    private gate: GatewayGate | null = null,
    options: ShieldProxyOptions = {},
  ) {
    const mode = options.uninspected ?? "withhold";
    if (mode !== "withhold" && mode !== "pass") {
      throw new Error(`unknown uninspected mode ${String(mode)}`);
    }
    this.uninspected = mode;
    this.allowDeclaredPurpose = options.allowDeclaredPurpose ?? false;
    const unchecked = options.uncheckedArguments ?? "refuse";
    if (unchecked !== "refuse" && unchecked !== "pass") {
      throw new Error(`unknown uncheckedArguments mode ${String(unchecked)}`);
    }
    this.uncheckedArguments = unchecked;
    this.toolRules = validateToolRules(options.toolRules ?? {});
    // No pin file = nothing approved (the metadata is withheld, not relayed).
    this.interfacePins = validateInterfacePins(options.interfacePins ?? { version: 0 });
    this.candidatesPath = options.candidatesPath ?? null;
  }

  private principal(): Obj {
    return { agent_id: this.agentId, session_id: this.sessionId, transport: "mcp" };
  }

  private blockReply(id: unknown, operation: string, reason: string): string {
    return line({
      jsonrpc: "2.0",
      id: id ?? null,
      result: {
        content: [
          {
            type: "text",
            text: `Aegis shield-proxy: '${operation}' blocked (${reason}, fail-closed).`,
          },
        ],
        isError: true,
      },
    });
  }

  /** A refusal. `blockedFields` names what was refused (argument names, never values). */
  private deny(purpose: string, operation: string, reasonCode: string, blockedFields: string[] = []): void {
    this.emitter.emit({
      principal: this.principal(),
      purpose,
      operation,
      decision: "deny",
      outcome: "blocked",
      reasonCode,
      blockedFields: [...new Set(blockedFields)].sort(),
    });
  }

  // -- host -> server -------------------------------------------------------
  // Returns { forward, reply }; exactly one is set. Async because the FULL
  // gate awaits the gateway; LITE resolves immediately.
  async handleClientLine(raw: string): Promise<{ forward?: string; reply?: string }> {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      return { forward: raw }; // not ours to judge; transport passthrough
    }
    if (Array.isArray(msg)) {
      // JSON-RPC batch: a batched response would bypass result filtering. No
      // batching in current MCP; fail-closed, never forward.
      this.deny("unknown", "<batch>", "batch_rejected");
      return { reply: this.blockReply(null, "<batch>", "batch_rejected") };
    }
    if (!isObj(msg)) return { forward: raw };
    const m = msg;
    const method = m.method;
    if (typeof method !== "string") {
      // The host's reply to a server request the proxy relayed under its own
      // id goes back under the server's id.
      if (typeof m.id === "string" && this.serverRequests.has(m.id)) {
        const serverId = this.serverRequests.get(m.id);
        this.serverRequests.delete(m.id);
        const k = idKey(serverId);
        if (k !== null) this.serverIds.delete(k);
        return { forward: line({ ...m, id: serverId }) };
      }
      return { forward: raw };
    }
    if (!("id" in m)) return { forward: raw }; // a host notification
    const id = m.id;
    const params = obj(m.params);
    this.rememberHostValues(method, params);

    if (method.startsWith("tasks/")) {
      // 2025-11-25 tasks carry a call's result out of band; refused.
      this.deny("unknown", method, "task_refused");
      return { reply: this.blockReply(id, method, "task_refused") };
    }

    let forward = raw;
    if (method in LISTING_METHODS && "cursor" in params) {
      const entry = typeof params.cursor === "string" ? this.cursors.get(params.cursor) : undefined;
      if (entry === undefined || entry[0] !== method) {
        return { reply: errorReply(id, -32602, "Aegis: unknown cursor") };
      }
      forward = line({ ...m, params: { ...params, cursor: entry[1] } });
    }

    if (!GATED_METHODS.has(method)) {
      this.remember(id, { method, operation: method, purpose: null, uri: null, declaredOverride: false });
      return { forward };
    }

    let operation: string;
    let lookup: string;
    let declared: string | undefined;
    if (method === "tools/call") {
      operation = typeof params.name === "string" ? params.name : "<unknown>";
      if ("task" in params) {
        this.deny("unknown", operation, "task_augmented_refused");
        return { reply: this.blockReply(id, operation, "task_augmented_refused") };
      }
      const args = params.arguments;
      const p = isObj(args) ? args.purpose : undefined;
      declared = typeof p === "string" && p ? p : undefined;
      lookup = operation;
    } else {
      let ref: unknown = params.uri || params.name || "";
      if (method === "completion/complete" && isObj(params.ref)) {
        ref = params.ref.name || params.ref.uri || "";
      }
      operation = typeof ref === "string" ? `${method}:${ref}` : method;
      lookup = method;
      declared = undefined;
    }

    const mapped = Object.prototype.hasOwnProperty.call(this.policy.tools, lookup)
      ? this.policy.tools[lookup]
      : undefined;
    let purpose: CanonicalPurpose | null;
    let override = false;
    if (this.allowDeclaredPurpose) {
      purpose = this.policy.purposeForTool(lookup, declared);
      override = declared !== undefined && declared !== mapped;
    } else {
      // The model writes arguments.purpose; in the proxy it is not the caller
      // the policy's "explicit declaration wins" rule trusts.
      if (mapped !== undefined && declared !== undefined && declared !== mapped) {
        this.deny(declared, operation, "declared_purpose_refused");
        return { reply: this.blockReply(id, operation, "declared_purpose_refused") };
      }
      purpose = mapped !== undefined ? this.policy.purposes[mapped] ?? null : null;
    }

    if (purpose === null) {
      this.deny(declared || "unknown", operation, "unknown_tool");
      return { reply: this.blockReply(id, operation, "unknown_tool") };
    }
    // host->server: a tools/call's arguments pass only by the tool's rule.
    let argumentsUnchecked = false;
    if (method === "tools/call") {
      const rule = Object.prototype.hasOwnProperty.call(this.toolRules, lookup) ? this.toolRules[lookup] : undefined;
      if (rule === undefined && this.uncheckedArguments === "pass") {
        argumentsUnchecked = true;
      } else {
        const refusal = checkArguments(rule, params.arguments);
        if (refusal !== null) {
          const [reason, names] = refusal;
          this.deny(purpose.name, operation, reason, names);
          return { reply: this.blockReply(id, operation, reason) };
        }
      }
    }
    if (this.gate !== null) {
      const [allowed, reason] = await this.gate.check(operation, purpose);
      if (!allowed) {
        // FULL gate deny: the tool NEVER runs (pre-call, like @shield).
        this.deny(purpose.name, operation, reason);
        return { reply: this.blockReply(id, operation, reason) };
      }
    }
    const uri = method === "resources/read" && typeof params.uri === "string" ? params.uri : null;
    this.remember(id, {
      method,
      operation,
      purpose: purpose.name,
      uri,
      declaredOverride: override,
      argumentsUnchecked,
    });
    return { forward };
  }

  private remember(id: unknown, request: HostRequest): void {
    const k = idKey(id);
    if (k !== null) this.pending.set(k, request);
  }

  /** (ii-b) values the host itself sent, which the server may echo back. */
  private rememberHostValues(method: string, params: Obj): void {
    const meta = params._meta;
    const token = isObj(meta) ? idKey(meta.progressToken) : null;
    if (token !== null) this.progressTokens.add(token);
    const uri = typeof params.uri === "string" ? params.uri : null;
    if (method === "resources/subscribe" && uri) this.subscriptions.add(uri);
    else if (method === "resources/unsubscribe" && uri) this.subscriptions.delete(uri);
  }

  // -- server -> host -------------------------------------------------------
  // Returns the line to relay to the host ("" = nothing). Lines the proxy owes
  // the server (a refusal of a server request) are queued for drainToServer().
  handleServerLine(raw: string): string {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      process.stderr.write("aegis-mcp-proxy: dropped non-JSON server stdout line\n");
      return "";
    }
    if (Array.isArray(msg)) {
      process.stderr.write("aegis-mcp-proxy: dropped JSON-RPC batch from server\n");
      return "";
    }
    if (!isObj(msg)) {
      process.stderr.write("aegis-mcp-proxy: dropped non-object server line\n");
      return "";
    }
    const method = msg.method;
    if (typeof method === "string") {
      return "id" in msg ? this.serverRequest(msg, method) : this.serverNotification(msg, method);
    }
    if ("id" in msg && ("result" in msg || "error" in msg)) return this.serverReply(msg);
    process.stderr.write("aegis-mcp-proxy: dropped unrecognised server line\n");
    return "";
  }

  /** Lines the proxy itself owes the server, in order. */
  drainToServer(): string[] {
    const out = this.toServer;
    this.toServer = [];
    return out;
  }

  private serverReply(msg: Obj): string {
    const k = idKey(msg.id);
    const request = k !== null ? this.pending.get(k) : undefined;
    if (request === undefined || k === null) {
      // No outstanding host request has this id: a duplicate reply, or one the
      // host never asked for. Dropped — relaying would bypass the filter.
      this.deny("unknown", "<reply>", "unmatched_response");
      return "";
    }
    this.pending.delete(k);
    const id = msg.id;
    if (request.purpose !== null) return this.gatedReply(id, msg, request);
    if ("error" in msg) {
      return line({ jsonrpc: "2.0", id, error: this.ungatedError(msg.error) });
    }
    const result = msg.result;
    if (request.method === "initialize") {
      const projected = this.projectInitialize(result);
      if (projected === null) {
        this.deny("unknown", "initialize", "protocol_version_unsupported");
        return errorReply(id, -32603, "Aegis: unsupported protocol version");
      }
      const pinned = this.pinInitialize(projected);
      this.flushCandidates();
      return line({ jsonrpc: "2.0", id, result: pinned });
    }
    if (request.method in LISTING_METHODS) {
      const listing = this.projectListing(request.method, result);
      this.flushCandidates();
      return line({ jsonrpc: "2.0", id, result: listing });
    }
    if (EMPTY_RESULT_METHODS.has(request.method)) {
      return line({ jsonrpc: "2.0", id, result: {} });
    }
    // A reply to a method the proxy has no projection for.
    this.deny("unknown", request.method, "unrecognized_method_reply");
    return errorReply(id, -32603, "Aegis: reply to an unrecognized method withheld");
  }

  private gatedReply(id: unknown, msg: Obj, request: HostRequest): string {
    const purpose = this.policy.purposes[request.purpose as string];
    const d = new Disclosure(purpose.name, this.uninspected);
    // The call went out without an argument rule: the reply never says protected.
    if (request.argumentsUnchecked) d.unfiltered.push("<unfiltered:arguments>");
    const out =
      "error" in msg
        ? { jsonrpc: "2.0", id, error: this.gatedError(d, purpose, msg.error) }
        : { jsonrpc: "2.0", id, result: this.projectGatedResult(d, purpose, msg.result, request) };
    const v = d.verdict();
    this.emitter.emit({
      principal: this.principal(),
      purpose: purpose.name,
      operation: request.operation,
      decision: "allow",
      outcome: v.outcome,
      reasonCode: request.declaredOverride ? "declared_purpose_override" : v.reason,
      blockedFields: v.blocked,
      allowedFields: v.unfiltered.length > 0 ? v.unfiltered : null,
      scope: purpose.scope ?? null,
      denyFields: purpose.denyFields ?? null,
    });
    this.logEventPending = true;
    return line(out);
  }

  // G2: a gated result, rebuilt from the projection only.
  private projectGatedResult(d: Disclosure, purpose: CanonicalPurpose, result: unknown, request: HostRequest): unknown {
    if (!isObj(result)) return d.uninspected("result") ? result : {};
    const out: Obj = {};
    for (const [key, value] of Object.entries(result)) {
      if (key === "structuredContent" && typeof value === "object" && value !== null) {
        out[key] = this.applyRule(d, purpose, value);
      } else if (key === "isError" && typeof value === "boolean") {
        out[key] = value;
      } else if (key === "content" && Array.isArray(value) && request.method === "tools/call") {
        out[key] = value.map((item, i) => this.projectBlock(d, purpose, item, `content[${i}]`));
      } else if (key === "contents" && Array.isArray(value) && request.method === "resources/read") {
        out[key] = value.map((item, i) => this.projectContents(d, purpose, item, `contents[${i}]`, request.uri));
      } else if (key === "messages" && Array.isArray(value) && request.method === "prompts/get") {
        const messages: unknown[] = [];
        value.forEach((item, i) => {
          const projected = this.projectMessage(d, purpose, item, `messages[${i}]`);
          if (projected !== undefined) messages.push(projected);
        });
        out[key] = messages;
      } else if (key === "completion" && isObj(value) && request.method === "completion/complete") {
        out[key] = this.projectCompletion(d, value);
      } else if (d.uninspected(key)) {
        out[key] = value;
      }
    }
    return out;
  }

  private applyRule(d: Disclosure, purpose: CanonicalPurpose, payload: unknown): unknown {
    const { filtered, removed } = this.policy.filterPayload(purpose, payload);
    d.blocked.push(...removed);
    return filtered;
  }

  /** The field rule's output when the text is JSON as a whole, the text itself
   * when uninspected carriers pass, else undefined. */
  private projectText(d: Disclosure, purpose: CanonicalPurpose, text: unknown, path: string): unknown {
    if (typeof text === "string") {
      let payload: unknown;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = undefined;
      }
      if (typeof payload === "object" && payload !== null) {
        return JSON.stringify(this.applyRule(d, purpose, payload));
      }
    }
    return d.uninspected(path) ? text : undefined;
  }

  /** Every key outside the projection is uninspected. */
  private rest(d: Disclosure, source: Obj, out: Obj, path: string, known: string[]): void {
    for (const [key, value] of Object.entries(source)) {
      if (!known.includes(key) && d.uninspected(`${path}.${key}`)) out[key] = value;
    }
  }

  private media(d: Disclosure, source: Obj, out: Obj, path: string): void {
    const mime = source.mimeType;
    if (mime === undefined || mime === null) return;
    if (typeof mime === "string" && MEDIA_TYPES.has(mime)) out.mimeType = mime;
    else if (d.uninspected(`${path}.mimeType`)) out.mimeType = mime;
  }

  /** A content block (tools/call content, prompts/get message content). */
  private projectBlock(d: Disclosure, purpose: CanonicalPurpose, item: unknown, path: string): unknown {
    if (!isObj(item)) {
      return d.uninspected(path) ? item : { type: "text", text: d.notice() };
    }
    const kind = item.type;
    if (kind === "text") {
      const text = this.projectText(d, purpose, item.text, `${path}.text`);
      const out: Obj = { type: "text", text: text === undefined ? d.notice() : text };
      this.rest(d, item, out, path, ["type", "text"]);
      return out;
    }
    if (kind === "resource" && isObj(item.resource)) {
      const resource = item.resource;
      const text =
        "text" in resource ? this.projectText(d, purpose, resource.text, `${path}.resource.text`) : undefined;
      if (text === undefined && !d.passMode) {
        // Nothing in the item could be inspected (blob, or text that is not
        // JSON): the whole item becomes the notice.
        this.rest(d, resource, {}, `${path}.resource`, ["text", "mimeType"]);
        return { type: "text", text: d.notice() };
      }
      const inner: Obj = {};
      if (resource.uri !== undefined && resource.uri !== null) {
        inner.uri = d.uninspected(`${path}.resource.uri`) ? resource.uri : "aegis:withheld";
      }
      this.media(d, resource, inner, `${path}.resource`);
      if (text !== undefined) inner.text = text;
      this.rest(d, resource, inner, `${path}.resource`, ["uri", "mimeType", "text"]);
      const out: Obj = { type: "resource", resource: inner };
      this.rest(d, item, out, path, ["type", "resource"]);
      return out;
    }
    // image / audio data, resource_link, an unknown type: nothing to apply the
    // field rule to.
    return d.uninspected(path) ? item : { type: "text", text: d.notice() };
  }

  /** resources/read contents: {uri, mimeType?, text | blob}. */
  private projectContents(
    d: Disclosure,
    purpose: CanonicalPurpose,
    item: unknown,
    path: string,
    asked: string | null,
  ): unknown {
    if (!isObj(item)) {
      return d.uninspected(path) ? item : { uri: asked || "aegis:withheld", text: d.notice() };
    }
    const out: Obj = {};
    const uri = item.uri;
    if (typeof uri === "string" && uri === asked) {
      out.uri = uri; // (ii-b) the URI the host asked for
    } else if (uri !== undefined && uri !== null && d.uninspected(`${path}.uri`)) {
      out.uri = uri;
    } else {
      out.uri = asked || "aegis:withheld";
    }
    this.media(d, item, out, path);
    if ("text" in item) {
      const text = this.projectText(d, purpose, item.text, `${path}.text`);
      out.text = text === undefined ? d.notice() : text;
    } else if (!d.passMode) {
      out.text = d.notice();
    }
    this.rest(d, item, out, path, ["uri", "mimeType", "text"]);
    return out;
  }

  private projectMessage(d: Disclosure, purpose: CanonicalPurpose, item: unknown, path: string): unknown {
    if (!isObj(item) || typeof item.role !== "string" || !ROLES.has(item.role)) {
      return d.uninspected(path) ? item : undefined;
    }
    const out: Obj = { role: item.role };
    out.content = this.projectBlock(d, purpose, item.content, `${path}.content`);
    this.rest(d, item, out, path, ["role", "content"]);
    return out;
  }

  private projectCompletion(d: Disclosure, completion: Obj): Obj {
    const out: Obj = { values: [] };
    for (const [key, value] of Object.entries(completion)) {
      if (d.uninspected(`completion.${key}`)) out[key] = value;
    }
    return out;
  }

  // G3: an error reply to a gated request.
  private gatedError(d: Disclosure, purpose: CanonicalPurpose, error: unknown): Obj {
    if (!isObj(error)) {
      d.uninspected("error");
      return { code: -32603, message: UPSTREAM_ERROR_NOTICE };
    }
    const out: Obj = { code: errorCode(error.code) };
    const message = error.message;
    out.message =
      message !== undefined && message !== null && d.uninspected("error.message") ? message : UPSTREAM_ERROR_NOTICE;
    if ("data" in error) {
      const data = error.data;
      if (typeof data === "object" && data !== null) out.data = this.applyRule(d, purpose, data);
      else if (d.uninspected("error.data")) out.data = data;
    }
    this.rest(d, error, out, "error", ["code", "message", "data"]);
    return out;
  }

  private ungatedError(error: unknown): Obj {
    const e = obj(error);
    return {
      code: errorCode(e.code),
      message: this.uninspected === "pass" && typeof e.message === "string" ? e.message : UPSTREAM_ERROR_NOTICE,
    };
  }

  // Ungated replies: interface metadata, projected per method.
  private projectInitialize(result: unknown): Obj | null {
    if (!isObj(result) || typeof result.protocolVersion !== "string" || !PROTOCOL_VERSIONS.has(result.protocolVersion)) {
      return null;
    }
    const out: Obj = { protocolVersion: result.protocolVersion };
    const caps = obj(result.capabilities);
    const projectedCaps: Obj = {};
    for (const [name, flags] of Object.entries(CAPABILITY_FLAGS)) {
      const value = caps[name];
      if (isObj(value)) {
        const kept: Obj = {};
        for (const f of flags) if (typeof value[f] === "boolean") kept[f] = value[f];
        projectedCaps[name] = kept;
      }
    }
    out.capabilities = projectedCaps;
    const info = obj(result.serverInfo);
    const serverInfo: Obj = {};
    for (const k of ["name", "title", "version"]) if (typeof info[k] === "string") serverInfo[k] = info[k];
    if (serverInfo.name === undefined) serverInfo.name = "mcp-server";
    if (serverInfo.version === undefined) serverInfo.version = "0";
    out.serverInfo = serverInfo;
    if (typeof result.instructions === "string") out.instructions = result.instructions;
    return out;
  }

  private familyMapped(method: string): boolean {
    const dataMethod = LISTING_METHODS[method][1];
    return dataMethod === "tools/call" || Object.prototype.hasOwnProperty.call(this.policy.tools, dataMethod);
  }

  /** serverInfo and instructions are server-written: relayed only as approved
   * (the pin's `initialize`). */
  private pinInitialize(projected: Obj): Obj {
    const iface: Obj = {};
    for (const k of ["serverInfo", "instructions"]) if (k in projected) iface[k] = projected[k];
    const pinned = this.interfacePins.initialize;
    if (pinned !== undefined && jsonEqual(pinned, iface)) return projected;
    this.candidates.initialize = iface;
    if (this.uninspected === "pass") {
      this.interfaceEvent("initialize", [], ["<unfiltered:initialize>"]);
      return projected;
    }
    const out: Obj = {};
    for (const [k, v] of Object.entries(projected)) if (!(k in iface)) out[k] = v;
    out.serverInfo = { ...NEUTRAL_SERVER_INFO };
    this.interfaceEvent("initialize", ["<withheld:initialize>"], []);
    return out;
  }

  /** One listing entry: the pinned value when the server's projected entry
   * equals it; otherwise withheld (a tool keeps its policy-known name only) or,
   * under uninspected=pass, relayed and named. */
  private pinEntry(method: string, index: number, projected: Obj, withheld: string[], unfiltered: string[]): Obj | null {
    const [section, keyName] = PIN_SECTIONS[method];
    const key = projected[keyName];
    const pins = obj(this.interfacePins[section]);
    const pinned = typeof key === "string" && Object.prototype.hasOwnProperty.call(pins, key) ? pins[key] : undefined;
    if (pinned !== undefined && jsonEqual(pinned, projected)) return pinned as Obj;
    if (typeof key === "string") {
      const bucket = obj(this.candidates[section]);
      bucket[key] = projected;
      this.candidates[section] = bucket;
    }
    // A tool's name comes from the operator's policy; any other entry's name or
    // URI is server-written, so the marker names its position only.
    const marker = method === "tools/list" ? `${method}:${String(key)}` : `${method}[${index}]`;
    if (this.uninspected === "pass") {
      unfiltered.push(`<unfiltered:${marker}>`);
      return projected;
    }
    withheld.push(`<withheld:${marker}>`);
    if (method === "tools/list") return { name: key, inputSchema: { type: "object" } };
    return null;
  }

  private interfaceEvent(operation: string, withheld: string[], unfiltered: string[]): void {
    if (withheld.length === 0 && unfiltered.length === 0) return;
    this.emitter.emit({
      principal: this.principal(),
      purpose: "unknown",
      operation,
      decision: "allow",
      outcome: withheld.length > 0 ? "access_reduced" : null,
      reasonCode: withheld.length > 0 ? "interface_unapproved" : "unfiltered_passthrough",
      blockedFields: [...new Set(withheld)].sort(),
      allowedFields: unfiltered.length > 0 ? [...new Set(unfiltered)].sort() : null,
    });
  }

  /** Write the candidates for the operator (owner-only, replaced whole). The
   * file holds server-written metadata: it is for review, never relayed. */
  private flushCandidates(): void {
    if (!this.candidatesPath) return;
    const tmp = `${this.candidatesPath}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, JSON.stringify(sortKeys(this.candidates), null, 1) + "\n");
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.candidatesPath);
  }

  private projectListing(method: string, result: unknown): Obj {
    const key = LISTING_METHODS[method][0];
    const entries = isObj(result) ? result[key] : undefined;
    const projected: unknown[] = [];
    const out: Obj = { [key]: projected };
    if (!this.familyMapped(method) || !Array.isArray(entries)) return out;
    const withheld: string[] = [];
    const unfiltered: string[] = [];
    entries.forEach((entry, index) => {
      if (!isObj(entry)) return;
      const p = this.projectEntry(method, entry);
      if (p === null) return;
      const relayed = this.pinEntry(method, index, p, withheld, unfiltered);
      if (relayed !== null) projected.push(relayed);
    });
    this.interfaceEvent(method, withheld, unfiltered);
    const cursor = obj(result).nextCursor;
    if (typeof cursor === "string" && cursor) {
      const handle = "aegis-cursor-" + randomHex(16); // (ii-c)
      this.cursors.set(handle, [method, cursor]);
      out.nextCursor = handle;
    }
    return out;
  }

  private projectEntry(method: string, entry: Obj): Obj | null {
    const strings = (...keys: string[]): Obj => {
      const out: Obj = {};
      for (const k of keys) if (typeof entry[k] === "string") out[k] = entry[k];
      return out;
    };
    if (method === "tools/list") {
      const name = entry.name;
      if (typeof name !== "string") return null;
      if (!this.allowDeclaredPurpose && !Object.prototype.hasOwnProperty.call(this.policy.tools, name)) {
        return null; // calling it would be blocked anyway
      }
      const out = strings("name", "title", "description");
      out.inputSchema = isObj(entry.inputSchema) ? entry.inputSchema : { type: "object" };
      if (isObj(entry.outputSchema)) out.outputSchema = entry.outputSchema;
      if (isObj(entry.annotations)) {
        const hints = entry.annotations;
        const kept: Obj = {};
        for (const h of TOOL_HINTS) if (typeof hints[h] === "boolean") kept[h] = hints[h];
        if (Object.keys(kept).length > 0) out.annotations = kept;
      }
      return out;
    }
    if (method === "prompts/list") {
      if (typeof entry.name !== "string") return null;
      const out = strings("name", "title", "description");
      if (Array.isArray(entry.arguments)) {
        out.arguments = entry.arguments
          .filter((a): a is Obj => isObj(a) && typeof a.name === "string")
          .map((a) => {
            const arg: Obj = {};
            for (const k of ["name", "title", "description"]) if (typeof a[k] === "string") arg[k] = a[k];
            if (typeof a.required === "boolean") arg.required = a.required;
            return arg;
          });
      }
      return out;
    }
    const locator = method === "resources/list" ? "uri" : "uriTemplate";
    if (typeof entry[locator] !== "string" || typeof entry.name !== "string") return null;
    const out = strings(locator, "name", "title", "description");
    if (typeof entry.mimeType === "string" && MEDIA_TYPES.has(entry.mimeType)) out.mimeType = entry.mimeType;
    return out;
  }

  // Server notifications and server requests.
  private serverNotification(msg: Obj, method: string): string {
    const params = obj(msg.params);
    const out: Obj = { jsonrpc: "2.0", method };
    if (method === "notifications/cancelled") {
      // The server cancels a request it sent; relayed only under the id the
      // host saw (ii-c).
      const k = idKey(params.requestId);
      const proxyId = k !== null ? this.serverIds.get(k) : undefined;
      if (proxyId === undefined) return "";
      const p: Obj = { requestId: proxyId };
      if (params.reason !== undefined && params.reason !== null && this.uninspected === "pass") {
        p.reason = params.reason;
      }
      out.params = p;
      return line(out);
    }
    if (method === "notifications/progress") {
      const k = idKey(params.progressToken);
      if (k === null || !this.progressTokens.has(k)) return "";
      // The number is the proxy's own count, never the server's: a number a
      // server chooses can carry a value one notification at a time.
      const count = (this.progressCounts.get(k) ?? 0) + 1;
      this.progressCounts.set(k, count);
      const p: Obj = { progressToken: params.progressToken, progress: count };
      if (params.message !== undefined && params.message !== null && this.uninspected === "pass") {
        p.message = params.message;
      }
      out.params = p;
      return line(out);
    }
    if (LIST_CHANGED.has(method)) return line(out);
    if (method === "notifications/resources/updated") {
      if (typeof params.uri !== "string" || !this.subscriptions.has(params.uri)) return "";
      out.params = { uri: params.uri };
      return line(out);
    }
    if (method === "notifications/message") {
      // A server log: free-form diagnostics nothing can be filtered on.
      const first = this.logEventPending;
      this.logEventPending = false;
      if (this.uninspected === "pass") {
        if (first) this.eventUninspectedLog(true);
        const p: Obj = {
          level: typeof params.level === "string" && LOG_LEVELS.has(params.level) ? params.level : "info",
        };
        for (const key of ["logger", "data"]) if (key in params) p[key] = params[key];
        out.params = p;
        return line(out);
      }
      if (first) this.eventUninspectedLog(false);
      return "";
    }
    this.deny("unknown", method, "server_notification_dropped");
    return "";
  }

  private eventUninspectedLog(passed: boolean): void {
    const marker = "notifications/message.params";
    this.emitter.emit({
      principal: this.principal(),
      purpose: "unknown",
      operation: "notifications/message",
      decision: passed ? "allow" : "deny",
      outcome: passed ? null : "blocked",
      reasonCode: passed ? "unfiltered_passthrough" : "server_log_withheld",
      blockedFields: passed ? [] : [`<withheld:${marker}>`],
      allowedFields: passed ? [`<unfiltered:${marker}>`] : null,
    });
  }

  private serverRequest(msg: Obj, method: string): string {
    const serverId = msg.id;
    const k = idKey(serverId);
    if (RELAYED_SERVER_REQUESTS.has(method) && k !== null) {
      const proxyId = "aegis-srv-" + randomHex(8); // (ii-c)
      this.serverRequests.set(proxyId, serverId);
      this.serverIds.set(k, proxyId);
      return line({ jsonrpc: "2.0", id: proxyId, method });
    }
    // sampling/createMessage, elicitation/create, tasks/*, anything else: never
    // relayed to the host; the server is told no.
    this.deny("unknown", method, "server_request_refused");
    this.toServer.push(errorReply(serverId, -32601, "Aegis: server-to-host request refused"));
    return "";
  }
}

interface ParsedArgs {
  policy: string;
  agentId: string;
  sessionId: string | null;
  auditPath: string | null;
  gateKind: "check-access" | "tool-call";
  owner: string | null;
  uninspected: "withhold" | "pass";
  allowDeclaredPurpose: boolean;
  toolRules: string | null;
  uncheckedArguments: "refuse" | "pass";
  interfacePins: string | null;
  interfaceCandidates: string | null;
  serverCmd: string[];
}

const USAGE = `usage: aegis-mcp-proxy --policy <aegis-policy v0 JSON> [options] -- <server command>

options:
  --policy <path>      aegis-policy v0 document (JSON), required
  --agent-id <id>      advisory principal id of the host agent (env AEGIS_AGENT_ID)
  --session-id <id>    session id stamped on canonical events (env AEGIS_SESSION_ID)
  --audit-path <path>  canonical event JSONL path (env AEGIS_CANONICAL_AUDIT_PATH)
  --gate <kind>        FULL-mode gate primitive: check-access | tool-call (env AEGIS_MCP_GATE)
  --owner <id>         principal.owner for the tool-call gate (env AEGIS_OWNER)
  --uninspected <mode> withhold (default) | pass: server output the field rule cannot
                       check is withheld, or relayed and named as unfiltered
  --allow-declared-purpose
                       honour arguments.purpose over the tools map (the host's
                       model then chooses the purpose; events say so)
  --tool-rules <path>  per-tool argument rules (JSON, aegis-mcp-relay's tools shape):
                       every argument leaf must be on the tool's arguments.allow;
                       a tool with no rule is refused
  --unchecked-arguments <mode>
                       refuse (default) | pass: a call whose tool has no rule is
                       refused, or forwarded and named unfiltered in the event
  --interface-pins <path>
                       approved interface metadata (JSON): an entry is relayed only
                       as pinned; without a pin it is withheld (a tool keeps its name)
  --interface-candidates <path>
                       where to write the server's unapproved entries for review (0600)
  --help               show this help
`;

// Flags that take a value. Anything else starting with "--" is rejected: the
// old positional parser silently consumed the NEXT flag as an unknown flag's
// value, so one typo could drop e.g. --audit-path without any warning — on
// the component whose whole job is auditable enforcement.
const VALUE_FLAGS = new Set([
  "--policy",
  "--agent-id",
  "--session-id",
  "--audit-path",
  "--gate",
  "--owner",
  "--uninspected",
  "--tool-rules",
  "--unchecked-arguments",
  "--interface-pins",
  "--interface-candidates",
]);
const BOOLEAN_FLAGS = new Set(["--allow-declared-purpose"]);

function parseArgs(argv: string[]): ParsedArgs {
  const sep = argv.indexOf("--");
  const flags = sep === -1 ? argv : argv.slice(0, sep);
  const serverCmd = sep === -1 ? [] : argv.slice(sep + 1);
  const opts: Record<string, string> = {};
  for (let i = 0; i < flags.length; i += 1) {
    const key = flags[i];
    if (BOOLEAN_FLAGS.has(key)) {
      opts[key.slice(2)] = "true";
      continue;
    }
    if (!VALUE_FLAGS.has(key)) {
      throw new Error(
        `aegis-mcp-proxy: unknown argument ${key}\n${USAGE}`,
      );
    }
    const value = flags[i + 1];
    if (value === undefined) {
      throw new Error(`aegis-mcp-proxy: ${key} requires a value\n${USAGE}`);
    }
    opts[key.slice(2)] = value;
    i += 1;
  }
  if (!opts.policy) {
    throw new Error("aegis-mcp-proxy: --policy <aegis-policy v0 JSON> is required");
  }
  if (serverCmd.length === 0) {
    throw new Error("aegis-mcp-proxy: a server command after `--` is required");
  }
  const gateKind = opts.gate || process.env.AEGIS_MCP_GATE || "check-access";
  if (gateKind !== "check-access" && gateKind !== "tool-call") {
    throw new Error(`aegis-mcp-proxy: unknown --gate ${gateKind} (check-access | tool-call)`);
  }
  const uninspected = opts.uninspected || "withhold";
  if (uninspected !== "withhold" && uninspected !== "pass") {
    throw new Error(`aegis-mcp-proxy: unknown --uninspected ${uninspected} (withhold | pass)`);
  }
  const uncheckedArguments = opts["unchecked-arguments"] || "refuse";
  if (uncheckedArguments !== "refuse" && uncheckedArguments !== "pass") {
    throw new Error(`aegis-mcp-proxy: unknown --unchecked-arguments ${uncheckedArguments} (refuse | pass)`);
  }
  return {
    policy: opts.policy,
    agentId: opts["agent-id"] || process.env.AEGIS_AGENT_ID || "mcp-host",
    sessionId: opts["session-id"] || process.env.AEGIS_SESSION_ID || null,
    auditPath: opts["audit-path"] || null,
    gateKind,
    owner: opts.owner || process.env.AEGIS_OWNER || null,
    uninspected,
    allowDeclaredPurpose: opts["allow-declared-purpose"] === "true",
    toolRules: opts["tool-rules"] || null,
    uncheckedArguments,
    interfacePins: opts["interface-pins"] || null,
    interfaceCandidates: opts["interface-candidates"] || null,
    serverCmd,
  };
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new ProxyConfigError(`cannot read ${path}: ${(e as Error).message}`, "aegis.mcp_proxy.proxy_config_unreadable");
  }
}

export async function main(argv: string[]): Promise<number> {
  const sepIdx = argv.indexOf("--");
  const flagPart = sepIdx === -1 ? argv : argv.slice(0, sepIdx);
  if (flagPart.includes("--help") || flagPart.includes("-h")) {
    process.stdout.write(USAGE);
    return 0;
  }
  const args = parseArgs(argv);
  const policy = loadCanonicalPolicy(args.policy);
  const emitter = new CanonicalEmitter(
    ENFORCEMENT_MCP_PROXY,
    PROXY_RUNTIME,
    args.auditPath,
    policy.policyId,
  );
  // FULL-mode gate: armed only on explicit intent (AEGIS_MODE=full, or
  // AEGIS_MODE=auto resolving FULL via the same detector shield uses).
  // Unset/lite keeps today's LITE-only proxy byte-for-byte.
  let gate: GatewayGate | null = null;
  const modeEnv = (process.env.AEGIS_MODE ?? "").trim().toLowerCase();
  if (modeEnv && modeEnv !== "lite") {
    const resolved = modeEnv === "full" ? "full" : await detectMode();
    if (resolved === "full") {
      gate = new GatewayGate(getModuleClient(), args.gateKind, args.owner ?? args.agentId);
      process.stderr.write(
        `aegis-mcp-proxy: FULL gate armed (${args.gateKind}) — gateway consulted `
          + "before every gated call (deny = tool never runs, fail-closed)\n",
      );
    }
  }
  const toolRules = args.toolRules ? validateToolRules(readJson(args.toolRules)) : {};
  const pins = args.interfacePins ? validateInterfacePins(readJson(args.interfacePins)) : null;
  const proxy = new ShieldProxy(policy, emitter, args.agentId, args.sessionId, gate, {
    uninspected: args.uninspected,
    allowDeclaredPurpose: args.allowDeclaredPurpose,
    toolRules,
    uncheckedArguments: args.uncheckedArguments,
    interfacePins: pins,
    candidatesPath: args.interfaceCandidates,
  });
  if (args.uncheckedArguments === "pass") {
    process.stderr.write(
      "aegis-mcp-proxy: --unchecked-arguments pass — a call whose tool has no rule is forwarded "
        + "and recorded as unfiltered\n",
    );
  }
  if (pins === null) {
    process.stderr.write(
      "aegis-mcp-proxy: no --interface-pins — the server's interface metadata is withheld until "
        + "approved (tools keep their names)\n",
    );
  }
  if (args.uninspected === "pass") {
    process.stderr.write(
      "aegis-mcp-proxy: --uninspected pass — output the field rule cannot check is relayed "
        + "and recorded as unfiltered\n",
    );
  }
  if (args.allowDeclaredPurpose) {
    process.stderr.write(
      "aegis-mcp-proxy: --allow-declared-purpose — arguments.purpose overrides the tools map "
        + "(the host's model chooses the purpose)\n",
    );
  }

  const server = spawn(args.serverCmd[0], args.serverCmd.slice(1), {
    stdio: ["pipe", "pipe", "inherit"],
  });
  // The proxy writes to the server from both directions (forwarded host lines,
  // refusals of server requests). A write after the server has gone (EPIPE) or
  // after the host closed its side must not crash the proxy.
  server.stdin.on("error", () => {});

  // host stdin -> proxy -> server stdin (or reply straight to host stdout).
  // Lines are handled SERIALLY (promise chain): the async FULL gate must not
  // reorder host traffic or interleave replies.
  const clientRl = createInterface({ input: process.stdin });
  let clientQueue: Promise<void> = Promise.resolve();
  clientRl.on("line", (line) => {
    if (!line.trim()) return;
    clientQueue = clientQueue.then(async () => {
      const { forward, reply } = await proxy.handleClientLine(line);
      if (reply !== undefined) process.stdout.write(reply);
      if (forward !== undefined) server.stdin.write(forward.endsWith("\n") ? forward : forward + "\n");
    });
  });
  clientRl.on("close", () => {
    void clientQueue.then(() => server.stdin.end());
  });

  // server stdout -> proxy -> host stdout
  const serverRl = createInterface({ input: server.stdout });
  serverRl.on("line", (line) => {
    if (!line.trim()) return;
    const relayed = proxy.handleServerLine(line);
    if (relayed) process.stdout.write(relayed);
    // Lines the proxy owes the server (a refused server request).
    for (const owed of proxy.drainToServer()) {
      if (!server.stdin.destroyed && !server.stdin.writableEnded) server.stdin.write(owed);
    }
  });

  server.on("exit", (code) => process.exit(code ?? 0));
  return 0;
}

// Run when invoked as the bin (aegis-mcp-proxy), not when imported. Robust
// real-path comparison (mirrors cli.ts) so symlinked bin invocations match.
function isMain(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMain()) {
  main(process.argv.slice(2)).catch((e) => {
    // Python-parity stderr contract: one line, `aegis-mcp-proxy: <message>
    // [<code>]` when the error carries a machine-parseable code — operators
    // grep the documented aegis.canonical.* codes on BOTH SDKs.
    const msg = String((e as Error).message ?? e);
    const prefixed = msg.startsWith("aegis-mcp-proxy:") ? msg : `aegis-mcp-proxy: ${msg}`;
    const code = (e as { code?: unknown }).code;
    const suffix = typeof code === "string" && code.startsWith("aegis.") ? ` [${code}]` : "";
    process.stderr.write(prefixed + suffix + "\n");
    process.exit(2);
  });
}
