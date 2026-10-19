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
// refused unless --allow-declared-purpose. Named limits: interface metadata
// (tool / resource / prompt descriptions, serverInfo, instructions) is relayed,
// and numbers or timing a server chooses are low-bandwidth channels.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
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

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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

  private deny(purpose: string, operation: string, reasonCode: string): void {
    this.emitter.emit({
      principal: this.principal(),
      purpose,
      operation,
      decision: "deny",
      outcome: "blocked",
      reasonCode,
      blockedFields: [],
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
    if (this.gate !== null) {
      const [allowed, reason] = await this.gate.check(operation, purpose);
      if (!allowed) {
        // FULL gate deny: the tool NEVER runs (pre-call, like @shield).
        this.deny(purpose.name, operation, reason);
        return { reply: this.blockReply(id, operation, reason) };
      }
    }
    const uri = method === "resources/read" && typeof params.uri === "string" ? params.uri : null;
    this.remember(id, { method, operation, purpose: purpose.name, uri, declaredOverride: override });
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
      return line({ jsonrpc: "2.0", id, result: projected });
    }
    if (request.method in LISTING_METHODS) {
      return line({ jsonrpc: "2.0", id, result: this.projectListing(request.method, result) });
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

  private projectListing(method: string, result: unknown): Obj {
    const key = LISTING_METHODS[method][0];
    const entries = isObj(result) ? result[key] : undefined;
    const projected: unknown[] = [];
    const out: Obj = { [key]: projected };
    if (!this.familyMapped(method) || !Array.isArray(entries)) return out;
    for (const entry of entries) {
      if (!isObj(entry)) continue;
      const p = this.projectEntry(method, entry);
      if (p !== null) projected.push(p);
    }
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
      const p: Obj = { progressToken: params.progressToken };
      for (const key of ["progress", "total"]) if (isNum(params[key])) p[key] = params[key];
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
  return {
    policy: opts.policy,
    agentId: opts["agent-id"] || process.env.AEGIS_AGENT_ID || "mcp-host",
    sessionId: opts["session-id"] || process.env.AEGIS_SESSION_ID || null,
    auditPath: opts["audit-path"] || null,
    gateKind,
    owner: opts.owner || process.env.AEGIS_OWNER || null,
    uninspected,
    allowDeclaredPurpose: opts["allow-declared-purpose"] === "true",
    serverCmd,
  };
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
  const proxy = new ShieldProxy(policy, emitter, args.agentId, args.sessionId, gate, {
    uninspected: args.uninspected,
    allowDeclaredPurpose: args.allowDeclaredPurpose,
  });
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
