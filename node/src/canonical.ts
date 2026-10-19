// Canonical contract v0: policy loader + audit event emitter (parity with
// python/src/aegis_trust/canonical.py). One policy document, one audit event
// shape, three enforcement points. The proxy (mcpProxy.ts) is the mcp_proxy
// enforcement point; this module gives it policy resolution + minimization
// (reusing the corpus-verified `wrap()` filter, so filtering matches Python
// byte-for-byte) and canonical v0 event emission.

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { AegisConfigError, aegisDocsUrl } from "./errors.js";
import { wrap } from "./shield.js";

export const CANONICAL_POLICY_SCHEMA_VERSION = 0;
export const CANONICAL_AUDIT_SCHEMA_VERSION = 0;

export const ENFORCEMENT_SDK = "sdk";
export const ENFORCEMENT_MCP_PROXY = "mcp_proxy";
export const ENFORCEMENT_GATEWAY = "gateway";
const ENFORCEMENT_POINTS = new Set([
  ENFORCEMENT_SDK,
  ENFORCEMENT_MCP_PROXY,
  ENFORCEMENT_GATEWAY,
]);

export interface CanonicalPurpose {
  readonly name: string;
  readonly scope?: string[];
  readonly denyFields?: string[];
  readonly destinationsAllow?: string[];
  readonly destinationsDeny?: string[];
  readonly maxLevel?: string;
  readonly legalBasis?: string;
  readonly retentionDays?: number;
}

const MAX_LEVELS = new Set([
  "public",
  "operational",
  "pii",
  "financial",
  "confidential",
  "critical",
]);
const LEGAL_BASES = new Set([
  "consent",
  "contract",
  "legal_obligation",
  "vital_interests",
  "public_task",
  "legitimate_interests",
]);

export interface RoleRule {
  readonly allow_purposes?: string[];
  readonly deny_purposes?: string[];
}

function cfgErr(message: string, code: string): AegisConfigError {
  return new AegisConfigError({
    message,
    code,
    remediation:
      "Fix the canonical policy document; see schemas/v0/aegis-policy.v0.schema.json.",
    docs_url: aegisDocsUrl(code),
  });
}

// Dot-notation path validation (parity with shield._validate_field_path):
// no empty, no leading/trailing dot, no consecutive dots.
function validateFieldPath(path: string): void {
  if (!path) {
    throw cfgErr("Field path must not be empty.", "aegis.canonical.fieldPath.invalid");
  }
  if (path.startsWith(".") || path.endsWith(".") || path.includes("..")) {
    throw cfgErr(
      `Invalid field path '${path}': leading/trailing/consecutive dot.`,
      "aegis.canonical.fieldPath.invalid",
    );
  }
}

export class CanonicalPolicy {
  constructor(
    readonly policyId: string | null,
    readonly purposes: Record<string, CanonicalPurpose>,
    readonly tools: Record<string, string> = {},
    readonly roles: Record<string, RoleRule> = {},
  ) {}

  // Explicit declaration wins; else the tools map; else null (caller blocks).
  purposeForTool(toolName: string, declaredPurpose?: string): CanonicalPurpose | null {
    const name = declaredPurpose || this.tools[toolName];
    if (!name) return null;
    return this.purposes[name] ?? null;
  }

  // Role layer (advisory outside the gateway). Unknown role => allowed (the
  // purpose/tool layer above is always enforced). Parity with role_allows.
  roleAllows(role: string, purpose: string): boolean {
    const rule = this.roles[role];
    if (!rule) return true;
    if (rule.allow_purposes !== undefined) return rule.allow_purposes.includes(purpose);
    if (rule.deny_purposes !== undefined) return !rule.deny_purposes.includes(purpose);
    return true;
  }

  // Egress check (v0). Fail-closed: a purpose with no destinations block permits
  // no egress at all. Parity with CanonicalPurpose.destination_allowed.
  destinationAllowed(purpose: CanonicalPurpose, destination: string): boolean {
    if (purpose.destinationsAllow !== undefined)
      return purpose.destinationsAllow.includes(destination);
    if (purpose.destinationsDeny !== undefined)
      return !purpose.destinationsDeny.includes(destination);
    return false;
  }

  // Minimize `data` under the purpose's rule. Reuses wrap() (corpus-verified,
  // identical to the Python filter). Fail-closed on any error.
  filterPayload(
    purpose: CanonicalPurpose,
    data: unknown,
  ): { filtered: unknown; removed: string[] } {
    try {
      const r =
        purpose.scope !== undefined
          ? wrap(data, { purpose: purpose.name, scope: purpose.scope })
          : wrap(data, { purpose: purpose.name, denyFields: purpose.denyFields ?? [] });
      return { filtered: r.data, removed: [...r.filteredKeys] };
    } catch {
      return { filtered: "", removed: ["<fail_closed>"] };
    }
  }
}

function parsePurpose(name: string, raw: unknown): CanonicalPurpose {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw cfgErr(`Purpose '${name}' must be a mapping`, "aegis.canonical.purpose.notMapping");
  }
  const o = raw as Record<string, unknown>;
  const hasScope = "scope" in o;
  const hasDeny = "deny_fields" in o;
  if (hasScope && hasDeny) {
    throw cfgErr(
      `Purpose '${name}': scope and deny_fields are mutually exclusive`,
      "aegis.canonical.purpose.scopeDenyConflict",
    );
  }
  if (!hasScope && !hasDeny) {
    throw cfgErr(
      `Purpose '${name}': either scope or deny_fields is required`,
      "aegis.canonical.purpose.empty",
    );
  }
  for (const key of ["scope", "deny_fields"] as const) {
    const fields = o[key];
    if (fields === undefined) continue;
    if (!Array.isArray(fields) || fields.some((f) => typeof f !== "string")) {
      throw cfgErr(
        `Purpose '${name}': ${key} must be a list of strings`,
        "aegis.canonical.fields.notList",
      );
    }
    for (const f of fields) validateFieldPath(f as string);
  }
  if (hasDeny && (o.deny_fields as string[]).length === 0) {
    throw cfgErr(
      `Purpose '${name}': deny_fields must not be empty (hiding nothing)`,
      "aegis.canonical.denyFields.empty",
    );
  }
  const maxLevel = o.max_level;
  if (maxLevel !== undefined && (typeof maxLevel !== "string" || !MAX_LEVELS.has(maxLevel))) {
    throw cfgErr(`Purpose '${name}': invalid max_level '${String(maxLevel)}'`, "aegis.canonical.maxLevel.invalid");
  }
  const legalBasis = o.legal_basis;
  if (legalBasis !== undefined && (typeof legalBasis !== "string" || !LEGAL_BASES.has(legalBasis))) {
    throw cfgErr(`Purpose '${name}': invalid legal_basis '${String(legalBasis)}'`, "aegis.canonical.legalBasis.invalid");
  }
  const retentionDays = o.retention_days;
  if (retentionDays !== undefined && (typeof retentionDays !== "number" || !Number.isInteger(retentionDays) || retentionDays < 1)) {
    throw cfgErr(`Purpose '${name}': retention_days must be a positive integer`, "aegis.canonical.retentionDays.invalid");
  }
  const [destAllow, destDeny] = parseDestinations(name, o.destinations);
  return {
    name,
    scope: hasScope ? [...(o.scope as string[])] : undefined,
    denyFields: hasDeny ? [...(o.deny_fields as string[])] : undefined,
    destinationsAllow: destAllow,
    destinationsDeny: destDeny,
    maxLevel: typeof maxLevel === "string" ? maxLevel : undefined,
    legalBasis: typeof legalBasis === "string" ? legalBasis : undefined,
    retentionDays: typeof retentionDays === "number" ? retentionDays : undefined,
  };
}

// Egress destinations: exactly one of allow/deny; lists of non-empty strings;
// deny must not be empty. Parity with canonical.py _parse_destinations.
function parseDestinations(
  name: string,
  raw: unknown,
): [string[] | undefined, string[] | undefined] {
  if (raw === undefined || raw === null) return [undefined, undefined];
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw cfgErr(`Purpose '${name}': destinations must be a mapping`, "aegis.canonical.destinations.notMapping");
  }
  const d = raw as Record<string, unknown>;
  const allow = d.allow;
  const deny = d.deny;
  if ((allow === undefined) === (deny === undefined)) {
    throw cfgErr(
      `Purpose '${name}': destinations requires exactly one of allow/deny`,
      "aegis.canonical.destinations.allowDenyConflict",
    );
  }
  for (const [key, values] of [["allow", allow], ["deny", deny]] as const) {
    if (values === undefined) continue;
    if (!Array.isArray(values) || values.some((v) => typeof v !== "string" || !v)) {
      throw cfgErr(
        `Purpose '${name}': destinations.${key} must be a list of non-empty strings`,
        "aegis.canonical.destinations.notList",
      );
    }
  }
  if (Array.isArray(deny) && deny.length === 0) {
    throw cfgErr(`Purpose '${name}': destinations.deny must not be empty`, "aegis.canonical.destinations.denyEmpty");
  }
  return [
    allow === undefined ? undefined : [...(allow as string[])],
    deny === undefined ? undefined : [...(deny as string[])],
  ];
}

// Load + validate an aegis-policy v0 document (JSON or YAML). YAML support, like
// Python's optional pyyaml extra, is opt-in: it needs the `yaml` package
// installed (npm install yaml); absent it, a .yaml/.yml path raises an
// actionable error rather than silently failing — parity with canonical.py.
export function loadCanonicalPolicy(path: string): CanonicalPolicy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    // Coded envelope instead of a raw ENOENT (Python parity:
    // aegis.canonical.file.notFound) — a missing policy file is the most
    // common operator mistake at proxy startup, and automation greps the
    // documented code. Other I/O errors (perms, etc.) propagate raw.
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw cfgErr(
        `Canonical policy file not found: ${path}`,
        "aegis.canonical.file.notFound",
      );
    }
    throw e;
  }
  let raw: unknown;
  if (path.endsWith(".yaml") || path.endsWith(".yml")) {
    let YAML: { parse(s: string): unknown };
    try {
      YAML = createRequire(import.meta.url)("yaml") as { parse(s: string): unknown };
    } catch {
      throw cfgErr(
        "the 'yaml' package is required for YAML policy documents (npm install yaml)",
        "aegis.canonical.yamlMissing",
      );
    }
    raw = YAML.parse(text);
  } else {
    try {
      raw = JSON.parse(text);
    } catch {
      throw cfgErr("Canonical policy must be valid JSON", "aegis.canonical.topLevel.notJson");
    }
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw cfgErr("Canonical policy must be a mapping", "aegis.canonical.topLevel.notMapping");
  }
  const o = raw as Record<string, unknown>;

  if (o.policy_schema_version !== CANONICAL_POLICY_SCHEMA_VERSION) {
    throw cfgErr(
      `Unsupported policy_schema_version ${JSON.stringify(o.policy_schema_version)}; ` +
        `this reader supports ${CANONICAL_POLICY_SCHEMA_VERSION} only (fail-closed)`,
      "aegis.canonical.version.unsupported",
    );
  }

  const purposesRaw = o.purposes;
  if (
    typeof purposesRaw !== "object" ||
    purposesRaw === null ||
    Array.isArray(purposesRaw) ||
    Object.keys(purposesRaw).length === 0
  ) {
    throw cfgErr("'purposes' must be a non-empty mapping", "aegis.canonical.purposes.notMapping");
  }
  const purposes: Record<string, CanonicalPurpose> = {};
  for (const [name, rule] of Object.entries(purposesRaw as Record<string, unknown>)) {
    purposes[name] = parsePurpose(name, rule);
  }

  const toolsRaw = (o.tools ?? {}) as unknown;
  if (
    typeof toolsRaw !== "object" ||
    toolsRaw === null ||
    Array.isArray(toolsRaw) ||
    Object.entries(toolsRaw).some(([k, v]) => typeof k !== "string" || typeof v !== "string")
  ) {
    throw cfgErr("'tools' must map tool names to purpose names", "aegis.canonical.tools.notMapping");
  }
  for (const [tool, purposeName] of Object.entries(toolsRaw as Record<string, string>)) {
    if (!(purposeName in purposes)) {
      throw cfgErr(
        `Tool '${tool}' maps to undeclared purpose '${purposeName}'`,
        "aegis.canonical.tools.unknownPurpose",
      );
    }
  }

  const rolesRaw = (o.roles ?? {}) as unknown;
  const roles: Record<string, RoleRule> = {};
  if (typeof rolesRaw !== "object" || rolesRaw === null || Array.isArray(rolesRaw)) {
    throw cfgErr("'roles' must be a mapping", "aegis.canonical.roles.notMapping");
  }
  for (const [roleName, rule] of Object.entries(rolesRaw as Record<string, unknown>)) {
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
      throw cfgErr(`Role '${roleName}' must be a mapping`, "aegis.canonical.roles.notMapping");
    }
    const rr = rule as Record<string, unknown>;
    const allow = rr.allow_purposes;
    const deny = rr.deny_purposes;
    if ((allow === undefined) === (deny === undefined)) {
      throw cfgErr(
        `Role '${roleName}': exactly one of allow_purposes/deny_purposes required`,
        "aegis.canonical.roles.allowDenyConflict",
      );
    }
    if (Array.isArray(deny) && deny.length === 0) {
      throw cfgErr(`Role '${roleName}': deny_purposes must not be empty`, "aegis.canonical.roles.denyEmpty");
    }
    roles[roleName] = {
      allow_purposes: Array.isArray(allow) ? (allow as string[]) : undefined,
      deny_purposes: Array.isArray(deny) ? (deny as string[]) : undefined,
    };
  }

  const defaults = o.defaults;
  if (typeof defaults === "object" && defaults !== null && !Array.isArray(defaults)) {
    for (const [key, value] of Object.entries(defaults as Record<string, unknown>)) {
      if (
        ["unknown_purpose", "unknown_destination", "unknown_tool"].includes(key) &&
        value !== "block"
      ) {
        throw cfgErr(
          `defaults.${key} must be 'block' (v0 admits no permissive default)`,
          "aegis.canonical.defaults.notBlock",
        );
      }
    }
  }

  return new CanonicalPolicy(
    typeof o.policy_id === "string" ? o.policy_id : null,
    purposes,
    toolsRaw as Record<string, string>,
    roles,
  );
}

export interface EmitArgs {
  principal: Record<string, unknown>;
  purpose: string;
  operation: string;
  decision: string;
  blockedFields: string[];
  eventType?: string;
  scope?: string[] | null;
  denyFields?: string[] | null;
  allowedFields?: string[] | null;
  outcome?: string | null;
  reasonCode?: string | null;
  destination?: string | null;
  mode?: string | null;
  traceId?: string | null;
}

// Append-only JSONL writer for aegis-audit-event v0 (canonical snake_case keys,
// identical wire shape to the Python emitter). Never throws into the data path.
export class CanonicalEmitter {
  readonly path: string;

  constructor(
    readonly enforcementPoint: string,
    readonly enforcementRuntime: string,
    path: string | null = null,
    readonly policyId: string | null = null,
  ) {
    if (!ENFORCEMENT_POINTS.has(enforcementPoint)) {
      throw new Error(`enforcement_point must be one of ${[...ENFORCEMENT_POINTS].sort()}`);
    }
    const resolved = path || process.env.AEGIS_CANONICAL_AUDIT_PATH;
    this.path = resolved || join(homedir(), ".aegis", "canonical_events.jsonl");
  }

  buildEvent(a: EmitArgs): Record<string, unknown> {
    const eventType = a.eventType ?? "access";
    if (eventType === "egress" && !a.destination) {
      throw new Error("egress events require destination (v0 requirement)");
    }
    if (!a.principal.agent_id && !a.principal.auth_sub) {
      throw new Error("principal requires agent_id or auth_sub");
    }
    const principal: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(a.principal)) if (v != null) principal[k] = v;
    const event: Record<string, unknown> = {
      audit_schema_version: CANONICAL_AUDIT_SCHEMA_VERSION,
      timestamp: new Date().toISOString(),
      enforcement_point: this.enforcementPoint,
      enforcement_runtime: this.enforcementRuntime,
      event_type: eventType,
      principal,
      purpose: a.purpose,
      operation: a.operation,
      decision: a.decision,
      blocked_fields: [...a.blockedFields],
    };
    const optional: Record<string, unknown> = {
      scope: a.scope,
      deny_fields: a.denyFields,
      allowed_fields: a.allowedFields,
      outcome: a.outcome,
      reason_code: a.reasonCode,
      destination: a.destination,
      policy_id: this.policyId,
      mode: a.mode,
      trace_id: a.traceId,
    };
    for (const [k, v] of Object.entries(optional)) if (v != null) event[k] = v;
    return event;
  }

  emit(a: EmitArgs): Record<string, unknown> | null {
    const event = this.buildEvent(a);
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      appendFileSync(this.path, JSON.stringify(event) + "\n", "utf8");
    } catch {
      return null;
    }
    return event;
  }
}
