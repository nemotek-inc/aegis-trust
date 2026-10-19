import type { PathTree } from "./types.js";
import { flatKeyHitsDenyLeaf } from "./paths.js";

// Assign an OWN, enumerable data property even when `key` is "__proto__".
// Plain `obj["__proto__"] = v` invokes the inherited prototype SETTER instead
// of creating data: the explicitly-scoped "__proto__" field is silently
// dropped (diverging from Python, which keeps it as an ordinary key) AND hidden
// from the audit diff (under-reported removed key). defineProperty stores it as
// real, enumerable data with no prototype pollution, so Object.keys/entries and
// the diff all see it — parity with Python. S017 H8/H9.
function safeSet(
  obj: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  Object.defineProperty(obj, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

// ── Shape probes ──────────────────────────────────────────

export function isPlainObject(x: unknown): x is Record<string, unknown> {
  if (x === null || typeof x !== "object") return false;
  const proto = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}

// A "record-like" element carries named fields that a leaf scope cannot
// filter. Bare scope=["users"] over [{ssn:"x"}] would leak — drop fail-closed.
export function isRecordLike(x: unknown): boolean {
  if (x === null || x === undefined) return false;
  const t = typeof x;
  if (t === "string" || t === "number" || t === "boolean" || t === "bigint") {
    return false;
  }
  if (t !== "object") return false;
  if (Array.isArray(x)) return false;
  if (x instanceof Date) return false;
  if (x instanceof Map || x instanceof Set) return false;
  // Plain object OR class instance — both can carry named fields.
  return true;
}

// Non-string, non-Map iterable that may carry record-like elements.
export function isTraversable(x: unknown): boolean {
  if (x === null || x === undefined) return false;
  if (typeof x === "string") return false;
  if (x instanceof Map) return false;
  if (Array.isArray(x)) return true;
  if (x instanceof Set) return true;
  // Generic iterables (excluding strings) — materialize them.
  return typeof (x as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function"
    && typeof x === "object";
}

// Materialize iterable into Array for repeated traversal (filter + diff).
export function materialize(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (v instanceof Set) return Array.from(v);
  if (v && typeof v === "object" && Symbol.iterator in (v as object)) {
    return Array.from(v as Iterable<unknown>);
  }
  return [v];
}

// Recursively freeze single-pass iterables into materialized arrays so
// filter pass and audit diff see the same concrete structure.
export function freezeSinglePass(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  const t = typeof data;
  if (t === "string" || t === "number" || t === "boolean" || t === "bigint") {
    return data;
  }
  if (data instanceof Date) return data;
  if (isPlainObject(data)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(data)) {
      safeSet(out, k, freezeSinglePass(v));
    }
    return out;
  }
  if (Array.isArray(data)) {
    return data.map(freezeSinglePass);
  }
  if (data instanceof Set) {
    return new Set(Array.from(data, freezeSinglePass));
  }
  if (data instanceof Map) {
    return data;
  }
  // Class instance with named fields — atomic at this layer (record-like).
  if (isRecordLike(data)) return data;
  // Generic iterable (generator etc.) — materialize.
  if (
    typeof data === "object"
    && Symbol.iterator in (data as object)
  ) {
    return Array.from(data as Iterable<unknown>, freezeSinglePass);
  }
  return data;
}

// Normalize a class instance to a plain dict for filtering.
// Plain objects pass through. Class instances become { ...instance }.
export function toFilterable(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  if (isPlainObject(data) || Array.isArray(data)) return data;
  if (data instanceof Date) return data;
  if (data instanceof Map || data instanceof Set) return data;
  if (typeof data === "object") {
    // Class instance → copy own enumerable string-keyed props.
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(data as object)) {
      safeSet(out, k, (data as Record<string, unknown>)[k]);
    }
    return out;
  }
  return data;
}

// ── Scope filter (allow-list) ─────────────────────────────

const HOLDS_RECORD_MAX_DEPTH = 64;

// True when `v` is record-like (or a Map), or a collection holding one at ANY
// depth. A bare leaf over `[[{ ssn }]]` must drop the key exactly as over
// `[{ ssn }]`: checking only the immediate elements let a record nested one
// collection deeper through. Over-deep nesting answers true (fail-closed).
// Parity with python `_holds_record`.
export function holdsRecord(v: unknown, depth = 0): boolean {
  if (depth > HOLDS_RECORD_MAX_DEPTH) return true;
  if (isRecordLike(v) || v instanceof Map) return true;
  if (isTraversable(v)) return materialize(v).some((x) => holdsRecord(x, depth + 1));
  return false;
}

export function filterDict(
  data: Record<string, unknown>,
  pathTree: PathTree,
  warn: (msg: string) => void,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    // hasOwnProperty, not `k in pathTree`: a data key named `toString` /
    // `constructor` etc. must not match an inherited Object.prototype member
    // and pass the whitelist un-granted (fail-OPEN scope bypass). S015 P0.
    if (!Object.prototype.hasOwnProperty.call(pathTree, k)) continue;
    const subtree = pathTree[k]!;
    const isLeaf = Object.keys(subtree).length === 0;

    if (isLeaf) {
      // Leaf: keep scalars and collections-of-scalars as-is, but drop
      // fail-closed whenever the value carries named fields a bare leaf cannot
      // filter — a record-like value itself (object / class instance), a `Map`
      // (a key→value container shield's dot-notation cannot traverse, so it is
      // all-or-nothing — and "nothing" is the safe choice), OR a collection
      // containing record-like elements. A bare `scope=['config']` over
      // `{ api_key: ... }` (or `new Map([['api_key', ...]])`) would otherwise
      // disclose the entire subtree the caller never enumerated (the
      // doctor→shield fail-open class; parity with Python where a Mapping is
      // record-like). Minimum disclosure requires the explicit
      // `'<field>.<subfield>'` form.
      if (holdsRecord(v)) {
        warn(
          `shield: scope=['${k}'] over a record-like value (or a collection of `
            + `record-like elements) drops the key (fail-closed). Use `
            + `'${k}.<field>' to enumerate the permitted nested fields.`,
        );
        continue;
      }
      if (isTraversable(v)) {
        safeSet(result, k, materialize(v));
      } else {
        safeSet(result, k, v);
      }
    } else if (isPlainObject(v)) {
      safeSet(result, k, filterDict(v, subtree, warn));
    } else if (isTraversable(v)) {
      safeSet(result, k, materialize(v).map((item) => filterResult(item, subtree, warn)));
    } else {
      // subtree expects nested access but value is scalar — drop fail-closed.
      warn(
        `shield: scope expects nested path under '${k}' but value is ${typeOf(v)}, `
          + `dropping key (fail-closed)`,
      );
    }
  }
  return result;
}

function filterResult(
  data: unknown,
  pathTree: PathTree,
  warn: (msg: string) => void,
): unknown {
  const normalized = toFilterable(data);
  if (isPlainObject(normalized)) {
    return filterDict(normalized, pathTree, warn);
  }
  if (Array.isArray(normalized)) {
    return normalized.map((item) => filterResult(item, pathTree, warn));
  }
  // Scalars where nested expected: emit empty (fail-closed).
  return emptyFor(data);
}

// ── Deny filter (block-list) ──────────────────────────────

export function denyFilterDict(
  data: Record<string, unknown>,
  pathTree: PathTree,
  warn: (msg: string) => void,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    // hasOwnProperty, not `k in pathTree` (prototype-member parity with the
    // scope path above). S015 P0.
    if (!Object.prototype.hasOwnProperty.call(pathTree, k)) {
      // Flattened-key APIs: a literal "card.cvv" data key is denied by a nested
      // deny path "card.cvv" (S017 H1 fail-open fix).
      if (flatKeyHitsDenyLeaf(k, pathTree)) continue;
      safeSet(result, k, v);
      continue;
    }
    const subtree = pathTree[k]!;
    const isLeaf = Object.keys(subtree).length === 0;
    if (isLeaf) {
      // Drop key entirely.
      continue;
    }
    if (isPlainObject(v)) {
      safeSet(result, k, denyFilterDict(v, subtree, warn));
    } else if (isTraversable(v)) {
      safeSet(result, k, materialize(v).map((item) => denyFilterResult(item, subtree, warn)));
    } else {
      // Scalar where nested deny expected — drop fail-closed (S022 R2).
      warn(
        `shield: denyFields expects nested path under '${k}' but value is ${typeOf(v)}, `
          + `dropping key (fail-closed)`,
      );
    }
  }
  return result;
}

function denyFilterResult(
  data: unknown,
  pathTree: PathTree,
  warn: (msg: string) => void,
): unknown {
  const normalized = toFilterable(data);
  if (isPlainObject(normalized)) {
    return denyFilterDict(normalized, pathTree, warn);
  }
  if (Array.isArray(normalized)) {
    return normalized.map((item) => denyFilterResult(item, pathTree, warn));
  }
  // Scalar where a deny path was expected — fail-closed (parity with Python
  // `_deny_filter_result`, shield.py:700, which returns ""). A bare scalar
  // carries no named fields for the blacklist to act on; returning it raw
  // would leak the value under a deny that "matched nothing". S015 P0-2.
  return emptyFor(data);
}

// ── Helpers ───────────────────────────────────────────────

// T-SDK-FULL-GATE-01: exported so shield() FULL mode can return a type-shaped
// safe empty value when the pre-call /check-access authorization is not
// granted (deny / gateway-unreachable / 503), and on the internal-error
// fail-closed path. Mirrors the Python SDK's `_empty_for`.
export function emptyFor(data: unknown): unknown {
  if (typeof data === "string") return "";
  if (Array.isArray(data)) return [];
  if (isPlainObject(data)) return {};
  if (typeof data === "number") return 0;
  if (typeof data === "boolean") return false;
  return null;
}

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

// ── Diff for audit (blocked field paths) ──────────────────

export function diffKeys(original: unknown, filtered: unknown, prefix = ""): string[] {
  const out: string[] = [];
  const o = toFilterable(original);
  const f = toFilterable(filtered);

  if (isPlainObject(o)) {
    const fObj = isPlainObject(f) ? f : {};
    for (const [k, ov] of Object.entries(o)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (!Object.prototype.hasOwnProperty.call(fObj, k)) {
        out.push(path);
        continue;
      }
      const fv = fObj[k];
      if (isPlainObject(ov) || Array.isArray(ov)) {
        out.push(...diffKeys(ov, fv, path));
      }
    }
    return out;
  }

  if (Array.isArray(o) && Array.isArray(f)) {
    const n = Math.min(o.length, f.length);
    for (let i = 0; i < n; i++) {
      out.push(...diffKeys(o[i], f[i], prefix));
    }
    return Array.from(new Set(out));
  }

  return out;
}
