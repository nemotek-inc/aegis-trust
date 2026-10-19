/**
 * Conformance runner hygiene — the guard on the guards (Node).
 *
 * A shared corpus only delivers cross-language identity if both implementations
 * feed it to code that actually ships. A runner that re-derives the behaviour
 * inline and checks its own reconstruction is tautological: it proves only that
 * the primitive it reimplemented is deterministic, it stays green while the
 * shipped code drifts underneath it, and it reads as coverage in every report.
 *
 * This SDK shipped exactly that. The byte anchor for the canonical idempotency
 * digest rebuilt the canonical form with JSON.stringify, hashed its own
 * reconstruction with createHash, and never called the shipped payloadHash.
 *
 * Cross-review history (2026-07-19, cursor + agy). The first version of this
 * guard had three holes, all found independently by both models:
 *   - it checked IMPORT, not USE. A runner could import the shipped symbol,
 *     never call it, and assert a hard-coded digest. Green, and the exact
 *     tautology the guard exists to stop.
 *   - it read `el.name.text`, the LOCAL binding, so `import { _payloadHash as h }`
 *     produced `::h` and silently failed to match. envSurfaceHygieneS024.test.ts
 *     already did this correctly via `propertyName`; this file did not follow it.
 *   - it banned static `import "node:crypto"` only, which `require()` and
 *     `await import()` walk straight past.
 * All three are closed below.
 *
 * Implemented on the TypeScript compiler AST, like the S024 env-surface guards:
 * comments, string contents and regex literals are tokenised by the parser, so
 * none of them can satisfy or evade the check.
 *
 * Mirror: python/tests/test_conformance_runner_hygiene.py.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const CONFORMANCE = join(REPO, "conformance");

interface RunnerSpec {
  path: string;
  must_import: { module: string; symbol: string };
}
interface CorpusEntry {
  corpus: string;
  exercises: string;
  runners: { python: RunnerSpec; node: RunnerSpec };
}

const registry = JSON.parse(
  readFileSync(join(CONFORMANCE, "runners.v0.json"), "utf8"),
) as {
  version: number;
  corpora: CorpusEntry[];
  forbidden_imports: { node: string[] };
  forbidden_dynamic_import: { node: string[] };
  not_corpora: string[];
  not_corpora_reasons: Record<string, string>;
};

const invariants = JSON.parse(
  readFileSync(join(CONFORMANCE, "invariants.v0.json"), "utf8"),
) as {
  enforcement_values: Record<string, string>;
  invariants: Array<{
    id: string;
    enforcement: Record<string, string>;
    customer_facing: boolean;
    evidence: Array<{ file: string; registered?: boolean }>;
    not_applicable_reason?: Record<string, string>;
  }>;
};

// Criterion 3 of enforcement_full_criteria needs the backend matrix. Loading it
// here (rather than only Python-side) keeps the two languages symmetric: a
// check that lives in one runtime leaves the other CI blind to the same drift,
// which is the asymmetry this suite exists to refuse.
const backends = JSON.parse(
  readFileSync(join(CONFORMANCE, "backends.v0.json"), "utf8"),
) as {
  coverage: Record<string, Record<string, { state: string }>>;
};

/** Every runner path declared in runners.v0.json, both languages. */
const registeredRunnerPaths = new Set(
  registry.corpora.flatMap((c) => Object.values(c.runners).map((r) => r.path)),
);

const FORBIDDEN = new Set(registry.forbidden_imports.node);
const DYNAMIC = new Set(registry.forbidden_dynamic_import.node);
const NOT_CORPORA = new Set(registry.not_corpora);

function parse(absPath: string): ts.SourceFile {
  return ts.createSourceFile(
    absPath,
    readFileSync(absPath, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
}

function walk(node: ts.Node, fn: (n: ts.Node) => void): void {
  fn(node);
  ts.forEachChild(node, (child) => walk(child, fn));
}

/**
 * The LOCAL binding a named export was imported under, honouring renames.
 * `import { a as b }` gives propertyName=a, name=b — we key on propertyName
 * (what the module exports) and return name (what the file calls it).
 */
function localNameFor(
  src: ts.SourceFile,
  module: string,
  symbol: string,
): string | null {
  let found: string | null = null;
  walk(src, (node) => {
    if (found !== null) return;
    if (!ts.isImportDeclaration(node)) return;
    const spec = node.moduleSpecifier;
    if (!ts.isStringLiteral(spec) || spec.text !== module) return;
    const named = node.importClause?.namedBindings;
    if (named && ts.isNamedImports(named)) {
      for (const el of named.elements) {
        const exported = (el.propertyName ?? el.name).text;
        if (exported === symbol) found = el.name.text;
      }
    }
  });
  return found;
}

/** Identifiers appearing in call position, e.g. `f(x)` or `obj.f(x)`. */
function calledNames(src: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  walk(src, (node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee)) out.add(callee.text);
      else if (ts.isPropertyAccessExpression(callee)) out.add(callee.name.text);
    }
    // `new ShieldProxy(...)` runs the shipped class's constructor: a call of the
    // symbol as much as `f(...)` is (the mcp_relay runner reaches it this way).
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      out.add(node.expression.text);
    }
    // `await import("x")` parses as a CallExpression with an ImportKeyword head.
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      out.add("import");
    }
  });
  return out;
}

function staticImportModules(src: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  walk(src, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      out.add(node.moduleSpecifier.text);
    }
  });
  return out;
}

function stringLiterals(src: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  walk(src, (node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      out.add(node.text);
    }
  });
  return out;
}

describe("conformance runner hygiene", () => {
  it("scan is non-vacuous", () => {
    expect(registry.version).toBe(0);
    expect(registry.corpora.length).toBeGreaterThan(0);
    expect(invariants.invariants.length).toBeGreaterThan(0);
  });

  it("every corpus on disk has a registry entry", () => {
    // Node checks this too now. Previously only Python did, so a corpus added
    // without a Node runner would have left this suite green. (cross-review)
    const onDisk = readdirSync(CONFORMANCE)
      .filter((f) => f.endsWith(".json"))
      .filter((f) => !NOT_CORPORA.has(f));
    const declared = new Set(registry.corpora.map((e) => e.corpus));
    const missing = onDisk.filter((f) => !declared.has(f));
    expect(missing, `corpora with no runner entry: ${missing.join(", ")}`).toEqual(
      [],
    );
  });

  it("not_corpora entries are justified", () => {
    // An undocumented exemption list is where a suite quietly stops meaning
    // anything: drop the awkward corpus in and it stops needing runners.
    for (const name of NOT_CORPORA) {
      const reason = registry.not_corpora_reasons[name];
      expect(reason, `${name}: exemption with no stated reason`).toBeTruthy();
      expect(reason!.length).toBeGreaterThan(20);
    }
  });

  for (const entry of registry.corpora) {
    const spec = entry.runners.node;
    const abs = join(REPO, spec.path);

    it(`${entry.corpus}: both runner files exist`, () => {
      // Each language checks BOTH paths, so deleting the Python runner cannot
      // leave Node CI green and vice versa. (cross-review, agy)
      for (const lang of ["python", "node"] as const) {
        const p = join(REPO, entry.runners[lang].path);
        expect(existsSync(p), `${lang} runner missing at ${p}`).toBe(true);
      }
    });

    it(`${entry.corpus}: runner calls the shipped symbol`, () => {
      // Import is not use. A runner could import the symbol, never call it, and
      // assert a hard-coded expectation — green, and the exact tautology this
      // guard exists to stop. Rename-aware: keys on the exported name.
      const src = parse(abs);
      const local = localNameFor(src, spec.must_import.module, spec.must_import.symbol);
      expect(
        local,
        `${spec.path} does not import ${spec.must_import.symbol} from ${spec.must_import.module}`,
      ).not.toBeNull();
      expect(
        [...calledNames(src)],
        `${spec.path} imports ${spec.must_import.symbol} but never calls it`,
      ).toContain(local!);
    });

    it(`${entry.corpus}: runner reads the corpus it is registered against`, () => {
      // Otherwise a runner can read some other fixture and still satisfy every
      // import check, making the registry's claim decorative. (cross-review)
      // Substring, not equality: runners name the corpus inside a path literal
      // ("../../conformance/<corpus>"), so an exact match would reject the
      // correct code.
      const names = [...stringLiterals(parse(abs))].filter((s) =>
        s.includes(entry.corpus),
      );
      expect(
        names.length,
        `${spec.path} never names ${entry.corpus}; the registry's claim that this runner exercises it was unchecked`,
      ).toBeGreaterThan(0);
    });

    it(`${entry.corpus}: runner cannot re-derive the behaviour`, () => {
      // Static crypto imports AND the dynamic-import machinery that would
      // smuggle them in are both refused.
      //
      // Honest residual, unchanged: a hand-rolled SHA-256 or an unlisted
      // third-party digest package still gets through. This removes the
      // accidental path and raises the cost; it does not make re-derivation
      // impossible. Nor would it have caught the ORIGINAL anchor, which lived
      // outside the registry. It closes the recurrence path for registered
      // runners. A repo-wide crypto ban was rejected: it would reject the
      // SHA-3 known-answer vectors, which must compute a digest independently.
      const src = parse(abs);
      const staticOffenders = [...staticImportModules(src)].filter((m) =>
        FORBIDDEN.has(m),
      );
      expect(staticOffenders, `${spec.path} imports ${staticOffenders}`).toEqual([]);

      const dynamicOffenders = [...calledNames(src)].filter((n) => DYNAMIC.has(n));
      expect(
        dynamicOffenders,
        `${spec.path} uses ${dynamicOffenders} — dynamic import is how a banned primitive gets in without appearing in the import list`,
      ).toEqual([]);
    });
  }
});

describe("invariant declaration cannot drift", () => {
  it("customer_facing is derived, never hand-set", () => {
    // invariants.v0.json declares this property "machine-checked". Nothing in
    // the repo enforced it, so `customer_facing: true` could be hand-edited
    // onto an unenforced invariant and reach a customer. Declaring a guarantee
    // while shipping no mechanism for it is the same failure the whole suite
    // exists to remove — one level further up. (cross-review, both models P1)
    for (const inv of invariants.invariants) {
      const applicable = Object.values(inv.enforcement).filter(
        (v) => v !== "not_applicable",
      );
      const expected =
        applicable.length > 0 && applicable.every((v) => v === "full");
      expect(
        inv.customer_facing,
        `${inv.id}: enforcement ${JSON.stringify(inv.enforcement)} derives ${expected}`,
      ).toBe(expected);
    }
  });

  it("enforcement values come from the declared vocabulary", () => {
    const allowed = new Set(Object.keys(invariants.enforcement_values));
    for (const inv of invariants.invariants) {
      for (const [side, value] of Object.entries(inv.enforcement)) {
        expect(allowed.has(value), `${inv.id}.${side}: unknown ${value}`).toBe(true);
      }
    }
  });

  it("not_applicable sides are justified", () => {
    for (const inv of invariants.invariants) {
      for (const [side, value] of Object.entries(inv.enforcement)) {
        if (value !== "not_applicable") continue;
        expect(
          inv.not_applicable_reason?.[side],
          `${inv.id}.${side}: unjustified exemption`,
        ).toBeTruthy();
      }
    }
  });

  it("attached evidence paths exist", () => {
    for (const inv of invariants.invariants) {
      for (const item of inv.evidence) {
        expect(existsSync(join(REPO, item.file)), `${inv.id}: ${item.file}`).toBe(
          true,
        );
      }
    }
  });

  it("full enforcement requires evidence", () => {
    for (const inv of invariants.invariants) {
      if (Object.values(inv.enforcement).some((v) => v === "full")) {
        expect(inv.evidence.length, `${inv.id}: 'full' with no evidence`).toBeGreaterThan(0);
      }
    }
  });

  // `enforcement_full_criteria` declares THREE criteria and says all three must
  // hold, because `customer_facing` derives from `full` — a criterion that is
  // written but not enforced becomes a loose promise in a sales conversation.
  // Only criterion 1 was mechanised. Cross-review (codex + cursor, 2026-07-29)
  // found the gap and the exact inflation path: mark the other side
  // `not_applicable`, set this side `full`, and `customer_facing` follows.
  it("evidence `registered` flag is not self-declared (criterion 2, precondition)", () => {
    for (const inv of invariants.invariants) {
      for (const item of inv.evidence) {
        if (!item.registered) continue;
        expect(
          registeredRunnerPaths.has(item.file),
          `${inv.id}: evidence ${item.file} claims registered=true but is not a `
            + `runner in runners.v0.json — the flag cannot be its own proof`,
        ).toBe(true);
      }
    }
  });

  it("full enforcement requires registered evidence (criterion 2)", () => {
    for (const inv of invariants.invariants) {
      if (!Object.values(inv.enforcement).some((v) => v === "full")) continue;
      for (const item of inv.evidence) {
        expect(
          registeredRunnerPaths.has(item.file),
          `${inv.id}: 'full' but evidence ${item.file} is not registered in `
            + `runners.v0.json — an unregistered test may be checking its own `
            + `reconstruction, which is how the digest anchor stayed green`,
        ).toBe(true);
      }
    }
  });

  it("full enforcement requires complete backend coverage (criterion 3)", () => {
    for (const inv of invariants.invariants) {
      if (!Object.values(inv.enforcement).some((v) => v === "full")) continue;
      const weak = Object.entries(backends.coverage)
        .filter(([, cells]) => cells[inv.id] && cells[inv.id].state !== "full")
        .map(([surface, cells]) => `${surface}=${cells[inv.id].state}`);
      expect(
        weak,
        `${inv.id}: 'full' but the backend registry still reports non-full cells`,
      ).toEqual([]);
    }
  });

  it("the criteria gates are not vacuous", () => {
    // Nothing is `full` today (by design — the registry is incomplete), so the
    // three tests above iterate an empty set and pass by examining nothing.
    // That is the exact failure mode this file exists to stop, so exercise the
    // predicates directly against inputs that must be rejected.
    expect(registeredRunnerPaths.size).toBeGreaterThan(0);
    const unregistered = "node/tests/definitelyNotARegisteredRunner.test.ts";
    expect(registeredRunnerPaths.has(unregistered)).toBe(false);

    const cells: Record<string, { state: string }> = { "INV-FAKE": { state: "partial" } };
    const weak = Object.entries(cells).filter(([, c]) => c.state !== "full");
    expect(weak.length).toBeGreaterThan(0);
  });
});
