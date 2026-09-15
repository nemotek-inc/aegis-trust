/**
 * INV-7, SDK form — the Node side of the irreversibility surface.
 *
 * Node ships no generated gateway client, so it has no operation set to
 * classify. That is the whole finding: the Python SDK carries POST
 * /capsules/{id}/destroy ("Irreversibly destroy a capsule") in its wheel and the
 * Node SDK carries nothing equivalent. With respect to INV-7 the two SDKs are
 * not the same product.
 *
 * A test that merely passed because there is nothing here would be vacuous, and
 * would go on passing after somebody added a destroy surface. So this asserts
 * the absence rather than assuming it: the Node source is scanned for an
 * irreversible surface, and the registry's declaration of the asymmetry is
 * checked against what the scan finds. If Node grows one, this fails and the
 * asymmetry entry has to be rewritten with the operation classified.
 *
 * Mirror: python/tests/test_irreversible_ops.py.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const SRC = join(HERE, "..", "src");

const registry = JSON.parse(
  readFileSync(join(REPO, "conformance", "irreversible_ops.v0.json"), "utf8"),
) as {
  version: number;
  irreversibility_marker: string;
  operations: Record<string, { class: string; url: string; summary: string }>;
  ungated_single_call: Record<string, { note: string }>;
  node_asymmetry: { state: string; consequence: string; enforced_by: string };
};

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

// URL paths that would reach an irreversible Core-side transition. Kept as
// paths rather than identifiers because that is what actually crosses the wire:
// a helper could be named anything and still POST to /destroy.
const IRREVERSIBLE_PATHS = [/\/capsules\/[^"'`]*\/destroy/, /\/destroy\b/, /\/wipe\b/];

describe("INV-7 SDK form — Node irreversibility surface", () => {
  it("scan is non-vacuous", () => {
    // Guard the guard: if the file walk breaks, this must fail rather than
    // report a clean absence.
    const files = tsFiles(SRC);
    expect(files.length, "no source files scanned — the walk is broken").toBeGreaterThan(10);
    expect(registry.version).toBe(0);
    expect(Object.keys(registry.operations).length).toBeGreaterThan(20);
  });

  it("Node source reaches no irreversible operation", () => {
    const offenders: string[] = [];
    for (const file of tsFiles(SRC)) {
      const text = readFileSync(file, "utf8");
      for (const pattern of IRREVERSIBLE_PATHS) {
        if (pattern.test(text)) offenders.push(`${file.slice(REPO.length + 1)} (${pattern})`);
      }
    }
    expect(
      offenders,
      `Node source now reaches an irreversible transition: ${offenders.join(", ")}. ` +
        "Classify it in irreversible_ops.v0.json and rewrite node_asymmetry — the " +
        "declared asymmetry is no longer true.",
    ).toEqual([]);
  });

  it("the declared asymmetry matches reality", () => {
    // The registry says Node has no such surface. The previous test establishes
    // that. This one stops the declaration going stale in the other direction:
    // if somebody empties the Python side, the asymmetry claim is wrong too.
    expect(registry.node_asymmetry.state).toContain("no generated gateway client");
    const pyIrreversible = Object.entries(registry.operations).filter(
      ([, op]) => op.class === "irreversible",
    );
    expect(
      pyIrreversible.length,
      "the asymmetry entry claims Python carries an irreversible surface that Python no longer has",
    ).toBeGreaterThan(0);
  });

  it("every ungated exposure carries a note", () => {
    // Bilateral read of the Python-side finding: a Node-only CI run must still
    // surface that an ungated irreversible call ships, rather than being blind
    // to it because the surface lives in the other language.
    expect(Object.keys(registry.ungated_single_call).length).toBeGreaterThan(0);
    for (const [name, entry] of Object.entries(registry.ungated_single_call)) {
      expect(entry.note, `${name}: ungated with no note`).toBeTruthy();
    }
  });

  it("authorization is not recorded as a gate", () => {
    // Recording a true fact must not close the hole in the guard's view.
    // `gated` is "entry has a truthy gate or confirmation_step", and `exposed`
    // subtracts it — so writing the server-side authorization (authenticated +
    // Role::Admin, 403 otherwise) into `gate` would move destroy_capsule out of
    // the exposed set, and INV-7 would look upheld without anything changing.
    //
    // INV-7 requires an explicit opt-in, not a role check: an Admin who
    // mistypes a capsule id still destroys it in one call.
    //
    // WHEN THIS FAILS: someone added a real opt-in or confirmation step. Good —
    // update this test to say which, rather than deleting it.
    const ungated = registry.ungated_single_call as Record<string, unknown>;
    const entry = ungated["destroy_capsule"] as Record<string, unknown>;
    expect(
      entry.server_side_authorization,
      "the measured authorization is no longer recorded",
    ).toBeTruthy();
    expect(
      entry.gate,
      "authorization was written into `gate`, which removes destroy_capsule from the exposed set",
    ).toBeFalsy();
    expect(entry.confirmation_step).toBeFalsy();

    const irreversible = Object.entries(registry.operations as Record<string, unknown>)
      .filter(([, op]) => (op as { class: string }).class === "irreversible")
      .map(([n]) => n);
    const gated = Object.entries(ungated)
      .filter(([, e]) => {
        const v = e as Record<string, unknown>;
        return Boolean(v.gate) || Boolean(v.confirmation_step);
      })
      .map(([n]) => n);
    expect(
      irreversible.includes("destroy_capsule") && !gated.includes("destroy_capsule"),
      "destroy_capsule is no longer an exposed irreversible single call. If it "
        + "was genuinely gated, move INV-7's sdk enforcement off 'none' too",
    ).toBe(true);
  });
});
