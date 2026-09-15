#!/usr/bin/env node
// aegis CLI — local history inspection and Core attestation verification.
//
// Usage:
//   aegis history [--limit N] [--purpose P]
//   aegis stats
//   aegis attest-verify [ATTESTATION] --expect-key HEX --expect-host FP [...]

import { appendFileSync, existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EXIT_ABNORMAL,
  EXIT_CLEAN,
  EXIT_NO_REPORT,
  advanceState,
  loadState,
  reportArrivedCheck,
  saveState,
  verifyAttestation,
  type AttestCheck,
  type AttestState,
} from "./attestVerify.js";
import { HistoryStore } from "./history.js";
import { shield } from "./shield.js";

function getDbPath(): string {
  return process.env.AEGIS_HISTORY_PATH
    ?? join(homedir(), ".aegis", "history.jsonl");
}

function openStore(): HistoryStore | null {
  const dbPath = getDbPath();
  if (!existsSync(dbPath)) {
    console.log(`No history database found at ${dbPath}`);
    console.log("Enable history with: AEGIS_HISTORY=1");
    return null;
  }
  return new HistoryStore(dbPath);
}

function pad(s: string, n: number, right = false): string {
  // Pad only, never truncate (Python `f"{x:<n}"` parity): a truncated
  // Blocked column made blocked fields disappear from the audit view,
  // which reads as "this field was disclosed" — the opposite of the truth.
  if (s.length >= n) return s;
  const fill = " ".repeat(n - s.length);
  return right ? fill + s : s + fill;
}

function cmdHistory(args: { limit: number; purpose?: string }): number {
  const store = openStore();
  if (!store) return 1;
  const records = store.getHistory({ limit: args.limit, purpose: args.purpose });
  store.close();

  if (records.length === 0) {
    console.log("No history records found.");
    return 0;
  }

  console.log(
    `${pad("ID", 5, true)}  ${pad("Function", 25)} ${pad("Purpose", 15)} `
      + `${pad("Blocked", 30)} ${pad("Timestamp", 25)}`,
  );
  console.log("-".repeat(105));

  for (const r of records) {
    const blocked = r.blockedFields.length > 0 ? r.blockedFields.join(", ") : "-";
    const ts = r.timestamp.length > 19 ? r.timestamp.slice(0, 19) : r.timestamp;
    console.log(
      `${pad(String(r.id), 5, true)}  ${pad(r.function, 25)} `
        + `${pad(r.purpose, 15)} ${pad(blocked, 30)} ${pad(ts, 25)}`,
    );
  }

  console.log(`\n${records.length} record(s) shown.`);
  return 0;
}

function cmdSandbox(): number {
  // Run the 10-second aegis-trust sandbox demo (dummy data, no infra):
  //   npm install aegis-trust && npx aegis sandbox
  // Node-only command: the Python `aegis` CLI has no sandbox subcommand
  // (it offers history/stats only) — do not claim a mirror that isn't there.

  const dummyUser: Record<string, unknown> = {
    user_id: "u_123",
    name: "Aria Sato",
    email: "aria@example.com",
    phone: "+81-80-1111-2222",
    ssn: "234-56-7890",
    credit_card: "5555-****-****-4242",
    plan: "pro",
    last_login: "2026-05-15T08:23:00Z",
    internal_notes: "VIP, do not contact about renewals",
  };

  const getUser = shield({
    purpose: "customer_support",
    scope: ["user_id", "plan", "last_login"],
  })((..._args: unknown[]) => dummyUser);

  console.log("Aegis sandbox demo");
  console.log("─".repeat(60));
  console.log();
  console.log("1. Source record:");
  for (const k of Object.keys(dummyUser).sort()) {
    console.log(`     ${k}: ${dummyUser[k]}`);
  }
  console.log();
  console.log("2. Agent request:");
  console.log('     getUser("u_123")   under purpose="customer_support"');
  console.log();

  const result = getUser("u_123") as Record<string, unknown>;
  const blocked = Object.keys(dummyUser).filter((k) => !(k in result)).sort();
  const auditPath = process.env.AEGIS_SANDBOX_AUDIT
    ?? resolve(process.cwd(), "aegis-sandbox-audit.jsonl");
  const entry = {
    timestamp: new Date().toISOString(),
    agent: "support_agent",
    purpose: "customer_support",
    requested_id: "u_123",
    allowed_fields: Object.keys(result).sort(),
    blocked_fields: blocked,
    decision: "filtered",
    reason: "fields outside declared scope",
  };
  appendFileSync(auditPath, JSON.stringify(entry) + "\n");

  console.log("3. Aegis decision:");
  console.log("     ┌────────────────────────────────────────────────────────┐");
  console.log("     │ Agent:        support_agent");
  console.log("     │ Purpose:      customer_support");
  console.log(`     │ Requested:    ${Object.keys(dummyUser).sort().join(", ")}`);
  console.log(`     │ ✓ Allowed:    ${Object.keys(result).sort().join(", ")}`);
  console.log(`     │ ✗ Blocked:    ${blocked.join(", ")}`);
  console.log("     │ Decision:     filtered");
  console.log(`     │ Audit:        ${auditPath}`);
  console.log("     └────────────────────────────────────────────────────────┘");
  console.log();
  console.log("4. What the agent actually sees:");
  console.log(`     ${JSON.stringify(result, null, 2).split("\n").join("\n     ")}`);
  console.log();
  console.log("5. Use in your own code:");
  console.log('     import { shield } from "aegis-trust";');
  console.log("     const fn = shield({ purpose: \"...\", scope: [\"a\", \"b\"] })(yourTool);");
  console.log();
  console.log(`To delete sandbox artifacts:  rm ${auditPath}`);
  return 0;
}

function cmdStats(): number {
  const store = openStore();
  if (!store) return 1;
  const stats = store.getStats();
  store.close();

  if (stats.totalCalls === 0) {
    console.log("No history records found.");
    return 0;
  }

  console.log(`Total calls: ${stats.totalCalls}`);
  console.log(`Total blocked fields: ${stats.totalBlockedFields}`);

  const purposes = Object.entries(stats.byPurpose);
  if (purposes.length > 0) {
    console.log(`\n${pad("Purpose", 20)} ${pad("Calls", 8, true)} ${pad("Blocked", 8, true)}`);
    console.log("-".repeat(40));
    purposes.sort(([a], [b]) => a.localeCompare(b));
    for (const [purpose, data] of purposes) {
      console.log(
        `${pad(purpose, 20)} ${pad(String(data.calls), 8, true)} ${pad(String(data.blocked), 8, true)}`,
      );
    }
  }

  const fields = Object.entries(stats.byField);
  if (fields.length > 0) {
    console.log(`\n${pad("Field", 30)} ${pad("Blocked Count", 15, true)}`);
    console.log("-".repeat(48));
    fields.sort((a, b) => b[1] - a[1]);
    for (const [field, count] of fields) {
      console.log(`${pad(field, 30)} ${pad(String(count), 15, true)}`);
    }
  }

  return 0;
}

interface AttestArgs {
  attestation: string | null;
  expectKey: string | null;
  expectHost: string | null;
  keyId: string | null;
  nonce: string | null;
  allowUnchallenged: boolean;
  maxAge: number;
  maxSkew: number;
  state: string | null;
  expectCapsules: string | null;
  requirePrevious: boolean;
  acceptLedgerReset: boolean;
  reportWithin: number | null;
  grace: number;
  json: boolean;
}

/**
 * Read the attestation document, or say why there is none.
 *
 * A null document is the exit-2 condition of contract section 5 — no report
 * could be obtained — which is deliberately not the same answer as a report was
 * obtained and it is abnormal. Bytes that are not JSON at all land here too: a
 * report that is not a document is indistinguishable from an invocation that
 * failed, and calling that an anomaly would page the deployment's owner about a
 * broken pipe.
 */
function readAttestationSource(
  source: string,
): { document: Record<string, unknown> | null; problem: string } {
  let raw: string;
  try {
    raw = source === "-" ? readFileSync(0, "utf8") : readFileSync(source, "utf8");
  } catch (err) {
    return { document: null, problem: `could not read ${source}: ${String(err)}` };
  }
  if (raw.trim() === "") {
    return { document: null, problem: `no attestation on ${source} (empty input)` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { document: null, problem: `${source} is not JSON: ${String(err)}` };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    // A JSON scalar or array is not a failed report; it IS a document making a
    // claim, so it goes to the verifier and comes back as an anomaly.
    return { document: { __not_an_object__: parsed }, problem: "" };
  }
  return { document: parsed as Record<string, unknown>, problem: "" };
}

/** One capsule id per line; blank lines and `#` comments ignored. */
function readExpectedCapsules(path: string): string[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function printChecks(checks: AttestCheck[]): void {
  for (const c of checks) {
    console.log(`  ${pad(c.outcome.toUpperCase(), 4)} ${pad(c.check, 18)} ${c.detail}`);
  }
}

/**
 * Verify a Core attestation (S051 ③).
 *
 * Exit codes are the verdict (contract section 5): 0 clean, 1 abnormal, 2 no
 * report could be obtained. 2 is deliberately distinct — "I could not report"
 * is not "I found problems", and collapsing them means a broken invocation
 * pages the same person as a broken deployment.
 *
 * Mirror: python/src/aegis_trust/cli.py cmd_attest_verify.
 */
function cmdAttestVerify(args: AttestArgs): number {
  if (args.expectKey === null || args.expectHost === null) {
    // Python's argparse exits 2 for a missing required argument; the same
    // number happens to be "no report", and both are true here.
    console.error("attest-verify: --expect-key and --expect-host are required");
    return EXIT_NO_REPORT;
  }

  let previous: AttestState | null;
  try {
    previous = args.state === null ? null : loadState(args.state);
  } catch (err) {
    // Not exit 2. A state file that exists and cannot be read is refused rather
    // than treated as a fresh start, because the degradation IS the bypass:
    // corrupt the file and the silence check skips every run while the report
    // stays green. Clearing it has to be a deliberate act.
    console.error(`[ANOMALY] ${err instanceof Error ? err.message : String(err)}`);
    return EXIT_ABNORMAL;
  }

  let timer: AttestCheck | null = null;
  if (args.reportWithin !== null) {
    timer = reportArrivedCheck(previous, {
      intervalSeconds: args.reportWithin,
      graceSeconds: args.grace,
    });
  }

  if (args.attestation === null) {
    if (timer === null) {
      console.error(
        "attest-verify: pass an attestation (a path, or - for stdin), or "
          + "--report-within SECONDS to check only whether one arrived",
      );
      return EXIT_NO_REPORT;
    }
    // Timer-only mode: nothing was fetched from Core, and that is the point.
    if (args.json) {
      console.log(
        JSON.stringify({ checks: [timer], ok: timer.outcome !== "fail" }, null, 2),
      );
    } else {
      printChecks([timer]);
    }
    return timer.outcome === "fail" ? EXIT_ABNORMAL : EXIT_CLEAN;
  }

  const { document, problem } = readAttestationSource(args.attestation);
  if (document === null) {
    console.error(`[ERROR] attestation could not be obtained: ${problem}`);
    return EXIT_NO_REPORT;
  }

  const verdict = verifyAttestation(
    document,
    {
      publicKeyHex: args.expectKey,
      hostFingerprint: args.expectHost,
      nonce: args.nonce,
      allowUnchallenged: args.allowUnchallenged,
      keyId: args.keyId,
      maxAgeSeconds: args.maxAge,
      maxClockSkewSeconds: args.maxSkew,
      capsuleIds:
        args.expectCapsules === null ? null : readExpectedCapsules(args.expectCapsules),
      requirePrevious: args.requirePrevious,
    },
    previous,
  );
  const checks = timer ? [...verdict.checks, timer] : [...verdict.checks];
  const failed = checks.filter((c) => c.outcome === "fail");

  if (args.json) {
    console.log(
      JSON.stringify(
        {
          ok: failed.length === 0,
          exit_code: failed.length === 0 ? EXIT_CLEAN : EXIT_ABNORMAL,
          signature_verified: verdict.signatureVerified,
          checks,
          findings: failed,
          skipped: checks.filter((c) => c.outcome === "skip"),
        },
        null,
        2,
      ),
    );
  } else {
    printChecks(checks);
    if (failed.length > 0) {
      console.log(`[ANOMALY] ${failed.length} check(s) failed`);
    } else {
      console.log("[OK] attestation verified");
      const skipped = checks.filter((c) => c.outcome === "skip");
      if (skipped.length > 0) {
        // Never folded into the green: a check that did not run is not a check
        // that passed.
        console.log(
          `      ${skipped.length} check(s) could not run: `
            + skipped.map((c) => c.check).join(", "),
        );
      }
    }
  }

  if (args.state !== null) {
    // Only ever forward. See advanceState: a genuinely signed OLD attestation
    // would otherwise be a way to roll the baseline back.
    const moved = advanceState(previous, verdict, {
      acceptLedgerReset: args.acceptLedgerReset,
    });
    if (moved !== null) saveState(args.state, moved);
  }

  return failed.length > 0 ? EXIT_ABNORMAL : EXIT_CLEAN;
}

/** Parse `attest-verify` flags, argparse-style: a bad value is an error, never
 * a silent fallback. Returns the exit code on a parse failure. */
function parseAttestArgs(argv: string[]): AttestArgs | number {
  const args: AttestArgs = {
    attestation: null,
    expectKey: null,
    expectHost: null,
    keyId: null,
    nonce: null,
    allowUnchallenged: false,
    maxAge: 3600,
    maxSkew: 60,
    state: null,
    expectCapsules: null,
    requirePrevious: false,
    acceptLedgerReset: false,
    reportWithin: null,
    grace: 0,
    json: false,
  };
  const takesValue: Record<string, keyof AttestArgs> = {
    "--expect-key": "expectKey",
    "--expect-host": "expectHost",
    "--key-id": "keyId",
    "--nonce": "nonce",
    "--state": "state",
    "--expect-capsules": "expectCapsules",
  };
  const takesNumber: Record<string, keyof AttestArgs> = {
    "--max-age": "maxAge",
    "--max-skew": "maxSkew",
    "--report-within": "reportWithin",
    "--grace": "grace",
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a in takesValue) {
      const raw = argv[++i];
      if (raw === undefined) {
        console.error(`argument ${a}: expected one argument`);
        return EXIT_NO_REPORT;
      }
      (args[takesValue[a]] as string) = raw;
    } else if (a in takesNumber) {
      const raw = argv[++i];
      if (raw === undefined || !/^[+-]?(\d+\.?\d*|\.\d+)$/.test(raw)) {
        console.error(`argument ${a}: invalid float value: ${raw ?? "(missing)"}`);
        return EXIT_NO_REPORT;
      }
      (args[takesNumber[a]] as number) = parseFloat(raw);
    } else if (a === "--allow-unchallenged") {
      args.allowUnchallenged = true;
    } else if (a === "--require-previous") {
      args.requirePrevious = true;
    } else if (a === "--accept-ledger-reset") {
      args.acceptLedgerReset = true;
    } else if (a === "--json") {
      args.json = true;
    } else if (a.startsWith("-") && a !== "-") {
      console.error(`unknown arg: ${a}`);
      return EXIT_NO_REPORT;
    } else if (args.attestation === null) {
      args.attestation = a;
    } else {
      console.error(`unexpected extra argument: ${a}`);
      return EXIT_NO_REPORT;
    }
  }
  return args;
}

function printHelp(): void {
  console.log(`aegis-trust CLI

Usage:
  aegis sandbox                              Run 10-second demo (dummy data, no infra)
  aegis history [--limit N] [--purpose P]   Show recent shield() invocations
  aegis stats                                Show aggregated statistics
  aegis attest-verify [ATTESTATION]          Verify an Aegis Core attestation
  aegis --help                               Print this help

aegis attest-verify (S051 (3)) — verifies a Core attestation and nothing else;
it never opens the capsule directory, because two implementations answering one
question about one disk is how a customer gets told two things.
Exit 0 clean / 1 abnormal / 2 no report could be obtained.

  ATTESTATION              attestation JSON (path, or - for stdin). Omit with
                           --report-within to check only whether one arrived.
  --expect-key HEX         the Ed25519 public key this deployment is pinned to
  --expect-host FP         the host fingerprint this deployment is pinned to
  --key-id ID              pin the key label as well
  --nonce N                the freshness challenge that was sent
  --allow-unchallenged     accept an attestation with no challenge (without one,
                           an attestation taken before the data went missing
                           replays perfectly, so this has to be said out loud)
  --max-age SECONDS        freshness window (default 3600)
  --max-skew SECONDS       tolerated clock skew (default 60)
  --state PATH             where the previous observation is kept; without it
                           the silence checks cannot run and report SKIP
  --expect-capsules PATH   expected capsule ids, one per line. Core holds no
                           expected inventory: twenty capsules reduced to one
                           attests as judged:1 and is otherwise clean
  --require-previous       refuse to verify without a baseline
  --accept-ledger-reset    assert a lower ledger head is a deliberate reset
                           (a sealed and rotated ledger) and re-base the
                           baseline to it. The SDK cannot check this:
                           genesis.json survives a rotation, so a rotation
                           and a truncation are the same bytes. Counted in
                           the state file; this run still reports the drop
  --report-within SECONDS  also raise an anomaly if no attestation arrived
  --grace SECONDS          grace added to --report-within
  --json                   machine-readable verdict

Environment:
  AEGIS_HISTORY=1                            Enable history recording
  AEGIS_HISTORY_PATH=<path>                  Override history file location
  AEGIS_SANDBOX_AUDIT=<path>                 Override sandbox audit path`);
}

export function main(argv: string[]): number {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printHelp();
    return 0;
  }
  const cmd = argv[0];

  if (cmd === "sandbox") {
    return cmdSandbox();
  }

  if (cmd === "history") {
    let limit = 20;
    let purpose: string | undefined;
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i];
      if (a === "--limit" || a === "-n") {
        const raw = argv[++i];
        // Python argparse parity: a bad --limit is an error (exit 2), never
        // a silent fallback. Strict integer syntax — parseInt alone accepts
        // partial garbage ("10oops" → 10, "0x10" → 0), argparse does not.
        if (raw === undefined || !/^[+-]?\d+$/.test(raw)) {
          console.error(`argument --limit/-n: invalid int value: ${raw ?? "(missing)"}`);
          return 2;
        }
        limit = parseInt(raw, 10);
      } else if (a === "--purpose" || a === "-p") {
        purpose = argv[++i];
        if (purpose === undefined) {
          // Python argparse parity: a missing value is an error, not
          // a silent "no filter" that shows everything.
          console.error("argument --purpose/-p: expected one argument");
          return 2;
        }
      } else {
        console.error(`unknown arg: ${a}`);
        return 2;
      }
    }
    return cmdHistory({ limit, purpose });
  }

  if (cmd === "stats") {
    return cmdStats();
  }

  if (cmd === "attest-verify") {
    const parsed = parseAttestArgs(argv.slice(1));
    if (typeof parsed === "number") return parsed;
    return cmdAttestVerify(parsed);
  }

  console.error(`unknown command: ${cmd}`);
  printHelp();
  return 2;
}

// When executed as a script (not imported as a library). ESM "is main module"
// detection must handle three invocation paths:
//   1. Direct: `node path/to/cli.js sandbox`
//   2. npm bin shim: symlink at node_modules/.bin/aegis → ../aegis-trust/dist/cli.js
//   3. npx aegis: also goes through the bin shim
//
// process.argv[1] is the literal path used to launch node (a symlink for #2/#3);
// import.meta.url is the resolved module URL (the real cli.js path). The previous
// basename-suffix check failed for #2/#3 because basename("aegis") never matched
// a URL ending in "cli.js", so main() never ran — every subcommand exited silently
// with stdout=0 bytes and exit code 0. realpathSync on both sides canonicalises
// the symlink so the comparison holds across all three invocation paths.
const isMain = (() => {
  if (typeof import.meta === "undefined") return false;
  const url = import.meta.url;
  if (!url || !process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMain) {
  process.exit(main(process.argv.slice(2)));
}
