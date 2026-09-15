#!/usr/bin/env python3
"""Mutation battery for the attestation verifier (S051 ③, both SDKs).

Why this exists: a conformance corpus that stays green when the shipped verifier
is wrong is worse than no corpus, because it reads as coverage. The corpus
runner asserts that every check has a rejecting case and an accepting case, but
that assertion is only as good as the corpus itself. This goes one level down —
it edits the shipped implementation, runs the real suites, and requires them to
go RED. A mutation that survives is a vacuous oracle and is reported as such.

The mutations are the failure shapes this layer exists to stop: a findings
digest that lets a rewritten capsule id hide inside an issue string, a verifier
that reads "no key configured" as "nothing to check", a silence check that
reports a ledger head which did not move as "no news", an Ed25519 verification
that accepts everything, and a baseline that follows a shrinking ledger.

The last three mutations target the CONTRACT PIN rather than the verifier:
the wire contract lives in another repository, so nothing here can watch it
move — it moved three times while this verifier was being written. What can
be checked is that the shipped code and the pinned shape cannot drift apart
silently, and these prove that check is live rather than decorative.

Run:  python3 scripts/attest_verify_mutation_battery.py
Exit: 0 only if every mutation was detected. Sources are restored and their
      hashes re-checked before the script exits, on every path including
      failure.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_SRC = ROOT / "python" / "src" / "aegis_trust" / "attest_verify.py"
PY_ED = ROOT / "python" / "src" / "aegis_trust" / "_ed25519.py"
TS_SRC = ROOT / "node" / "src" / "attestVerify.ts"
CORPUS = ROOT / "conformance" / "attest_verify.v0.json"

PY_CMD = [
    ".venv/bin/pytest",
    "-q",
    "tests/test_attest_verify_corpus.py",
    "tests/test_attest_verify.py",
    "tests/test_ed25519_corpus.py",
]
NODE_CMD = [
    "npx",
    "vitest",
    "run",
    "tests/attestVerifyCorpus.test.ts",
    "tests/attestVerify.test.ts",
    "tests/ed25519Corpus.test.ts",
]


def run(cmd: list[str], cwd: Path) -> bool:
    """True if the suite passed."""
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode == 0


def run_python() -> bool:
    return run(PY_CMD, ROOT / "python")


def run_node() -> bool:
    return run(NODE_CMD, ROOT / "node")


def run_both() -> bool:
    """True only if BOTH suites pass — the corpus is shared, so a drift in it
    has to be caught on both sides or one SDK is reading a pin nobody checks."""
    return run_python() and run_node()


# (name, file, find, replace, suite that must go red)
MUTATIONS: list[tuple[str, Path, str, str, object]] = [
    (
        "python: drop the 8-byte length prefix from the findings digest",
        PY_SRC,
        '            h.update(len(encoded).to_bytes(8, "little"))\n',
        "",
        run_python,
    ),
    (
        "python: length-prefix by CHARACTER count instead of BYTE count",
        PY_SRC,
        '            h.update(len(encoded).to_bytes(8, "little"))\n',
        '            h.update(len(part).to_bytes(8, "little"))\n',
        run_python,
    ),
    (
        "python: treat an unsigned attestation as nothing to check",
        PY_SRC,
        "    if att.signature is None:\n"
        "        add(\n"
        "            CHECK_SIGNATURE_PRESENT,\n"
        "            CheckOutcome.FAIL,\n",
        "    if att.signature is None:\n"
        "        add(\n"
        "            CHECK_SIGNATURE_PRESENT,\n"
        "            CheckOutcome.PASS,\n",
        run_python,
    ),
    (
        "python: report a ledger head that did not advance as 'no news'",
        PY_SRC,
        "        elif att.chain.last_seq == previous.last_seq:\n"
        "            add(\n"
        "                CHECK_SEQUENCE_ADVANCED,\n"
        "                CheckOutcome.FAIL,\n",
        "        elif att.chain.last_seq == previous.last_seq:\n"
        "            add(\n"
        "                CHECK_SEQUENCE_ADVANCED,\n"
        "                CheckOutcome.PASS,\n",
        run_python,
    ),
    (
        "python: accept every Ed25519 signature",
        PY_ED,
        "    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:\n",
        "    return True\n"
        "    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:\n",
        run_python,
    ),
    (
        "python: skip the canonical-scalar check (accept S+L malleability)",
        PY_ED,
        "    if s >= _L:\n",
        "    if False:\n",
        run_python,
    ),
    (
        "python: let an expected-inventory mismatch pass",
        PY_SRC,
        '            add(CHECK_INVENTORY, CheckOutcome.FAIL, "; ".join(parts))\n',
        '            add(CHECK_INVENTORY, CheckOutcome.PASS, "; ".join(parts))\n',
        run_python,
    ),
    (
        "python: let the baseline follow a shrinking ledger head",
        PY_SRC,
        "    head_forward = nxt.last_seq > previous.last_seq\n",
        "    head_forward = True\n",
        run_python,
    ),
    (
        "node: length-prefix by UTF-16 unit count instead of BYTE count",
        TS_SRC,
        "      length.writeBigUInt64LE(BigInt(encoded.length));\n",
        "      length.writeBigUInt64LE(BigInt(part.length));\n",
        run_node,
    ),
    (
        "node: accept every Ed25519 signature",
        TS_SRC,
        "  if (!ed25519Verify(publicKey, messageBytes, signature)) {\n",
        "  if (false) {\n",
        run_node,
    ),
    (
        "node: report a ledger head that did not advance as 'no news'",
        TS_SRC,
        "    } else if (att.chain.lastSeq === previous.lastSeq) {\n"
        "      add(\n"
        "        CHECK_SEQUENCE_ADVANCED,\n"
        '        "fail",\n',
        "    } else if (att.chain.lastSeq === previous.lastSeq) {\n"
        "      add(\n"
        "        CHECK_SEQUENCE_ADVANCED,\n"
        '        "pass",\n',
        run_node,
    ),
    (
        "node: treat an unsigned attestation as nothing to check",
        TS_SRC,
        "    add(\n"
        "      CHECK_SIGNATURE_PRESENT,\n"
        '      "fail",\n'
        '      "the attestation is unsigned',
        "    add(\n"
        "      CHECK_SIGNATURE_PRESENT,\n"
        '      "pass",\n'
        '      "the attestation is unsigned',
        run_node,
    ),
    (
        "contract pin: the declared canonical-message field list drifts from the code",
        CORPUS,
        '      "chain_curr_hash",\n',
        '      "chain_curr_hash_RENAMED",\n',
        run_both,
    ),
    (
        "contract pin: the declared integer bound drifts from the code",
        CORPUS,
        '  "max_integer": 9007199254740991,\n',
        '  "max_integer": 9007199254740990,\n',
        run_both,
    ),
    (
        "python: the integer bound moves without the contract pin moving",
        PY_SRC,
        "MAX_SAFE_INTEGER = 9007199254740991\n",
        "MAX_SAFE_INTEGER = 9007199254740990\n",
        run_python,
    ),
]


def main() -> int:
    targets = [PY_SRC, PY_ED, TS_SRC, CORPUS]
    originals = {p: p.read_text(encoding="utf-8") for p in targets}
    hashes = {
        p: hashlib.sha256(t.encode("utf-8")).hexdigest() for p, t in originals.items()
    }

    survivors: list[str] = []
    try:
        # A mutation probe against a red baseline proves nothing.
        print("baseline (both suites must be green before any mutation means anything)")
        base_py, base_node = run_python(), run_node()
        print(f"  python: {'green' if base_py else 'RED'}")
        print(f"  node  : {'green' if base_node else 'RED'}")
        if not (base_py and base_node):
            print("baseline is not green; aborting", file=sys.stderr)
            return 1

        for name, path, old, new, runner in MUTATIONS:
            text = originals[path]
            if old not in text:
                print(f"mutation anchor not found: {name}", file=sys.stderr)
                return 1
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            try:
                still_green = runner()  # type: ignore[operator]
            finally:
                path.write_text(text, encoding="utf-8")
            print(f"  {'SURVIVED' if still_green else 'caught  '}  {name}")
            if still_green:
                survivors.append(name)
    finally:
        for path, text in originals.items():
            path.write_text(text, encoding="utf-8")
        for path, digest in hashes.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                print(f"FAILED TO RESTORE {path}", file=sys.stderr)
                return 1
        print("all sources restored byte-for-byte")

    if survivors:
        print(
            f"\n{len(survivors)} mutation(s) survived — those oracles are decorative:",
            file=sys.stderr,
        )
        for name in survivors:
            print(f"  - {name}", file=sys.stderr)
        return 1
    print(f"\nall {len(MUTATIONS)} mutations were caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
