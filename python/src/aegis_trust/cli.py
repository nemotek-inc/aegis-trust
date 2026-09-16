"""aegis CLI — local history inspection and Core attestation verification.

Usage:
    aegis history [--limit N] [--purpose PURPOSE]
    aegis stats
    aegis attest-verify [ATTESTATION] --expect-key HEX --expect-host FP [...]
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Sequence

from aegis_trust.attest_verify import (
    EXIT_ABNORMAL,
    EXIT_CLEAN,
    EXIT_NO_REPORT,
    AttestCheck,
    AttestExpectation,
    AttestStateError,
    advance_state,
    load_state,
    report_arrived_check,
    save_state,
    verify_attestation,
)
from aegis_trust.history import HistoryStore


def _get_db_path() -> str:
    return os.environ.get(
        "AEGIS_HISTORY_PATH",
        str(Path.home() / ".aegis" / "history.db"),
    )


def _open_store() -> HistoryStore | None:
    db_path = _get_db_path()
    if not os.path.exists(db_path):
        print(f"No history database found at {db_path}")
        print("Enable history with: AEGIS_HISTORY=1")
        return None
    try:
        return HistoryStore(db_path)
    except sqlite3.Error:
        # Not a SQLite database (e.g. AEGIS_HISTORY_PATH points at the Node
        # SDK's history.jsonl, which shares the env var name but not the
        # format). Inspection commands must hint, not stack-trace.
        print(f"History file at {db_path} is not a SQLite database.")
        print(
            "If this is the Node SDK's history.jsonl, inspect it with "
            "`npx aegis history` instead."
        )
        return None


def cmd_history(args: argparse.Namespace) -> int:
    """Print recent ``@shield`` invocation history.

    Reads from the local SQLite store (default ``~/.aegis/history.db``,
    overridable via ``AEGIS_HISTORY_PATH``). Returns 0 on success, 1 if no
    history database exists.
    """
    store = _open_store()
    if store is None:
        return 1
    records = store.get_history(limit=args.limit, purpose=args.purpose)
    store.close()

    if not records:
        print("No history records found.")
        return 0

    # Header
    print(
        f"{'ID':>5}  {'Function':<25} {'Purpose':<15} {'Blocked':<30} {'Timestamp':<25}"
    )
    print("-" * 105)

    for r in records:
        blocked = ", ".join(r.blocked_fields) if r.blocked_fields else "-"
        ts = r.timestamp[:19] if len(r.timestamp) > 19 else r.timestamp
        print(f"{r.id:>5}  {r.function:<25} {r.purpose:<15} {blocked:<30} {ts:<25}")

    print(f"\n{len(records)} record(s) shown.")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Print aggregated ``@shield`` statistics from local history.

    Shows total call count, blocked field totals, per-purpose summaries, and
    per-field block counts. Returns 0 on success, 1 if no history database exists.
    """
    store = _open_store()
    if store is None:
        return 1
    stats = store.get_stats()
    store.close()

    if stats["total_calls"] == 0:
        print("No history records found.")
        return 0

    print(f"Total calls: {stats['total_calls']}")
    print(f"Total blocked fields: {stats['total_blocked_fields']}")

    if stats["by_purpose"]:
        print(f"\n{'Purpose':<20} {'Calls':>8} {'Blocked':>8}")
        print("-" * 40)
        for purpose, data in sorted(stats["by_purpose"].items()):
            print(f"{purpose:<20} {data['calls']:>8} {data['blocked']:>8}")

    if stats["by_field"]:
        print(f"\n{'Field':<30} {'Blocked Count':>15}")
        print("-" * 48)
        for field, count in sorted(
            stats["by_field"].items(), key=lambda x: x[1], reverse=True
        ):
            print(f"{field:<30} {count:>15}")

    return 0


def _read_attestation_source(source: str) -> tuple[dict[str, Any] | None, str]:
    """Read the attestation document, or say why there is none.

    Returns ``(document, problem)``. A ``problem`` is the exit-2 condition of
    contract §5 — *no report could be obtained* — which is deliberately not the
    same answer as *a report was obtained and it is abnormal*. Bytes that are
    not JSON at all land here too: a report that is not a document is
    indistinguishable from an invocation that failed, and calling that an
    anomaly would page the deployment's owner about a broken pipe.
    """
    try:
        raw = (
            sys.stdin.read()
            if source == "-"
            else Path(source).read_text(encoding="utf-8")
        )
    except OSError as exc:
        return None, f"could not read {source}: {exc}"
    if not raw.strip():
        return None, f"no attestation on {source} (empty input)"
    try:
        document = json.loads(raw)
    except ValueError as exc:
        return None, f"{source} is not JSON: {exc}"
    if not isinstance(document, dict):
        # A JSON scalar or array is not a failed report; it IS a document making
        # a claim, so it goes to the verifier and comes back as an anomaly.
        return {"__not_an_object__": document}, ""
    return document, ""


def _read_expected_capsules(path: str) -> tuple[str, ...]:
    """One capsule id per line; blank lines and ``#`` comments ignored."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return tuple(
        s for s in (line.strip() for line in lines) if s and not s.startswith("#")
    )


def _print_checks(checks: Sequence[AttestCheck]) -> None:
    for check in checks:
        print(f"  {check.outcome.value.upper():<4} {check.check:<18} {check.detail}")


def cmd_attest_verify(args: argparse.Namespace) -> int:
    """Verify a Core attestation (S051 ③).

    Exit codes are the verdict (contract §5): 0 clean, 1 abnormal, 2 no report
    could be obtained. 2 is deliberately distinct — "I could not report" is not
    "I found problems", and collapsing them means a broken invocation pages the
    same person as a broken deployment.
    """
    try:
        previous = load_state(args.state) if args.state else None
    except AttestStateError as exc:
        # Not exit 2. A state file that exists and cannot be read is refused
        # rather than treated as a fresh start, because the degradation IS the
        # bypass: corrupt the file and the silence check skips every run while
        # the report stays green. Clearing it has to be a deliberate act.
        print(f"[ANOMALY] {exc}", file=sys.stderr)
        return EXIT_ABNORMAL

    timer: AttestCheck | None = None
    if args.report_within is not None:
        timer = report_arrived_check(
            previous,
            interval_seconds=args.report_within,
            grace_seconds=args.grace,
        )

    if args.attestation is None:
        if timer is None:
            print(
                "attest-verify: pass an attestation (a path, or - for stdin), "
                "or --report-within SECONDS to check only whether one arrived",
                file=sys.stderr,
            )
            return EXIT_NO_REPORT
        # Timer-only mode: nothing was fetched from Core, and that is the point.
        if args.json:
            print(
                json.dumps(
                    {"checks": [timer.to_dict()], "ok": not timer.failed}, indent=2
                )
            )
        else:
            _print_checks([timer])
        return EXIT_ABNORMAL if timer.failed else EXIT_CLEAN

    document, problem = _read_attestation_source(args.attestation)
    if document is None:
        print(f"[ERROR] attestation could not be obtained: {problem}", file=sys.stderr)
        return EXIT_NO_REPORT

    expect = AttestExpectation(
        public_key_hex=args.expect_key,
        host_fingerprint=args.expect_host,
        nonce=args.nonce,
        allow_unchallenged=args.allow_unchallenged,
        key_id=args.key_id,
        max_age_seconds=args.max_age,
        max_clock_skew_seconds=args.max_skew,
        capsule_ids=(
            _read_expected_capsules(args.expect_capsules)
            if args.expect_capsules
            else None
        ),
        require_previous=args.require_previous,
    )
    verdict = verify_attestation(document, expect, previous)
    checks = list(verdict.checks) + ([timer] if timer else [])
    failed = [c for c in checks if c.failed]

    if args.json:
        payload = verdict.to_dict()
        payload["checks"] = [c.to_dict() for c in checks]
        payload["findings"] = [c.to_dict() for c in failed]
        payload["ok"] = not failed
        payload["exit_code"] = EXIT_CLEAN if not failed else EXIT_ABNORMAL
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _print_checks(checks)
        if failed:
            print(f"[ANOMALY] {len(failed)} check(s) failed")
        else:
            skipped = verdict.skipped
            print("[OK] attestation verified")
            if skipped:
                # Never folded into the green: a check that did not run is not a
                # check that passed.
                print(
                    f"      {len(skipped)} check(s) could not run: "
                    + ", ".join(c.check for c in skipped)
                )

    if args.state:
        # Only ever forward. See advance_state: a genuinely signed OLD
        # attestation would otherwise be a way to roll the baseline back.
        moved = advance_state(
            previous, verdict, accept_ledger_reset=args.accept_ledger_reset
        )
        if moved is not None:
            save_state(args.state, moved)

    return EXIT_ABNORMAL if failed else EXIT_CLEAN


def cmd_attest_watch(args: argparse.Namespace) -> int:
    """Run `attest-verify` on a schedule, and notify when the verdict is bad.

    S053 B-1 / B-2. The verifier existed and nothing ran it; the documentation
    said how to invoke it and the distribution shipped no unit that did. A check
    nobody runs is indistinguishable from a check that always passes — and this
    one exists to notice that a customer's boundary stopped reporting.

    The loop reuses `cmd_attest_verify` unchanged. One verifier, one answer: a
    second implementation of "is this attestation good" is how a customer gets
    told two different things about one disk.
    """
    from . import attest_watch

    return attest_watch.main(lambda: cmd_attest_verify(args), args)


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and dispatch to the correct subcommand.

    Returns the subcommand's exit code, or 0 when no subcommand is given
    (prints help in that case).
    """
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="aegis-trust CLI — local history inspection",
    )
    subparsers = parser.add_subparsers(dest="command")

    # aegis history
    hist_parser = subparsers.add_parser("history", help="Show recent filtering history")
    hist_parser.add_argument(
        "--limit", "-n", type=int, default=20, help="Number of records (default: 20)"
    )
    hist_parser.add_argument(
        "--purpose", "-p", type=str, default=None, help="Filter by purpose"
    )

    # aegis stats
    subparsers.add_parser("stats", help="Show aggregated statistics")

    # aegis attest-verify
    att = subparsers.add_parser(
        "attest-verify",
        help="Verify an Aegis Core attestation (S051 ③)",
        description=(
            "Verify a Core attestation and nothing else: this never opens the "
            "capsule directory, because two implementations answering one "
            "question about one disk is how a customer gets told two things. "
            "Exit 0 clean / 1 abnormal / 2 no report could be obtained."
        ),
    )
    att.add_argument(
        "attestation",
        nargs="?",
        default=None,
        help="attestation JSON (path, or - for stdin). Omit with --report-within "
        "to check only whether a report arrived at all.",
    )
    att.add_argument(
        "--expect-key",
        required=True,
        help="the Ed25519 public key (64 hex chars) this deployment is pinned to",
    )
    att.add_argument(
        "--expect-host",
        required=True,
        help="the host fingerprint this deployment is pinned to",
    )
    att.add_argument("--key-id", default=None, help="pin the key label as well")
    att.add_argument(
        "--nonce",
        default=None,
        help="the freshness challenge that was sent, which must come back",
    )
    att.add_argument(
        "--allow-unchallenged",
        action="store_true",
        help="accept an attestation with no challenge. Without a nonce, one "
        "taken before the data went missing replays perfectly, so this has to "
        "be said out loud.",
    )
    att.add_argument("--max-age", type=float, default=3600.0, metavar="SECONDS")
    att.add_argument("--max-skew", type=float, default=60.0, metavar="SECONDS")
    att.add_argument(
        "--state",
        default=None,
        metavar="PATH",
        help="where the previous observation is kept. Without it the silence "
        "checks cannot run and report SKIP.",
    )
    att.add_argument(
        "--expect-capsules",
        default=None,
        metavar="PATH",
        help="file of expected capsule ids, one per line. Core holds no expected "
        "inventory (contract §6): twenty capsules reduced to one attests as "
        "judged:1 and is otherwise clean, and only this catches it.",
    )
    att.add_argument(
        "--require-previous",
        action="store_true",
        help="refuse to verify without a baseline, so deleting the state file "
        "cannot silence the silence check",
    )
    att.add_argument(
        "--accept-ledger-reset",
        action="store_true",
        help="assert that a lower ledger head is a deliberate reset (a sealed "
        "and rotated ledger), and re-base the stored baseline to it. The SDK "
        "cannot check this: genesis.json survives a rotation, so a rotation and "
        "a truncation are the same bytes. The assertion is counted in the state "
        "file, and this run still reports the drop.",
    )
    att.add_argument(
        "--report-within",
        type=float,
        default=None,
        metavar="SECONDS",
        help="also raise an anomaly if no attestation has arrived this recently",
    )
    att.add_argument("--grace", type=float, default=0.0, metavar="SECONDS")
    att.add_argument("--json", action="store_true", help="machine-readable verdict")

    # aegis attest-watch — the same check, on a schedule, with a way to tell
    # somebody. Every `attest-verify` flag is accepted verbatim so a customer
    # who has a working one-shot invocation turns it into a deployment by
    # changing one word.
    from . import attest_watch as _attest_watch

    watch = subparsers.add_parser(
        "attest-watch",
        help="run attest-verify on a schedule and notify on a bad verdict (S053 B-1/B-2)",
        description=(
            "The verifier, deployed. One long-running loop: a systemd Service, a "
            "container's main process, or a one-replica Deployment — three shapes, "
            "one artifact. Every cycle writes a heartbeat, so 'is it running' is "
            "answerable without asking a person to look."
        ),
    )
    for action in att._actions:  # noqa: SLF001 - reuse the verifier's own flags
        if action.dest in {"help"}:
            continue
        kwargs = {
            "default": action.default,
            "help": action.help,
        }
        if action.dest == "attestation":
            watch.add_argument("attestation", nargs="?", **kwargs)
            continue
        if action.__class__.__name__ == "_StoreTrueAction":
            watch.add_argument(*action.option_strings, action="store_true", **kwargs)
            continue
        kwargs["type"] = action.type
        kwargs["required"] = action.required
        kwargs["metavar"] = action.metavar
        watch.add_argument(*action.option_strings, **kwargs)
    _attest_watch.add_arguments(watch)

    args = parser.parse_args(argv)

    if args.command == "history":
        return cmd_history(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "attest-verify":
        return cmd_attest_verify(args)
    elif args.command == "attest-watch":
        return cmd_attest_watch(args)
    else:
        parser.print_help()
        return 0


def cli_entry() -> None:
    """Entry point used by the ``aegis`` console script (see ``pyproject.toml``)."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    # `python -m aegis_trust.cli` must behave like the `aegis` console script.
    # Without this guard the module invocation was a silent no-op with exit 0 —
    # the same silent-exit class the Node CLI fixed in PR #4.
    cli_entry()
