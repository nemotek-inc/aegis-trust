"""Run the attestation check on a schedule, and say something when it is bad.

S053 B-1 / B-2. The verifier has existed since S051 with 17 checks, including a
silence check (`--report-within`) that turns "no report arrived" into a finding.
**Nothing ran it.** The documentation said how to invoke it; the distribution
carried no timer, no Action, no container entrypoint, and no way to tell anyone
the answer except an exit code and a line on stderr.

That is the same shape Core had: the capability existed and the entry point did
not. For a verifier the consequence is sharper than usual — a check nobody runs
is indistinguishable from a check that always passes, and this one exists to
notice that a customer's boundary stopped reporting.

## What this is

One long-running loop. It is the only deployment unit shipped, on purpose:

* under **systemd** it is a `Service` with `Restart=always` (see
  `deploy/aegis-attest-watch.service`);
* in a **container** it is the main process — no cron inside the image, no
  supervisor;
* under **Kubernetes** it is a `Deployment` with one replica, for the same
  reason.

Three shapes, one artifact. A cron-per-platform would have been three artifacts
and three ways to be misconfigured, and the thing being deployed is a watcher —
the one program whose own liveness has to be legible.

## Proving it runs, rather than asserting it

Every cycle writes a **heartbeat** file: the time, the verdict, the cycle count.
That file is how an operator (or another machine) answers "is this actually
running" without asking a person to go and look at a process list. A watcher
that cannot show it ran is the hole it was deployed to close.

## Notifying

`--notify-command` receives the verdict as JSON on **stdin** and is executed as
an argv list, never through a shell: a webhook URL or a pager script is exactly
the kind of value that ends up holding a customer's secret, and `shell=True`
would make a stray character in it into command execution.

Notification fires on a **change of verdict**, plus every `--renotify` seconds
while the verdict stays bad. Firing every cycle trains people to filter it;
firing only once means a problem that persists for a week is announced once, on
a Tuesday, and then never again.

A notification that fails to send is itself abnormal and is recorded in the
heartbeat. The watcher does not exit on it — losing the watcher because the
pager was down is the wrong trade — but it never reports a delivery it did not
make.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = [
    "Heartbeat",
    "WatchConfig",
    "should_notify",
    "run_cycle",
    "watch",
]

#: Verdict names, mapped from the verifier's exit codes. The names travel into
#: the heartbeat and the notification, so a reader never has to remember which
#: integer meant which thing.
VERDICT = {0: "clean", 1: "abnormal", 2: "no_report"}


@dataclass
class Heartbeat:
    """What one cycle leaves behind. Written whether the cycle was good or bad."""

    started_at: float
    finished_at: float
    cycle: int
    verdict: str
    exit_code: int
    notified: bool = False
    notify_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cycle": self.cycle,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "notified": self.notified,
            "notify_error": self.notify_error,
        }


@dataclass
class WatchConfig:
    """Everything the loop needs, so the loop itself has no hidden inputs."""

    every_seconds: float
    heartbeat_path: str | None = None
    notify_command: list[str] = field(default_factory=list)
    renotify_seconds: float | None = None
    max_cycles: int | None = None


def should_notify(
    previous_verdict: str | None,
    verdict: str,
    last_notified_at: float | None,
    now: float,
    renotify_seconds: float | None,
) -> tuple[bool, str]:
    """Decide whether this cycle's verdict is worth telling somebody about.

    Returns ``(notify, reason)``. The reason travels into the heartbeat, so a
    reader can tell "we stayed quiet because nothing changed" from "we stayed
    quiet because nothing is configured".

    * a **clean** verdict never notifies. A watcher that pages on success is a
      watcher people mute;
    * the first bad verdict notifies;
    * a bad verdict that is the same as last time notifies again only after
      ``renotify_seconds``. Without a repeat, a problem that persists is
      announced once and then never again — which reads, to anyone who joined
      after that day, exactly like no problem at all;
    * a bad verdict that DIFFERS from the last bad one notifies immediately:
      "the report stopped arriving" and "the report arrived and is wrong" are
      different emergencies.
    """
    if verdict == "clean":
        return False, "clean"
    if previous_verdict != verdict:
        return True, "verdict changed"
    if renotify_seconds is None:
        return False, "unchanged (no --renotify configured)"
    if last_notified_at is None:
        return True, "unchanged but never notified"
    if now - last_notified_at >= renotify_seconds:
        return True, f"unchanged for {now - last_notified_at:.0f}s (>= renotify)"
    return False, "unchanged, within the renotify window"


def _write_atomic(path: str, body: str) -> None:
    """Replace `path` in one step, at 0600.

    The heartbeat is read by other programs while this one writes it; a partial
    file would be read as a corrupt heartbeat, which is a false alarm about the
    very thing this file exists to report honestly.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".heartbeat.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _notify(command: list[str], payload: dict[str, Any]) -> str | None:
    """Run the notify command with the verdict on stdin. Returns an error, or None.

    argv, never a shell. A notify command is typically built from a webhook URL
    or a token, and those are exactly the values that turn `shell=True` into
    command execution.
    """
    if not command:
        return "no --notify-command configured"
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, never shell
            command,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"notify command could not run: {exc}"
    if proc.returncode != 0:
        return (
            f"notify command exited {proc.returncode}: "
            f"{(proc.stderr or '').strip()[:200]}"
        )
    return None


def run_cycle(
    check: Callable[[], int],
    config: WatchConfig,
    state: dict[str, Any],
    now_fn: Callable[[], float] = time.time,
) -> Heartbeat:
    """One pass: check, decide, notify, leave evidence.

    `check` returns the verifier's exit code. It is injected rather than
    imported so the loop can be exercised without an attestation, a key, or a
    Core to talk to — the loop's own behaviour is what these controls are about.
    """
    started = now_fn()
    try:
        code = check()
    except Exception as exc:  # noqa: BLE001 - a crashing check is a verdict
        # A verifier that raises has not said "clean". Treat it as the
        # could-not-report verdict and carry the reason, rather than letting an
        # exception end the watcher and take the monitoring with it.
        code = 2
        state["last_error"] = repr(exc)
    verdict = VERDICT.get(code, "unknown")
    finished = now_fn()

    state["cycle"] = state.get("cycle", 0) + 1
    beat = Heartbeat(
        started_at=started,
        finished_at=finished,
        cycle=state["cycle"],
        verdict=verdict,
        exit_code=code,
    )

    notify, reason = should_notify(
        state.get("verdict"),
        verdict,
        state.get("last_notified_at"),
        finished,
        config.renotify_seconds,
    )
    if notify:
        error = _notify(
            config.notify_command,
            {
                "verdict": verdict,
                "exit_code": code,
                "cycle": beat.cycle,
                "at": finished,
                "reason": reason,
            },
        )
        beat.notify_error = error
        beat.notified = error is None
        if beat.notified:
            state["last_notified_at"] = finished
    state["verdict"] = verdict

    if config.heartbeat_path:
        payload = beat.to_dict()
        payload["notify_reason"] = reason
        _write_atomic(config.heartbeat_path, json.dumps(payload, indent=2) + "\n")
    return beat


def watch(
    check: Callable[[], int],
    config: WatchConfig,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], float] = time.time,
) -> int:
    """Loop until `max_cycles`, or forever.

    Returns the LAST cycle's exit code, which makes `--max-cycles 1` behave
    exactly like a single `attest-verify` run — the property that lets a
    customer test the deployment without waiting for a period to elapse.
    """
    state: dict[str, Any] = {}
    last = 0
    while True:
        beat = run_cycle(check, config, state, now_fn=now_fn)
        last = beat.exit_code
        if config.max_cycles is not None and beat.cycle >= config.max_cycles:
            return last
        sleep_fn(config.every_seconds)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The watch-specific flags. The check's own flags are added by the caller."""
    parser.add_argument(
        "--every",
        type=float,
        default=3600.0,
        metavar="SECONDS",
        help="how long to wait between checks (default: 3600)",
    )
    parser.add_argument(
        "--heartbeat",
        default=None,
        metavar="PATH",
        help=(
            "write the cycle's outcome here every time. This is how anyone "
            "answers 'is the watcher running' without asking a person to look."
        ),
    )
    parser.add_argument(
        "--notify-command",
        default=None,
        metavar="CMD",
        help=(
            "command to run when the verdict is bad. Executed as argv (split on "
            "spaces), never through a shell; the verdict arrives as JSON on stdin."
        ),
    )
    parser.add_argument(
        "--renotify",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "repeat the notification while the verdict stays bad. Without it a "
            "persistent problem is announced once and then never again."
        ),
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        metavar="N",
        help="stop after N cycles (1 = run the check once and exit, for testing)",
    )


def config_from_args(args: argparse.Namespace) -> WatchConfig:
    command = (args.notify_command or "").split()
    return WatchConfig(
        every_seconds=args.every,
        heartbeat_path=args.heartbeat,
        notify_command=command,
        renotify_seconds=args.renotify,
        max_cycles=args.max_cycles,
    )


def main(check: Callable[[], int], args: argparse.Namespace) -> int:
    config = config_from_args(args)
    if config.max_cycles is None:
        print(
            f"attest-watch: every {config.every_seconds:g}s"
            + (f", heartbeat {config.heartbeat_path}" if config.heartbeat_path else "")
            + (
                ", notify configured"
                if config.notify_command
                else ", **no --notify-command: a bad verdict will be silent**"
            ),
            file=sys.stderr,
        )
    return watch(check, config)
