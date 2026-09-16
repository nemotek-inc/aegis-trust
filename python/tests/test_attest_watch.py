"""S053 B-1 / B-2 — the verifier, actually deployed, and actually saying something.

The verifier has existed since S051 with 17 checks, including a silence check
that turns "no report arrived" into a finding. **Nothing ran it.** The docs said
how to invoke it; the distribution carried no timer, no Action, no container
entrypoint, and no way to tell anyone the answer except an exit code and a line
on stderr.

For a verifier that is worse than for an ordinary feature: a check nobody runs
is indistinguishable from a check that always passes, and this one exists to
notice that a customer's boundary stopped reporting.

The acceptance the handoff asked for, and where each half is pinned here:

* **B-1: 叩かなくても回ること** — `it_runs_again_without_anyone_invoking_it`
  and `a_heartbeat_is_written_every_cycle`. The loop is driven with an injected
  clock, so "the next period produced a report" is asserted, not waited for.
* **B-2: 異常時に通知が出る / 正常時に出ない** —
  `a_bad_verdict_notifies` / `a_clean_verdict_never_notifies`.
* **その 2 つが実際に動いていることの対照** — the notify path is exercised with a
  real subprocess that records what it received, and a failing notifier is
  asserted to be reported rather than swallowed.
"""

from __future__ import annotations

import json
import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis_trust.attest_watch import (  # noqa: E402
    WatchConfig,
    run_cycle,
    should_notify,
    watch,
)


# --------------------------------------------------------------------------
# B-1 — it runs again, without anyone invoking it
# --------------------------------------------------------------------------
def test_it_runs_again_without_anyone_invoking_it():
    """The whole point: one invocation, several checks.

    Driven with an injected sleep and clock so the assertion is "the loop ran
    the check N times", not "we waited N periods and hoped".
    """
    calls = []
    slept = []

    def check() -> int:
        calls.append(len(calls))
        return 0

    watch(
        check,
        WatchConfig(every_seconds=3600, max_cycles=3),
        sleep_fn=slept.append,
        now_fn=lambda: 1000.0 + len(calls),
    )
    assert len(calls) == 3, "the loop stopped after the first check"
    # Two waits for three checks: the loop does not sleep after the last one.
    assert slept == [3600, 3600], slept


def test_a_heartbeat_is_written_every_cycle(tmp_path):
    """ "Is it running" must be answerable without asking a person to look."""
    beat = tmp_path / "beat.json"
    watch(
        lambda: 0,
        WatchConfig(every_seconds=1, heartbeat_path=str(beat), max_cycles=2),
        sleep_fn=lambda _s: None,
        now_fn=lambda: 5.0,
    )
    doc = json.loads(beat.read_text())
    assert doc["cycle"] == 2, doc
    assert doc["verdict"] == "clean", doc


def test_the_heartbeat_is_not_world_readable(tmp_path):
    """It carries a deployment's verdict history. 0600, like anything else here."""
    beat = tmp_path / "beat.json"
    watch(
        lambda: 0,
        WatchConfig(every_seconds=1, heartbeat_path=str(beat), max_cycles=1),
        sleep_fn=lambda _s: None,
    )
    mode = stat.S_IMODE(beat.stat().st_mode)
    assert mode == 0o600, oct(mode)


def test_a_crashing_check_does_not_end_the_watcher(tmp_path):
    """Losing the watcher because the check raised is the wrong trade.

    A raising verifier has not said "clean"; it becomes the could-not-report
    verdict and the loop carries on, because the alternative is that one bad
    attestation file silently ends all monitoring.
    """
    beat = tmp_path / "beat.json"
    calls = []

    def check() -> int:
        calls.append(1)
        raise RuntimeError("core unreachable")

    watch(
        check,
        WatchConfig(every_seconds=1, heartbeat_path=str(beat), max_cycles=2),
        sleep_fn=lambda _s: None,
    )
    assert len(calls) == 2, "the watcher stopped on an exception"
    assert json.loads(beat.read_text())["verdict"] == "no_report"


# --------------------------------------------------------------------------
# B-2 — it tells somebody, and only when there is something to tell
# --------------------------------------------------------------------------
def _recorder(tmp_path):
    """A real notify command that records what arrived on stdin."""
    script = tmp_path / "notify.py"
    out = tmp_path / "notified.jsonl"
    script.write_text(
        "import sys, pathlib\n"
        f"pathlib.Path({str(out)!r}).open('a').write(sys.stdin.read() + '\\n')\n"
    )
    return [sys.executable, str(script)], out


def test_a_bad_verdict_notifies(tmp_path):
    command, out = _recorder(tmp_path)
    watch(
        lambda: 1,
        WatchConfig(every_seconds=1, notify_command=command, max_cycles=1),
        sleep_fn=lambda _s: None,
    )
    assert out.exists(), "an abnormal verdict sent no notification"
    payload = json.loads(out.read_text().strip())
    assert payload["verdict"] == "abnormal", payload
    assert payload["exit_code"] == 1


def test_a_clean_verdict_never_notifies(tmp_path):
    command, out = _recorder(tmp_path)
    watch(
        lambda: 0,
        WatchConfig(every_seconds=1, notify_command=command, max_cycles=3),
        sleep_fn=lambda _s: None,
    )
    assert not out.exists(), "a clean run paged somebody"


def test_no_report_and_abnormal_are_different_emergencies(tmp_path):
    """ "the report stopped arriving" and "the report is wrong" both notify.

    They are distinct verdicts, so moving between them notifies immediately
    rather than being filtered as "unchanged".
    """
    command, out = _recorder(tmp_path)
    codes = iter([1, 2])
    watch(
        lambda: next(codes),
        WatchConfig(every_seconds=1, notify_command=command, max_cycles=2),
        sleep_fn=lambda _s: None,
    )
    lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
    assert [x["verdict"] for x in lines] == ["abnormal", "no_report"], lines


def test_an_unchanged_bad_verdict_does_not_page_every_cycle(tmp_path):
    """Firing every cycle trains people to filter it."""
    command, out = _recorder(tmp_path)
    watch(
        lambda: 1,
        WatchConfig(every_seconds=1, notify_command=command, max_cycles=4),
        sleep_fn=lambda _s: None,
    )
    lines = [x for x in out.read_text().splitlines() if x.strip()]
    assert len(lines) == 1, f"notified {len(lines)} times for one unchanged verdict"


def test_a_persistent_problem_is_announced_again_after_renotify():
    """Announced once and never again reads, to anyone who joined later, like no
    problem at all."""
    now = [1000.0]
    state: dict = {}
    sent = []
    config = WatchConfig(
        every_seconds=60,
        notify_command=["true"],
        renotify_seconds=300,
    )
    for _ in range(10):
        beat = run_cycle(lambda: 1, config, state, now_fn=lambda: now[0])
        if beat.notified:
            sent.append(now[0])
        now[0] += 60
    assert len(sent) >= 2, f"a persistent problem was announced {len(sent)} time(s)"
    assert sent[1] - sent[0] >= 300, sent


def test_a_failing_notifier_is_recorded_not_swallowed(tmp_path):
    """Never report a delivery that was not made."""
    beat = tmp_path / "beat.json"
    watch(
        lambda: 1,
        WatchConfig(
            every_seconds=1,
            heartbeat_path=str(beat),
            notify_command=[sys.executable, "-c", "raise SystemExit(3)"],
            max_cycles=1,
        ),
        sleep_fn=lambda _s: None,
    )
    doc = json.loads(beat.read_text())
    assert doc["notified"] is False, doc
    assert "exited 3" in (doc["notify_error"] or ""), doc


def test_no_notify_command_is_visible_in_the_heartbeat(tmp_path):
    """A deployment with nowhere to send the alarm must not look healthy."""
    beat = tmp_path / "beat.json"
    watch(
        lambda: 1,
        WatchConfig(every_seconds=1, heartbeat_path=str(beat), max_cycles=1),
        sleep_fn=lambda _s: None,
    )
    doc = json.loads(beat.read_text())
    assert doc["notified"] is False
    assert "no --notify-command" in (doc["notify_error"] or ""), doc


# --------------------------------------------------------------------------
# The decision itself
# --------------------------------------------------------------------------
def test_should_notify_rules():
    # clean never pages
    assert should_notify(None, "clean", None, 0.0, 300)[0] is False
    assert should_notify("abnormal", "clean", 0.0, 10.0, 300)[0] is False
    # first bad pages
    assert should_notify(None, "abnormal", None, 0.0, 300)[0] is True
    # a different bad pages immediately
    assert should_notify("abnormal", "no_report", 0.0, 1.0, 300)[0] is True
    # the same bad, inside the window, does not
    assert should_notify("abnormal", "abnormal", 0.0, 10.0, 300)[0] is False
    # the same bad, past the window, does
    assert should_notify("abnormal", "abnormal", 0.0, 400.0, 300)[0] is True
    # no renotify configured => announce once
    assert should_notify("abnormal", "abnormal", 0.0, 99999.0, None)[0] is False
