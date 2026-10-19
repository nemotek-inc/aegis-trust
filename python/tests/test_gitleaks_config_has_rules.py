"""The secret scan must be able to find a secret.

**aegis-trust is a PUBLIC repository.** The CI ``gitleaks`` job is the machine
that stops a credential from being published with a push.

WHY THIS EXISTS. ``.gitleaks.toml`` used to be an ``[allowlist]`` and nothing
else: no ``[extend] useDefault = true``, no ``[[rules]]``. gitleaks v8 builds
its rule set from the config it is given, so that config loaded ZERO rules and
the job passed on every history it was shown. Its green meant nothing. With the
default rules switched back on, a full-history scan reported four hits — all
synthetic leak-test fixtures, now allowlisted by path with a reason.

A scanner with no rules reports the same thing as a scanner over a clean tree,
so this file checks the scanner, not the tree:

1. the config, parsed as TOML, extends the default rules or declares at least
   one rule of its own (runs in every Python cell, no binary needed);
2. when a ``gitleaks`` binary is on PATH, the config detects a GitHub-token
   shape — the same positive control the CI job runs before its history scan —
   and the allowlist-only shape it replaced does not (the red, observed).

The token is generated at run time and passed on stdin only. This file never
holds a well-formed token: the repository's own scans read every tracked file.

Mirror of the CI step "gitleaks positive control (the config must detect)".
"""

from __future__ import annotations

import secrets
import shutil
import string
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — pytest itself depends on tomli there
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / ".gitleaks.toml"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"

#: gitleaks exits 1 on a crash or a config error as well as on a finding, so the
#: control asks for a distinct status and accepts only that one (as CI does).
FOUND_EXIT = 42

#: The shape the old config had: an allowlist and nothing that loads a rule.
ALLOWLIST_ONLY = """\
[allowlist]
description = "allowlist only"
paths = ['''(.*/)?tests/never_matches\\.py$''']
"""


def _loads_a_rule(cfg: dict[str, Any]) -> bool:
    """Does this parsed config give gitleaks at least one rule to apply?"""
    extend = cfg.get("extend")
    if isinstance(extend, dict) and extend.get("useDefault") is True:
        return True
    rules = cfg.get("rules")
    return isinstance(rules, list) and len(rules) > 0


def _synthetic_github_token() -> str:
    """A GitHub-token SHAPE that was never anyone's token, built in memory."""
    alphabet = string.ascii_letters + string.digits
    return "ghp" + "_" + "".join(secrets.choice(alphabet) for _ in range(36))


def _gitleaks_stdin(
    binary: str, config: Path, data: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            binary,
            "stdin",
            "--config",
            str(config),
            "--redact",
            "--no-banner",
            "--exit-code",
            str(FOUND_EXIT),
        ],
        input=data + "\n",
        capture_output=True,
        text=True,
        timeout=60,
    )


# ---------------------------------------------------------------------------
# The config, read as data (no binary needed).
# ---------------------------------------------------------------------------


def test_the_config_loads_at_least_one_rule() -> None:
    cfg = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    assert _loads_a_rule(cfg), (
        ".gitleaks.toml loads no rule: without `[extend] useDefault = true` or a "
        "[[rules]] table, gitleaks detects nothing and the CI scan passes on any "
        "history, including one that holds a real secret."
    )


def test_the_rule_check_rejects_an_allowlist_only_config() -> None:
    """The failing direction of the check above, observed rather than assumed."""
    assert not _loads_a_rule(tomllib.loads(ALLOWLIST_ONLY))
    assert not _loads_a_rule(tomllib.loads("[extend]\nuseDefault = false\n"))
    assert not _loads_a_rule(tomllib.loads("rules = []\n"))
    assert _loads_a_rule(tomllib.loads("[extend]\nuseDefault = true\n"))


def test_ci_proves_the_scanner_detects_before_the_history_scan() -> None:
    """The control only protects the scan if it runs first, in the same job,
    against the same config."""
    ci = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    steps = ci["jobs"]["gitleaks"]["steps"]
    runs = [str(step.get("run", "")) for step in steps]
    control = [i for i, run in enumerate(runs) if "gitleaks stdin" in run]
    scan = [
        i
        for i, run in enumerate(runs)
        if "gitleaks detect" in run or "gitleaks git" in run
    ]
    assert control, "the gitleaks job has no positive control (`gitleaks stdin`)"
    assert scan, "the gitleaks job has no history scan"
    assert max(control) < min(scan), (
        "the positive control must run before the history scan"
    )
    control_run = runs[control[0]]
    assert "--config .gitleaks.toml" in control_run
    assert f"--exit-code {FOUND_EXIT}" in control_run
    assert f"-ne {FOUND_EXIT}" in control_run


# ---------------------------------------------------------------------------
# The positive control itself (only where a gitleaks binary is installed).
# ---------------------------------------------------------------------------

_GITLEAKS = shutil.which("gitleaks")
_needs_gitleaks = pytest.mark.skipif(_GITLEAKS is None, reason="gitleaks not on PATH")


@_needs_gitleaks
def test_the_config_detects_a_synthetic_github_token() -> None:
    assert _GITLEAKS is not None
    proc = _gitleaks_stdin(_GITLEAKS, CONFIG, _synthetic_github_token())
    # --redact keeps the token out of gitleaks' output, so it is safe to show.
    assert proc.returncode == FOUND_EXIT, (
        f".gitleaks.toml did not detect a synthetic GitHub token "
        f"(exit {proc.returncode}, expected {FOUND_EXIT}): {proc.stderr[-500:]}"
    )


@_needs_gitleaks
def test_the_control_is_red_on_an_allowlist_only_config(tmp_path: Path) -> None:
    """The same control against the shape this repo's config used to have finds
    nothing — which is exactly what the CI step stops on."""
    assert _GITLEAKS is not None
    vacuous = tmp_path / "allowlist_only.toml"
    vacuous.write_text(ALLOWLIST_ONLY, encoding="utf-8")
    proc = _gitleaks_stdin(_GITLEAKS, vacuous, _synthetic_github_token())
    assert proc.returncode == 0, (
        f"an allowlist-only config was expected to load no rule and find nothing "
        f"(exit {proc.returncode}): {proc.stderr[-500:]}"
    )
