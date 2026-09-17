"""T-509: CI/CD malicious branch push scenario.

AI Red Team S018 — analysis of CI/CD attack vectors.
These tests verify CI configuration properties at the workflow yaml layer,
not runtime behavior.

Updated 2026-05-21 (Tier 0, T-006c-1c block A,
PR #5) for modern GitHub Actions threat model + top-level workflow path:

  - Path resolution switched from cwd-relative `open(".github/workflows/ci.yml")`
    to repo-root-resolved (`Path(__file__).resolve().parents[3]`). Reason: pytest
    is invoked with `working-directory: python` in the new top-level CI, so the
    old cwd-relative path resolved to `python/.github/workflows/ci.yml` (which
    no longer exists after T-006c-1c block A4 deletes the nested fixture).

  - Trigger model: prior assertions banned `pull_request` outright. That was
    correct when push-only was the safest stance and `pull_request` was
    conflated with `pull_request_target` as a fork-PR attack vector. Modern
    GitHub Actions distinguishes them clearly: `pull_request` runs with an
    auto-restricted token on fork PRs (no secret access, GITHUB_TOKEN
    read-scoped), while `pull_request_target` runs with the full base-repo
    token. The real attack vector is `pull_request_target`; `pull_request`
    alone is safe for block A's no-secret read-only CI.

    Updated assertions raise the security bar by:
      - forbidding `pull_request_target` explicitly (the real attack)
      - forbidding `id-token: write` permission anywhere (no OIDC, no signing)
      - forbidding any custom secret reference (PYPI_TOKEN, NPM_TOKEN, etc.)
      - asserting the `ci-gate` aggregator exists (branch-protection regression
        guard)

  - Self-hosted runner: block A uses `ubuntu-latest` (GitHub-hosted ephemeral),
    which eliminates the original self-hosted-fork-PR code-execution risk.
    If a future PR switches to `dedicated-runner` self-hosted, the
    fork-PR-runs-as-runner-user risk re-enters and operator MUST enable
    Settings → Actions → "Require approval for all outside collaborators".
    That switch should also re-add a workflow-level fork guard or extend
    these tests.
"""

import re
from pathlib import Path

import yaml


# ── Shared path helpers ────────────────────────────────────────────
# parents[0] = adversarial/  parents[1] = tests/  parents[2] = python/  parents[3] = repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _load_ci() -> dict:
    """Parse the top-level ci.yml as a dict.

    Note: PyYAML 1.1 normalizes the unquoted key `on:` to boolean `True`.
    Callers that look up triggers use the `ci.get("on", ci.get(True, {}))`
    fallback below.
    """
    return yaml.safe_load(CI_YML.read_text())


def _read_ci_text() -> str:
    """Raw text read of ci.yml for substring / regex checks."""
    return CI_YML.read_text()


def _read_ci_non_comment() -> str:
    """Read ci.yml with `#`-prefixed comment regions stripped per line.

    Use this for substring / regex checks that should match only the
    executable workflow content. The header comment block in `ci.yml`
    documents safety invariants by literally writing the forbidden
    strings (e.g., `# id-token: write`, `# secrets.PYPI_TOKEN`); raw-
    text checks against those documentation strings would false-trigger.
    """
    return "\n".join(line.split("#", 1)[0] for line in CI_YML.read_text().splitlines())


def _triggers(ci: dict) -> dict:
    """Return the `on:` block, accounting for PyYAML 1.1 `True`-key fallback."""
    return ci.get("on", ci.get(True, {}))


# ── Attack 1: Verify `pull_request_target` (the real fork-PR attack) is not used ─


def test_ci_does_not_use_pull_request_target():
    """`pull_request_target` runs with base-repo token (secret access);
    `pull_request` does NOT (GitHub auto-restricts the token on fork PRs).
    Block A uses `pull_request` and `push`. `pull_request_target` is the
    real attack vector and must never be present.
    """
    ci = _load_ci()
    triggers = _triggers(ci)
    assert "pull_request_target" not in triggers, (
        "CI must NOT use `pull_request_target` (fork-PR token-theft attack vector)"
    )
    assert "push" in triggers, "CI must run on `push` to protected branches"


def test_ci_no_pull_request_target_anywhere():
    """Stronger guard: `pull_request_target` must not appear in any
    executable region of the workflow yaml — not as a trigger, not in
    `if:` conditions, not inside `uses:` references.

    Comments are stripped before checking so a documentation comment
    that mentions `pull_request_target` (e.g., "do not use") is allowed.
    """
    assert "pull_request_target" not in _read_ci_non_comment(), (
        "Executable region of CI workflow must not mention pull_request_target"
    )


# ── Attack 2: Verify branch pattern restrictions ─────────────────


def test_ci_branch_restrictions():
    """CI must only run on controlled branches, not arbitrary patterns."""
    ci = _load_ci()
    triggers = _triggers(ci)
    push_config = triggers.get("push", {})
    branches = push_config.get("branches", [])

    assert len(branches) > 0, "CI push trigger must have branch restrictions"

    for b in branches:
        assert b != "*", "CI must not trigger on all branches"
        assert b != "**", "CI must not trigger on all branches"


# ── Attack 3: Verify minimal permissions ─────────────────────────


def test_ci_minimal_permissions():
    """CI must use minimal permissions (contents: read)."""
    ci = _load_ci()
    perms = ci.get("permissions", {})
    assert perms.get("contents") == "read", (
        "CI permissions must be contents: read (minimal)"
    )

    # Must not have any write permissions.
    for key, value in perms.items():
        assert value != "write", f"CI must not have {key}: write permission"


# ── Attack 4: Verify checkout (and every third-party action) uses pinned SHA ─


def test_ci_checkout_pinned_sha():
    """Every third-party action `uses:` reference must pin a full 40-char
    SHA. Mutable tags (`@v4`) are a supply-chain attack surface.
    """
    ci = _load_ci()
    for job_name, job in ci.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if not uses:
                continue
            # First-party `actions/checkout` is the canonical example, but
            # the rule applies to every third-party `uses:`.
            assert "@" in uses, f"`uses` in {job_name} must pin a version: {uses}"
            ref = uses.split("@", 1)[1].strip()
            # 40-hex SHA only. Tag-style refs ('v4', 'main', etc.) fail.
            assert len(ref) >= 40 and re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"`uses` in {job_name} must pin a full 40-char SHA, not a tag: {uses}"
            )


# ── Attack 5: Verify no `id-token: write` permission anywhere ───


def test_ci_no_id_token_write():
    """Block A has no OIDC / cosign / signing path. `id-token: write`
    grants ambient OIDC tokens for cloud auth; any enabling is a
    release-class change requiring Block B authorization.

    Regex `id-token:\\s*write` covers both flow-style (`id-token: write`)
    and block-style (`id-token:\\n  write`) regardless of indentation.

    Comments are stripped first so a documentation comment that names
    `id-token: write` as forbidden (e.g., "do not grant id-token: write")
    does not false-trigger.
    """
    assert not re.search(r"id-token:\s*write", _read_ci_non_comment()), (
        "CI must NOT grant `id-token: write` (no OIDC / signing path in Block A)"
    )


# ── Attack 6: Verify no custom secret references anywhere ──────


def test_ci_no_secrets_in_env():
    """Block A is read-only, no-publish CI. There must be NO custom
    secret references — no PYPI_TOKEN, NPM_TOKEN, COSIGN_*, or any
    other `secrets.X`. The implicit `GITHUB_TOKEN` is permission-scoped
    by the top-level `contents: read` block; it does not need an
    explicit `secrets.GITHUB_TOKEN` reference and is forbidden along
    with everything else.

    Comments are stripped first so documentation that names forbidden
    tokens (e.g., "Block A has no PYPI_TOKEN") does not false-trigger.
    """
    non_comment = _read_ci_non_comment()

    # Absolute ban on `secrets.` references.
    assert "secrets." not in non_comment, (
        "CI must NOT reference any secret (Block A is read-only, no-publish)"
    )

    # Defense-in-depth: spell out the specific tokens we never want.
    for token in (
        "secrets.PYPI_TOKEN",
        "secrets.NPM_TOKEN",
        "secrets.COSIGN_",
        "secrets.GITHUB_TOKEN",
    ):
        assert token not in non_comment, (
            f"CI must NOT reference {token} (subsumed by absolute `secrets.` ban; "
            "spelled out for regression-test clarity)"
        )


# ── Attack 7: Verify no expression injection from untrusted contexts ─


def test_ci_no_expression_injection():
    """CI must not use untrusted input in `run:` steps without sanitization.
    `github.event.pull_request.title`, etc., are common injection vectors.
    """
    content = _read_ci_text()
    dangerous_contexts = [
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.comment.body",
        "github.event.head_commit.message",
    ]
    for ctx in dangerous_contexts:
        assert ctx not in content, (
            f"CI uses untrusted context '{ctx}' — potential expression injection"
        )


# ── Attack 8: Verify ci-gate aggregator exists for branch protection ──


def test_ci_uses_aggregator_job():
    """Branch protection's required-status-check name should be the single
    `ci-gate` aggregator, not matrix-suffixed names (`python-test (3.12)`).
    This test guards the design: `ci-gate` job exists with `needs:` covering
    all CI jobs (regression for §4.5 of the design note).
    """
    ci = _load_ci()
    jobs = ci.get("jobs", {})
    assert "ci-gate" in jobs, (
        "CI must define `ci-gate` aggregator job for branch protection"
    )

    ci_gate = jobs["ci-gate"]
    needs = ci_gate.get("needs", [])
    # `needs:` may be a list of strings or a single string; normalize.
    if isinstance(needs, str):
        needs = [needs]

    expected_upstream = {
        "python-test",
        "node-test",
        "gitleaks",
        "drift-check",
        "public-surface",
    }
    assert set(needs) == expected_upstream, (
        f"ci-gate.needs must be exactly {sorted(expected_upstream)}; got {sorted(needs)}"
    )


# ── Attack 9: Verify the node job installs the LOCKED tree and nothing else ──


def test_ci_node_install_is_lockfile_exact():
    """`npm ci` must be the whole install; no `npm install` may follow it.

    This is the node-side twin of audit.yml's invariant 7, and it exists
    because that invariant was silently broken here for months. The node-test
    job used to append

        npm install --no-save --no-package-lock @rollup/rollup-linux-x64-gnu

    as a workaround for npm bug #4828. `--no-package-lock` makes npm re-resolve
    from the ranges in `package.json` instead of the lockfile, and it did: the
    Node 18 cell reported "added 4 packages, removed 6 packages, changed 20
    packages" immediately after a clean `npm ci`. The suite therefore passed on
    a dependency set nobody had committed, and the real incompatibility
    underneath it (vitest 4 / vite 8 require node >=20.19) stayed hidden until
    the line was removed. On Node 22 that same line crashed npm 10.9.x's
    arborist outright, which is what kept `ci-gate` red from 2026-09-05.

    Testing a tree CI resolved on the fly is the same class of defect as
    auditing one: whatever turns green, it is not the artifact that ships.
    """
    ci = _load_ci()
    steps = ci["jobs"]["node-test"]["steps"]
    install_steps = [s for s in steps if "npm ci" in str(s.get("run", ""))]
    assert install_steps, "node-test must install dependencies with `npm ci`"

    for step in install_steps:
        run = str(step["run"])
        commands = [
            line.strip()
            for line in run.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert commands == ["npm ci"], (
            "the node-test install step must run `npm ci` and nothing else — "
            f"anything installed on top of the lockfile is untested drift; got {commands}"
        )
        assert "--no-package-lock" not in run, (
            "`--no-package-lock` re-resolves from package.json ranges and "
            "silently replaces locked versions"
        )
