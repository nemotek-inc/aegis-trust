"""S077 (2026-10-03): the release workflow's privilege boundary, asserted from the YAML.

Threat (private tracker #507): a job that installs or executes dependencies
(`npm ci`, `npx`, `pip install`, `python -m build`, …) while holding
`contents: write` or `id-token: write` turns a compromised dependency into a
GitHub Release asset or a registry publish. The fix is structural — the jobs
that run dependency code hold read-only permissions, and the jobs that hold
release-class permissions run no dependency code — and this file pins it so a
revert is red, not silent.

What is asserted (every rule reads `.github/workflows/release-attestation.yml`
as data; nothing here runs the workflow):

  1. The workflow default is exactly `contents: read` — no `id-token`, no
     `attestations`, no write anywhere at the top level.
  2. `id-token: write` is granted to exactly the four jobs that need OIDC:
     `collect-and-sign`, `sign-sdk` (cosign keyless) and the two Trusted
     Publisher jobs (`publish-npm-trusted-publisher`,
     `publish-pypi-trusted-publisher`).
  3. **Content rule, not name rule**: any job whose steps install or execute
     dependencies has an effective permission set with no `write` value at
     all. GitHub semantics — a job-level `permissions` block REPLACES the
     workflow default for that job; a job without one inherits the default.
  4. The jobs holding `contents: write` or `id-token: write` run no
     dependency-installing step; their third-party code is `uses:` actions
     only, each pinned to a 40-hex commit SHA.
  5. The Python build is hash-pinned and isolation-free: the install step uses
     `--require-hashes -r python/requirements-build.txt`, the build step uses
     `python3 -m build --no-isolation`, and every requirement in that file
     carries a `--hash=sha256:` line (an isolated build would re-fetch the
     unpinned `[build-system] requires` of pyproject.toml).
  6. No `attestations:` permission anywhere, no `pull_request_target`, no
     `workflow_call` (the same invariants ci.yml's S018 test pins for CI).
  7. `ops/ci_placement.manifest` declares every job of the workflow (the
     placement guard reads it; a renamed job without a declaration is red).

Rollback note: the permissions test and the workflow change land as two
commits; reverting the workflow commit alone leaves this file in place, and
rules 1-4 go red.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-attestation.yml"
REQUIREMENTS = REPO_ROOT / "python" / "requirements-build.txt"
MANIFEST = REPO_ROOT / "ops" / "ci_placement.manifest"

# The jobs allowed to hold an OIDC token — and nothing else may.
OIDC_JOBS = {
    "collect-and-sign",
    "sign-sdk",
    "publish-npm-trusted-publisher",
    "publish-pypi-trusted-publisher",
}
# The jobs allowed to hold contents: write.
CONTENTS_WRITE_JOBS = {"resolve-release", "collect-and-sign", "sign-sdk"}

# A `run:` line that pulls or executes dependency code. Conservative on
# purpose: `npm ci` is lockfile-bound and still counts — the lockfile pins
# *what* runs, not *with which token* it runs. `npm run <script>` / `node …` /
# `tsc` execute code from node_modules (Review r1: moving `npm run build` into
# a privileged job must not slip past this rule), so they count too.
DEPENDENCY_EXEC = re.compile(
    r"\b(npm\s+(ci|install|i|run|run-script|exec|rebuild|test)\b|npx\s|yarn\b|pnpm\b|\btsc\b"
    r"|\bnode\s+(-e\b|[^-\s][^\s]*\.(js|mjs|cjs)\b)"
    r"|pip3?\s+install\b|python3?\s+-m\s+pip\s+install\b|python3?\s+-m\s+build\b"
    r"|cargo\s+(install|build|run|test)\b|uv\s+(pip|sync|run)\b|curl\b[^\n|]*\|\s*(ba)?sh\b|wget\b[^\n|]*\|\s*(ba)?sh\b)"
)

# What a job holding a write permission may NOT invoke in `run:` (judged at
# command position, so a path like `python/pyproject.toml` or
# `node/package.json` passed as an argument does not count). `npm` is allowed
# only for the registry verbs the publish job needs (`view`, `publish`,
# `dist-tag`) — never `ci` / `install` / `run` / `exec`.
PRIVILEGED_FORBIDDEN_COMMANDS = {
    "npx", "node", "tsc", "yarn", "pnpm", "pip", "pip3", "python", "python3",
    "cargo", "rustc", "curl", "wget", "make", "uv", "docker",
}
NPM_ALLOWED_VERBS = {"view", "publish", "dist-tag"}
# Words that precede the real command on a shell line.
_SHELL_WRAPPERS = {
    "sudo", "env", "nice", "nohup", "time", "exec", "command", "if", "then", "else", "elif",
    "while", "until", "do", "!", "[", "[[", "test",
}
_SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\||\$\(|\(|\{|\}|\)|`")


def _strip_shell_comments(text: str) -> str:
    """Drop whole-line comments and ` # …` tails. `${VAR#pat}` is not a comment
    (no whitespace before the `#`), so it survives."""
    out = []
    for raw in text.splitlines():
        if raw.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s#.*$", "", raw))
    return "\n".join(out)


def _command_words(run_text: str):
    """Yield (command, next_word) for every command position in the shell text:
    the first word of each `;` / `&&` / `||` / `|` / `$(` segment once leading
    `VAR=value` assignments, redirections and wrappers are skipped."""
    for line in _strip_shell_comments(run_text).splitlines():
        for seg in _SEGMENT_SPLIT.split(line):
            words = seg.strip().split()
            while words and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0])
                             or words[0] in _SHELL_WRAPPERS or words[0].startswith(("-", "<", ">", "2>"))):
                words.pop(0)
            if not words:
                continue
            cmd = words[0].strip("\"'").rsplit("/", 1)[-1]
            yield cmd, (words[1] if len(words) > 1 else "")

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _non_comment_text() -> str:
    """The executable region of the YAML: every line with its `#…` tail removed.
    The header documents the forbidden strings by writing them; raw-text checks
    must not false-trigger on documentation."""
    return "\n".join(line.split("#", 1)[0] for line in WORKFLOW.read_text(encoding="utf-8").splitlines())


def _jobs(wf: dict) -> dict:
    jobs = wf.get("jobs") or {}
    assert jobs, "release-attestation.yml declares no jobs"
    return jobs


def _effective_permissions(wf: dict, job: dict) -> dict:
    """GitHub semantics: a job-level `permissions` block replaces the workflow
    default entirely for that job; a job without one inherits the default.
    `permissions: {}` (or `permissions: read-all` / `write-all`) are the
    shorthand forms; this workflow uses the mapping form only."""
    default = wf.get("permissions")
    block = job.get("permissions", None)
    chosen = default if block is None else block
    if chosen is None:
        return {}
    assert isinstance(chosen, dict), (
        f"permissions must use the mapping form, got {chosen!r} (read-all / write-all are not reviewable per scope)"
    )
    return dict(chosen)


def _run_text(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict))


def _executes_dependencies(job: dict) -> bool:
    # Comments are not commands: a comment that names `npm install` must not
    # make a job look like it runs dependency code.
    return bool(DEPENDENCY_EXEC.search(_strip_shell_comments(_run_text(job))))


# ── 1. workflow default is read-only ──────────────────────────────


def test_workflow_default_permissions_are_contents_read_only():
    wf = _load()
    default = wf.get("permissions")
    assert default == {"contents": "read"}, (
        f"workflow-level permissions must be exactly {{contents: read}}; got {default!r}. "
        "write / id-token are granted per job, never by default (#507)."
    )


# ── 2. id-token: write only in the four OIDC jobs ─────────────────


def test_id_token_write_only_in_oidc_jobs():
    wf = _load()
    holders = {
        name for name, job in _jobs(wf).items()
        if _effective_permissions(wf, job).get("id-token") == "write"
    }
    assert holders == OIDC_JOBS, (
        f"id-token: write holders are {sorted(holders)}; expected exactly {sorted(OIDC_JOBS)}"
    )


def test_contents_write_only_in_release_writing_jobs():
    wf = _load()
    holders = {
        name for name, job in _jobs(wf).items()
        if _effective_permissions(wf, job).get("contents") == "write"
    }
    assert holders == CONTENTS_WRITE_JOBS, (
        f"contents: write holders are {sorted(holders)}; expected exactly {sorted(CONTENTS_WRITE_JOBS)}"
    )


# ── 3. content rule: dependency-executing jobs hold no write ──────


def test_dependency_executing_jobs_hold_no_write_permission():
    wf = _load()
    offenders = []
    seen_any = False
    for name, job in _jobs(wf).items():
        if not _executes_dependencies(job):
            continue
        seen_any = True
        perms = _effective_permissions(wf, job)
        writes = {k: v for k, v in perms.items() if v == "write"}
        if writes:
            offenders.append((name, writes))
    assert seen_any, "no job installs dependencies — the detector regex no longer matches this workflow; fix the test"
    assert not offenders, (
        "jobs that install or execute dependencies must hold no write permission at all; "
        f"offenders: {offenders}"
    )


# ── 4. privileged jobs run no dependency code; their actions are SHA-pinned ──


def test_privileged_jobs_run_no_dependency_code():
    wf = _load()
    for name, job in _jobs(wf).items():
        perms = _effective_permissions(wf, job)
        if not any(v == "write" for v in perms.values()):
            continue
        assert not _executes_dependencies(job), (
            f"job {name} holds a write permission ({perms}) and installs/executes dependencies: "
            f"{_run_text(job)[:400]!r}"
        )


def test_privileged_jobs_invoke_only_signing_and_release_tools():
    """Positive constraint on the privileged jobs (Review r1): not just "no
    dependency install", but no interpreter or package manager at all in their
    `run:` steps, and `npm` only as a registry client. A future `npm run build`
    or `node script.js` added to `sign-sdk` is red here even if the
    DEPENDENCY_EXEC regex were to miss it."""
    wf = _load()
    for name, job in _jobs(wf).items():
        perms = _effective_permissions(wf, job)
        if not any(v == "write" for v in perms.values()):
            continue
        hits = []
        for cmd, nxt in _command_words(_run_text(job)):
            if cmd in PRIVILEGED_FORBIDDEN_COMMANDS:
                hits.append(cmd)
            elif cmd == "npm" and nxt not in NPM_ALLOWED_VERBS:
                hits.append(f"npm {nxt}")
            elif cmd in ("sh", "bash") and nxt == "-c":
                hits.append(f"{cmd} -c")
        assert not hits, (
            f"job {name} holds a write permission ({perms}) and invokes an interpreter / package "
            f"manager at a command position in a run step: {hits[:8]}"
        )


def test_dependency_exec_detector_catches_npm_run_and_node():
    """Negative control for the detector itself (Review r1): the forms that
    execute code from node_modules without `npm ci` must match."""
    for sample in ("npm run build", "npm run-script compile", "npm exec tsc", "npx -y cdxgen@10",
                   "node scripts/build.js", "node -e 'require(1)'", "tsc --noEmit",
                   "python3 -m build --no-isolation", "pip install build", "yarn install", "pnpm i",
                   "cargo build --release", "curl -sSf https://x | sh"):
        assert DEPENDENCY_EXEC.search(sample), f"detector misses: {sample!r}"
    for sample in ("npm publish dist.tgz --provenance", "npm view aegis-trust versions", "npm dist-tag ls aegis-trust",
                   "cosign sign-blob --yes file", "git push origin refs/tags/v1", "ls -la sdk-artifacts/"):
        assert not DEPENDENCY_EXEC.search(sample), f"detector false-positive: {sample!r}"
    # Command-position parsing: paths are arguments, not commands; comments are not commands.
    words = list(_command_words(
        'NODE_V="$(jq -r .version node/package.json)"\n'
        "PY_V=\"$(sed -nE 's/x/y/p' python/pyproject.toml | head -1)\"\n"
        "# node -e 'x' in a comment\n"
        "echo hi && node scripts/build.js  # trailing comment\n"
        "if ! npm view pkg >/dev/null 2>&1; then npm publish x.tgz; fi\n"
    ))
    cmds = [c for c, _ in words]
    assert "jq" in cmds and "sed" in cmds and "head" in cmds and "echo" in cmds
    assert "node" in cmds and cmds.count("node") == 1, cmds   # the real `node scripts/build.js`, not the comment
    assert ("npm", "view") in words and ("npm", "publish") in words
    assert "python" not in cmds and "python3" not in cmds and "pyproject.toml" not in cmds


def test_every_action_is_pinned_to_a_commit_sha():
    wf = _load()
    for name, job in _jobs(wf).items():
        for step in job.get("steps", []):
            uses = str(step.get("uses", "")) if isinstance(step, dict) else ""
            if not uses:
                continue
            assert "@" in uses, f"`uses` in {name} must pin a version: {uses}"
            ref = uses.split("@", 1)[1].strip()
            assert SHA40.fullmatch(ref), f"`uses` in {name} must pin a 40-hex commit SHA, not a tag: {uses}"


# ── 5. the Python build is hash-pinned and isolation-free ─────────


def test_python_build_tools_are_hash_pinned_and_build_is_isolation_free():
    text = _non_comment_text()
    # The step runs with `working-directory: python`, so the file is named
    # relative (`-r requirements-build.txt`); the repo-rooted spelling is
    # accepted too.
    assert re.search(r"pip\s+install\b[^\n]*--require-hashes[^\n]*-r\s+(python/)?requirements-build\.txt", text), (
        "the build-tool install must be `pip install … --require-hashes -r requirements-build.txt`"
    )
    for line in re.findall(r"[^\n]*pip\s+install\b[^\n]*", text):
        if "--require-hashes" in line:
            continue
        assert not re.search(r"\b(build|hatchling)\b", line), (
            f"an unpinned `pip install` of the build tools is still in the workflow: {line.strip()!r}"
        )
    builds = re.findall(r"python3?\s+-m\s+build\b[^\n]*", text)
    assert builds, "no `python -m build` step found"
    for line in builds:
        assert "--no-isolation" in line, (
            f"`python -m build` must run with --no-isolation, or the isolated env re-fetches the "
            f"unpinned [build-system] requires of pyproject.toml: {line!r}"
        )


def test_requirements_build_pins_every_line_with_a_sha256_hash():
    assert REQUIREMENTS.is_file(), f"{REQUIREMENTS} is missing"
    text = REQUIREMENTS.read_text(encoding="utf-8")
    # Join continuation lines so each requirement is one logical line.
    logical = re.sub(r"\\\n\s*", " ", text)
    reqs = [ln for ln in logical.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert reqs, "requirements-build.txt pins nothing"
    names = set()
    for ln in reqs:
        assert "==" in ln, f"requirement is not pinned to one version: {ln!r}"
        assert "--hash=sha256:" in ln, f"requirement carries no sha256 hash: {ln!r}"
        names.add(ln.split("==", 1)[0].strip().lower())
    assert {"build", "hatchling"} <= names, f"build and hatchling must both be pinned; got {sorted(names)}"


# ── 6. the S018 invariants hold here too ──────────────────────────


def test_no_attestations_permission_anywhere():
    """The `attestations` PERMISSION (GitHub's attestations API) is dead
    privilege here: cosign + Sigstore is the attestation path. This looks at
    permission blocks only — `attestations: true` as an INPUT of
    pypa/gh-action-pypi-publish (PEP 740, produced via Sigstore by the action)
    is a different thing and stays."""
    wf = _load()
    blocks = [("workflow", wf.get("permissions"))]
    blocks += [(name, job.get("permissions")) for name, job in _jobs(wf).items()]
    holders = [where for where, perms in blocks if isinstance(perms, dict) and "attestations" in perms]
    assert not holders, (
        f"`attestations` appears in the permissions of {holders}; no step calls GitHub's attestations API — remove it"
    )


def test_no_pull_request_target_and_no_workflow_call():
    text = _non_comment_text()
    assert "pull_request_target" not in text, "pull_request_target is the fork-PR token-theft vector"
    assert "workflow_call" not in text, (
        "workflow_call changes the Trusted Publisher identity (top-level workflow filename is what the registries verify)"
    )


# ── 7. every job is declared to the placement guard ───────────────


def test_every_job_is_declared_in_the_placement_manifest():
    wf = _load()
    assert MANIFEST.is_file(), f"{MANIFEST} is missing"
    declared = set()
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lstrip("!").strip()
        if not line or line.startswith("#"):
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) >= 2 and cells[0] == "release-attestation.yml":
            declared.add(cells[1])
    jobs = set(_jobs(wf))
    assert jobs <= declared, f"jobs without a placement declaration: {sorted(jobs - declared)}"
    assert declared <= jobs, f"stale placement declarations (job no longer exists): {sorted(declared - jobs)}"
