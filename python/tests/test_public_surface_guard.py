"""Controls for `scripts/public_surface_guard.py`.

Why this file exists
--------------------
On 2026-09-16 content belonging to the private core repository reached this
public repository. It was caught by a human, not by a machine. The guard is the
machine; this file is the proof that the machine actually fires.

A guard with no positive control is indistinguishable from a guard that returns
success unconditionally. Every rule below is asserted twice: once with content
that MUST be rejected, once with content that MUST pass. Two further controls
cover the two ways this particular guard could fail silently:

  * it must never print the matched content (public CI logs are public — echoing
    a leaked value there re-publishes it), and
  * it must be wired into `ci-gate`, because a guard no job runs is not a guard.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# parents[0] = tests/  parents[1] = python/  parents[2] = repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "public_surface_guard.py"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"

MARKERS_REL = "scripts/private_markers.sha256"
ALLOW_REL = "scripts/public_surface_allow.txt"

# The vocabulary file's header carries both the generation stamp and
# `max_segments`, the single definition point for how wide the guard joins
# adjacent word segments when matching. Both are required; see the R4 controls.
MARKER_HEADER = "# max_segments: 3\n# generated: 2026-09-17T00:00:00Z\n"


def _norm(token: str) -> str:
    """Same normalization the guard applies before hashing."""
    return "".join(ch for ch in token.lower() if ch.isalnum())


def _digest(token: str) -> str:
    return hashlib.sha256(_norm(token).encode()).hexdigest()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A minimal tracked repo the guard can scan.

    It carries one Python source file, so `python` is one of "this repo's
    languages" and `rust` is not — which is what R2 keys off.
    """
    repo = tmp_path / "surface"
    (repo / "src").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "src" / "thing.py").write_text("VALUE = 1\n")
    (repo / MARKERS_REL).write_text(MARKER_HEADER)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "controls@example.invalid")
    _git(repo, "config", "user.name", "controls")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    return repo


def run_guard(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GUARD), "--repo", str(repo)],
        capture_output=True, text=True, check=False,
    )


def commit_file(repo: Path, rel: str, body: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"add {rel}")


# ── Baseline: a clean repo passes ──────────────────────────────────


def test_clean_repo_passes(fake_repo: Path) -> None:
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout + result.stderr


# ── R1: a reference to a source path this repo does not contain ────


def test_r1_rejects_path_from_another_repo(fake_repo: Path) -> None:
    """The exact shape of the 2026-09-16 disclosure: prose naming a source
    file that lives in a different repository."""
    commit_file(fake_repo, "docs/note.md",
                "See engine/other_crate/src/backends/mod.rs for the wrapper.\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1, result.stdout
    assert "R1" in result.stdout
    assert "docs/note.md" in result.stdout


def test_r1_accepts_reference_to_a_file_that_exists(fake_repo: Path) -> None:
    commit_file(fake_repo, "docs/note.md", "See src/thing.py for the value.\n")
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout


def test_r1_accepts_relative_module_specifiers(fake_repo: Path) -> None:
    """`../src/index.js` is a module resolution target, not a repo path.
    Measured against the real tree: treating these as findings produced 100+
    false positives, which is the same as having no guard."""
    commit_file(fake_repo, "src/app.ts",
                'import { shield } from "../src/index.js";\n')
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout


def test_r1_accepts_shell_variable_expansion(fake_repo: Path) -> None:
    commit_file(fake_repo, "scripts/run.sh",
                'hash_file "$REPO_ROOT/.github/workflows/thing.yml"\n')
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout


def test_r1_allowlist_entry_suppresses_the_finding(fake_repo: Path) -> None:
    commit_file(fake_repo, "docs/note.md",
                "See engine/other_crate/src/backends/mod.rs for the wrapper.\n")
    assert run_guard(fake_repo).returncode == 1
    commit_file(fake_repo, ALLOW_REL,
                "docs/note.md | R1 | negative control, deliberately absent path\n")
    assert run_guard(fake_repo).returncode == 0


def test_allowlist_entry_without_a_reason_is_not_a_declaration(fake_repo: Path) -> None:
    """An exception anyone can add without writing down why is not a control."""
    commit_file(fake_repo, ALLOW_REL, "docs/note.md | R1 |\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1
    assert "理由" in result.stdout


# ── R2: a code fence in a language this repo does not contain ──────


def test_r2_rejects_a_fence_in_a_foreign_language(fake_repo: Path) -> None:
    commit_file(fake_repo, "docs/note.md",
                "Example:\n\n```rust\npub trait Wrapper {}\n```\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1, result.stdout
    assert "R2" in result.stdout


def test_r2_accepts_a_fence_in_a_language_this_repo_has(fake_repo: Path) -> None:
    commit_file(fake_repo, "docs/note.md",
                "Example:\n\n```python\nVALUE = 1\n```\n")
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout


def test_r2_accepts_language_neutral_fences(fake_repo: Path) -> None:
    commit_file(fake_repo, "docs/note.md",
                "Output:\n\n```text\nOK\n```\n\n```\nbare\n```\n")
    result = run_guard(fake_repo)
    assert result.returncode == 0, result.stdout


# ── R3: the hashed vocabulary ──────────────────────────────────────


def test_r3_rejects_a_token_whose_hash_is_declared(fake_repo: Path) -> None:
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + _digest("clandestine-widget") + "\n")
    commit_file(fake_repo, "docs/note.md", "The clandestine_widget ships next year.\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1, result.stdout
    assert "R3" in result.stdout


def test_r3_normalization_survives_respelling(fake_repo: Path) -> None:
    """Changing punctuation or case must not walk past the rule."""
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + _digest("clandestine-widget") + "\n")
    commit_file(fake_repo, "docs/note.md", "The ClandestineWidget ships next year.\n")
    assert run_guard(fake_repo).returncode == 1


def test_r3_matches_a_term_that_carries_a_suffix(fake_repo: Path) -> None:
    """Regression, found by running the private-side positive control against
    the tree as it stood while the disclosure was live: the first version took
    whole tokens, so a term appearing as `<term>.rs:<symbol>` normalized to a
    different string and the scan came back clean on content that was in fact
    leaking. Matching now joins adjacent segments instead."""
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + _digest("clandestine-widget") + "\n")
    commit_file(fake_repo, "docs/note.md",
                "Mirrors other_crate/tests/clandestine_widget.rs:setup so that\n")
    assert run_guard(fake_repo).returncode == 1


def test_r3_accepts_unrelated_tokens(fake_repo: Path) -> None:
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + _digest("clandestine-widget") + "\n")
    commit_file(fake_repo, "docs/note.md", "The public widget ships next year.\n")
    assert run_guard(fake_repo).returncode == 0


# ── R4: the guard refuses to be green when it could not measure ────


def test_r4_missing_vocabulary_file_fails(fake_repo: Path) -> None:
    (fake_repo / MARKERS_REL).unlink()
    _git(fake_repo, "add", "-A")
    _git(fake_repo, "commit", "-qm", "drop markers")
    result = run_guard(fake_repo)
    assert result.returncode == 1
    assert "測れなかった" in result.stdout


def test_r4_vocabulary_without_a_generation_stamp_fails(fake_repo: Path) -> None:
    commit_file(fake_repo, MARKERS_REL, "# no stamp here\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1
    assert "測れなかった" in result.stdout


def test_r4_vocabulary_without_max_segments_fails(fake_repo: Path) -> None:
    """Without it the guard would have to guess how wide to join segments, and
    a term that stopped matching would go unnoticed."""
    commit_file(fake_repo, MARKERS_REL, "# generated: 2026-09-17T00:00:00Z\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1
    assert "測れなかった" in result.stdout


def test_r4_plaintext_in_the_vocabulary_file_fails(fake_repo: Path) -> None:
    """The vocabulary file lives in a public repo. A plaintext entry there
    would make the guard itself the disclosure."""
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + "clandestine-widget\n")
    result = run_guard(fake_repo)
    assert result.returncode == 1
    assert "測れなかった" in result.stdout


# ── The guard must not re-publish what it finds ────────────────────


def test_guard_never_prints_the_matched_content(fake_repo: Path) -> None:
    """Public CI logs are public. Printing the hit would disclose it again —
    for R3 that is the private token itself."""
    secret_path = "engine/other_crate/src/backends/mod.rs"
    commit_file(fake_repo, MARKERS_REL, MARKER_HEADER + _digest("clandestine-widget") + "\n")
    commit_file(
        fake_repo, "docs/note.md",
        f"See {secret_path}.\nThe clandestine_widget ships.\n\n```rust\nfn x() {{}}\n```\n",
    )
    result = run_guard(fake_repo)
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert secret_path not in combined
    assert "clandestine" not in combined.lower()
    assert "backends" not in combined
    # It must still say enough to find the line by hand.
    assert "docs/note.md" in combined


# ── Wiring: a guard that no job runs is not a guard ────────────────


def _load_ci() -> dict:
    return yaml.safe_load(CI_YML.read_text())


def test_ci_defines_the_public_surface_job() -> None:
    jobs = _load_ci().get("jobs", {})
    assert "public-surface" in jobs, (
        "ci.yml must define a `public-surface` job — the guard only exists "
        "where something runs it"
    )
    steps = jobs["public-surface"].get("steps", [])
    runs = " ".join(str(step.get("run", "")) for step in steps)
    assert "scripts/public_surface_guard.py" in runs, (
        "the `public-surface` job must actually invoke the guard"
    )


def test_ci_gate_requires_the_public_surface_job() -> None:
    """Branch protection keys off `ci-gate`. A job outside its `needs:` can
    fail without blocking the merge."""
    ci_gate = _load_ci()["jobs"]["ci-gate"]
    needs = ci_gate.get("needs", [])
    if isinstance(needs, str):
        needs = [needs]
    assert "public-surface" in needs, (
        "ci-gate.needs must include `public-surface`; otherwise the guard can "
        "fail while the merge stays green"
    )


def test_repo_vocabulary_file_is_present_and_hashed() -> None:
    """The shipped vocabulary file must never contain plaintext."""
    body = (REPO_ROOT / MARKERS_REL).read_text()
    assert "# generated:" in body
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert len(stripped) == 64 and all(c in "0123456789abcdef" for c in stripped), (
            "private_markers.sha256 must contain only sha256 digests — a "
            "plaintext entry in a public repo is itself the disclosure"
        )
