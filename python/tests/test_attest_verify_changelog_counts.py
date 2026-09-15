"""Every quantity the CHANGELOGs assert about the attestation verifier must be
countable from the source it describes.

This exists because all four of them were wrong when the feature was first
written. The attestation contract moved three times mid-build; the check list
grew to 17, the corpus to 53 cases, the mutation battery to 15 — and the prose
kept saying 16, 50 and 12/12. Nothing failed, because nothing was counting.

A number in a changelog is a claim about a security verifier's coverage. Either
it is derived from the artifact or it is decoration, so it is derived here.
Both SDKs' CHANGELOGs are checked from this one place: the two files carry the
same paragraphs by design, and a claim that drifts in only one of them is the
same defect.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aegis_trust.attest_verify import ALL_CHECKS

# parents[0] = tests/  parents[1] = python/  parents[2] = repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGELOGS = (
    REPO_ROOT / "python" / "CHANGELOG.md",
    REPO_ROOT / "node" / "CHANGELOG.md",
)
CORPUS = REPO_ROOT / "conformance" / "attest_verify.v0.json"
VECTORS = REPO_ROOT / "conformance" / "ed25519_vectors.v0.json"
BATTERY = REPO_ROOT / "scripts" / "attest_verify_mutation_battery.py"


def _only(pattern: str, text: str, where: Path) -> re.Match[str]:
    """The claim must appear exactly once — two copies drift independently."""
    found = list(re.finditer(pattern, text))
    assert len(found) == 1, (
        f"{where.name}: expected exactly one claim matching {pattern!r}, "
        f"found {len(found)}"
    )
    return found[0]


def _battery_size() -> int:
    src = BATTERY.read_text()
    block = re.search(r"MUTATIONS[^=]*=\s*\[(.*?)\n\]", src, re.S)
    assert block, "MUTATIONS list not found in the mutation battery"
    return len(re.findall(r"\n    [A-Za-z(]", block.group(1)))


@pytest.mark.parametrize("changelog", CHANGELOGS, ids=lambda p: p.parent.name)
def test_changelog_check_count_matches_all_checks(changelog: Path) -> None:
    text = changelog.read_text()
    stated = int(_only(r"- (\d+) checks on the document", text, changelog).group(1))
    assert stated == len(ALL_CHECKS), (
        f"{changelog.name} says {stated} checks; ALL_CHECKS has {len(ALL_CHECKS)}"
    )


@pytest.mark.parametrize("changelog", CHANGELOGS, ids=lambda p: p.parent.name)
def test_changelog_corpus_coverage_count_matches(changelog: Path) -> None:
    """The reject/accept non-vacuity claim names the same number of checks."""
    text = changelog.read_text()
    stated = int(
        _only(r"one of the (\d+) checks has a rejecting case", text, changelog).group(1)
    )
    assert stated == len(ALL_CHECKS), (
        f"{changelog.name} claims coverage of {stated} checks; "
        f"ALL_CHECKS has {len(ALL_CHECKS)}"
    )


@pytest.mark.parametrize("changelog", CHANGELOGS, ids=lambda p: p.parent.name)
def test_changelog_corpus_size_matches(changelog: Path) -> None:
    corpus = json.loads(CORPUS.read_text())
    text = changelog.read_text()
    m = _only(r"\((\d+) cases \+ (\d+) timer cases\)", text, changelog)
    assert (int(m.group(1)), int(m.group(2))) == (
        len(corpus["cases"]),
        len(corpus["timer_cases"]),
    ), (
        f"{changelog.name} says {m.group(1)} cases + {m.group(2)} timer cases; "
        f"the corpus holds {len(corpus['cases'])} + {len(corpus['timer_cases'])}"
    )


@pytest.mark.parametrize("changelog", CHANGELOGS, ids=lambda p: p.parent.name)
def test_changelog_vector_count_matches(changelog: Path) -> None:
    vectors = json.loads(VECTORS.read_text())
    text = changelog.read_text()
    stated = int(_only(r"\((\d+) vectors: the RFC 8032", text, changelog).group(1))
    assert stated == len(vectors["vectors"]), (
        f"{changelog.name} says {stated} vectors; "
        f"the corpus holds {len(vectors['vectors'])}"
    )


@pytest.mark.parametrize("changelog", CHANGELOGS, ids=lambda p: p.parent.name)
def test_changelog_mutation_battery_count_matches(changelog: Path) -> None:
    size = _battery_size()
    text = changelog.read_text()
    m = _only(r"go red \((\d+)/(\d+) caught\)", text, changelog)
    assert m.group(1) == m.group(2), (
        f"{changelog.name} claims {m.group(1)} of {m.group(2)} caught — the "
        "battery is only meaningful if every mutation is caught"
    )
    assert int(m.group(2)) == size, (
        f"{changelog.name} says {m.group(2)} mutations; the battery defines {size}"
    )


def test_both_changelogs_state_the_same_numbers() -> None:
    """The two SDKs ship the same verifier, so the claims must be identical."""
    patterns = (
        r"- (\d+) checks on the document",
        r"one of the (\d+) checks has a rejecting case",
        r"\((\d+) cases \+ (\d+) timer cases\)",
        r"\((\d+) vectors: the RFC 8032",
        r"go red \((\d+)/(\d+) caught\)",
    )
    seen = [[_only(p, c.read_text(), c).groups() for p in patterns] for c in CHANGELOGS]
    assert seen[0] == seen[1], (
        "the python and node CHANGELOGs state different numbers for the same "
        f"verifier: {seen[0]} vs {seen[1]}"
    )
