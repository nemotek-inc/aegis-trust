"""INV-7, SDK form — no single call reaches an irreversible transition (Python).

INV-7's SDK obligation is written against REACHABLE EFFECT: what the SDK can
CAUSE, not what it contains. An earlier draft of this suite asserted "the SDK
contains no destructive operations", reached by grepping for os.remove, rmtree,
unlink and rmSync. That found nothing and was reported as satisfaction. It was
wrong -- it had only asked about local filesystem deletion, never about what the
SDK could reach over the wire. The generated gateway client ships in the wheel
and carries POST /capsules/{id}/destroy, whose own docstring reads "Irreversibly
destroy a capsule".

The contrast this guard exists to hold in place: capsule RECALL is a deliberate
two-step flow (request, then confirm) so no single call completes it. Capsule
DESTROY, the one operation that cannot be undone, is a single call with no
confirmation step. The two-step pattern this codebase already knows how to build
is applied to the reversible operation and not to the irreversible one -- D8's
shape restated at the SDK layer.

This guard does NOT fix that. Fixing it means changing a shipped surface, which
is a product decision. What it does is make the count machine-visible and stop a
second one appearing unnoticed.

Mirror: node/tests/irreversibleOps.test.ts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "conformance" / "irreversible_ops.v0.json"
API_DIR = (
    REPO
    / "python"
    / "src"
    / "aegis_trust"
    / "_generated"
    / "aegis_gateway_rest_api_client"
    / "api"
)

_REG = json.loads(REGISTRY.read_text())
assert _REG["version"] == 0
OPERATIONS = _REG["operations"]
UNGATED = _REG["ungated_single_call"]
MARKER = _REG["irreversibility_marker"]
CLASSES = set(_REG["classes"])


def _shipped_ops() -> dict[str, str]:
    """{operation name: first docstring line}, read from the shipped source."""
    out: dict[str, str] = {}
    for f in sorted(API_DIR.rglob("*.py")):
        if f.name == "__init__.py":
            continue
        src = f.read_text(encoding="utf-8")
        m = re.search(r'def sync_detailed\(.*?"""(.+?)$', src, re.S)
        out[f.stem] = m.group(1).strip().splitlines()[0].strip() if m else ""
    return out


def test_scan_is_non_vacuous() -> None:
    """A guard that finds no operations must fail, not pass."""
    ops = _shipped_ops()
    assert len(ops) >= 20, f"only {len(ops)} operations found — the scan is broken"
    assert "destroy_capsule" in ops, (
        "destroy_capsule not detected — the scan is broken, and this is the exact "
        "operation the guard exists for"
    )
    assert UNGATED, "ungated_single_call is empty — verify before celebrating"


def test_every_shipped_operation_is_classified() -> None:
    """A new operation cannot ship without someone deciding if it is irreversible."""
    shipped = set(_shipped_ops())
    unclassified = shipped - set(OPERATIONS)
    assert not unclassified, (
        f"shipped but unclassified operations: {sorted(unclassified)}. "
        "Classify each as irreversible / two_step / reversible."
    )
    stale = set(OPERATIONS) - shipped
    assert not stale, f"classified but no longer shipped: {sorted(stale)}"


def test_classification_values_are_known() -> None:
    for name, op in OPERATIONS.items():
        assert op["class"] in CLASSES, f"{name}: unknown class {op['class']!r}"


def test_docstring_irreversibility_forces_classification() -> None:
    """Classification cannot drift from what the generator actually emitted.

    If the API grows another operation that declares irreversibility, marking it
    'reversible' in the registry will not make it so.
    """
    for name, summary in _shipped_ops().items():
        if MARKER.lower() in summary.lower():
            assert OPERATIONS[name]["class"] == "irreversible", (
                f"{name} declares itself irreversible ({summary!r}) but is "
                f"classified {OPERATIONS[name]['class']!r}"
            )


def test_no_irreversible_operation_is_top_level_public_api() -> None:
    """True today. Asserting it stops it silently becoming false.

    The generated subtree ships in the wheel, so these operations are importable
    by an installed caller — but they are not surfaced from the package root, and
    re-exporting one would put an irreversible call one import away from every
    user of the SDK.
    """
    roots = [
        REPO / "python" / "src" / "aegis_trust" / "__init__.py",
        REPO / "python" / "src" / "aegis_trust" / "client.py",
    ]
    irreversible = [n for n, op in OPERATIONS.items() if op["class"] == "irreversible"]
    assert irreversible, "no irreversible operation known — the registry looks wrong"
    for root in roots:
        text = root.read_text(encoding="utf-8")
        for name in irreversible:
            assert name not in text, (
                f"{root.name} references {name}: an irreversible operation must not "
                "be reachable from the package's top-level surface"
            )


def test_ungated_irreversible_set_does_not_grow() -> None:
    """The load-bearing assertion. This set may shrink freely; it may not grow.

    Every irreversible operation that is neither part of a multi-call flow nor
    behind an opt-in gate has to be listed in `ungated_single_call` with its
    reachability and remediation recorded. Adding another one fails here.
    """
    irreversible = {n for n, op in OPERATIONS.items() if op["class"] == "irreversible"}
    two_step = {n for n, op in OPERATIONS.items() if op["class"] == "two_step"}
    gated = {
        n for n, e in UNGATED.items() if e.get("gate") or e.get("confirmation_step")
    }

    exposed = irreversible - two_step - gated
    undeclared = exposed - set(UNGATED)
    assert not undeclared, (
        f"irreversible single-call operations not declared in ungated_single_call: "
        f"{sorted(undeclared)}. One call from the shipped package would reach an "
        "irreversible transition with nothing recording that it can."
    )
    for name, entry in UNGATED.items():
        assert name in irreversible, (
            f"{name}: listed as ungated but not classified irreversible"
        )
        assert entry.get("note"), (
            f"{name}: ungated with no note explaining the exposure"
        )


@pytest.mark.parametrize("name", sorted(UNGATED))
def test_ungated_entry_records_its_remediation_state(name: str) -> None:
    """An ungated exposure must say what is missing, not merely that it exists."""
    entry = UNGATED[name]
    for field in ("gate", "confirmation_step", "test"):
        assert field in entry, f"{name}: missing {field} field"
    assert entry.get("reachable_from"), f"{name}: reachability not recorded"


def test_recall_is_two_step_and_destroy_is_not() -> None:
    """Pins the contrast, so a regression in either direction is visible.

    If destroy ever gains a confirmation step this fails and the registry is
    updated to record the improvement. If recall ever loses one, it fails for the
    reason that matters.
    """
    assert OPERATIONS["recall_capsule_request"]["class"] == "two_step"
    assert OPERATIONS["recall_capsule_confirm"]["class"] == "two_step"
    assert OPERATIONS["destroy_capsule"]["class"] == "irreversible"
    assert "destroy_capsule" in UNGATED, (
        "destroy_capsule is no longer recorded as ungated — if it gained a gate, "
        "move it out deliberately and record what gates it"
    )


def test_authorization_is_not_recorded_as_a_gate() -> None:
    """Recording a true fact must not close the hole in the guard's view.

    `gated` is computed as "entry has a truthy `gate` or `confirmation_step`",
    and `exposed` subtracts it. So writing the server-side authorization
    (authenticated + Role::Admin, 403 otherwise) into `gate` would move
    `destroy_capsule` out of the exposed set — and INV-7 would look upheld
    without anything having changed.

    It has not changed. INV-7's statement is "no single call causes an
    irreversible transition; irreversible destruction requires explicit opt-in".
    Authorization is not an opt-in: an Admin who mistypes a capsule id still
    destroys it in one call. The authorization is recorded in its own field and
    this pins that it stayed there.

    WHEN THIS FAILS: someone has added a real opt-in or confirmation step. Good
    — update this test to say which, rather than deleting it.
    """
    entry = UNGATED["destroy_capsule"]
    assert entry.get("server_side_authorization"), (
        "the measured authorization is no longer recorded; it is the reason the "
        "hole is narrower than 'any installed package can destroy'"
    )
    assert not entry.get("gate"), (
        "authorization was written into `gate`, which removes destroy_capsule "
        "from the exposed set. INV-7 requires an explicit opt-in, not a role check"
    )
    assert not entry.get("confirmation_step"), (
        "a confirmation step is claimed but INV-7 enforcement still reads 'none'"
    )

    irreversible = {n for n, op in OPERATIONS.items() if op["class"] == "irreversible"}
    two_step = {n for n, op in OPERATIONS.items() if op["class"] == "two_step"}
    gated = {
        n for n, e in UNGATED.items() if e.get("gate") or e.get("confirmation_step")
    }
    assert "destroy_capsule" in (irreversible - two_step - gated), (
        "destroy_capsule is no longer counted as an exposed irreversible "
        "single call. If that is because it was genuinely gated, move INV-7's "
        "sdk enforcement off 'none' in the same change"
    )
