"""conformance/attest_verify.v0.json, run through the shipped verifier (Python).

The corpus is the single place where "this attestation is verified" is defined.
Both SDKs read it, so a change that makes one of them describe an attestation
differently from the other fails here or in
node/tests/attestVerifyCorpus.test.ts.

This runner feeds the corpus to the real ``verify_attestation`` — it does not
rebuild a verdict of its own and check its own reconstruction. That tautology
has shipped in this repo before (the Node byte anchor for the idempotency digest
hashed its own rebuild and never called the shipped function), which is why
conformance/runners.v0.json machine-checks that this file imports and calls the
shipped symbol and cannot reach a hashing primitive.

Mirror: node/tests/attestVerifyCorpus.test.ts.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from aegis_trust.attest_verify import (
    ALL_CHECKS,
    MAX_SAFE_INTEGER,
    AttestExpectation,
    AttestState,
    CapsuleFinding,
    canonical_message,
    findings_digest,
    parse_attestation,
    report_arrived_check,
    verify_attestation,
)

REPO = Path(__file__).resolve().parents[2]
CORPUS = json.loads(
    (REPO / "conformance" / "attest_verify.v0.json").read_text(encoding="utf-8")
)
CASES = CORPUS["cases"]
TIMER_CASES = CORPUS["timer_cases"]


def _expectation(raw: dict) -> AttestExpectation:
    return AttestExpectation(
        public_key_hex=raw["public_key_hex"],
        host_fingerprint=raw["host_fingerprint"],
        nonce=raw["nonce"],
        allow_unchallenged=raw["allow_unchallenged"],
        key_id=raw["key_id"],
        max_age_seconds=raw["max_age_seconds"],
        max_clock_skew_seconds=raw["max_clock_skew_seconds"],
        capsule_ids=None if raw["capsule_ids"] is None else tuple(raw["capsule_ids"]),
        require_previous=raw["require_previous"],
    )


def _state(raw: dict | None) -> AttestState | None:
    return None if raw is None else AttestState.from_dict(raw)


def _case(case_id: str) -> dict:
    return next(c for c in CASES if c["id"] == case_id)


def _ids(cases: list[dict]) -> list[str]:
    return [c["id"] for c in cases]


def test_corpus_is_not_empty() -> None:
    """A runner that silently matched nothing would report a clean pass."""
    assert CORPUS["version"] == 0
    assert len(CASES) >= 20
    assert len(TIMER_CASES) >= 3


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_verdict_matches_the_corpus(case: dict) -> None:
    """Every check, outcome and detail sentence is byte-identical to the pin."""
    verdict = verify_attestation(
        case["attestation"],
        _expectation(case["expect"]),
        _state(case["previous"]),
        now=datetime.fromisoformat(case["now"]),
    )
    expected = case["expected"]

    assert [c.to_dict() for c in verdict.checks] == expected["checks"], case["id"]
    assert verdict.ok is expected["ok"]
    assert verdict.exit_code == expected["exit_code"]
    assert verdict.signature_verified is expected["signature_verified"]
    assert (
        None if verdict.next_state is None else verdict.next_state.to_dict()
    ) == expected["next_state"]


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_hand_written_intent_holds(case: dict) -> None:
    """``must`` is the specification; ``expected`` is only the regression pin.

    Asserted here as well as at generation time, so a regenerated corpus that
    quietly recorded a different verdict cannot pass by agreeing with itself.
    """
    verdict = verify_attestation(
        case["attestation"],
        _expectation(case["expect"]),
        _state(case["previous"]),
        now=datetime.fromisoformat(case["now"]),
    )
    failed = {c.check for c in verdict.checks if c.outcome.value == "fail"}
    passed = {c.check for c in verdict.checks if c.outcome.value == "pass"}
    skipped = {c.check for c in verdict.checks if c.outcome.value == "skip"}
    must = case["must"]

    assert failed == set(must["fails"]), f"{case['id']}: failing checks"
    assert set(must.get("passes", [])) <= passed, f"{case['id']}: expected passes"
    assert set(must.get("skips", [])) <= skipped, f"{case['id']}: expected skips"
    # ok is derived from the failures, and must stay that way: a verdict that
    # reported findings and still called itself ok is the whole disease.
    assert verdict.ok is (len(failed) == 0)


def test_every_check_has_a_reject_and_an_accept() -> None:
    """The discipline that makes the rest of this file mean anything.

    A suite built only from broken material is passed by an implementation that
    always answers red; one built only from healthy material is passed by one
    that always answers green. So every check this verifier can emit must appear
    in the corpus at least once failing and at least once passing. Measured,
    rather than asserted in a comment.
    """
    ever_failed: set[str] = set()
    ever_passed: set[str] = set()
    for case in CASES:
        for check in case["expected"]["checks"]:
            if check["outcome"] == "fail":
                ever_failed.add(check["check"])
            elif check["outcome"] == "pass":
                ever_passed.add(check["check"])

    missing_red = sorted(set(ALL_CHECKS) - ever_failed)
    missing_green = sorted(set(ALL_CHECKS) - ever_passed)
    assert not missing_red, f"no corpus case makes these fail: {missing_red}"
    assert not missing_green, f"no corpus case makes these pass: {missing_green}"


def test_a_clean_attestation_is_actually_accepted() -> None:
    """The healthy control, named. Without it every other case is satisfied by a
    verifier that rejects everything."""
    green = [c for c in CASES if c["expected"]["ok"]]
    assert green, "the corpus contains no attestation that verifies cleanly"
    full = [
        c for c in green if all(k["outcome"] == "pass" for k in c["expected"]["checks"])
    ]
    assert full, "no corpus case passes every check; 'clean' is never exercised"


def test_core_produced_vectors_are_present_and_verify() -> None:
    """The byte-level pin against the shipped Rust.

    Nothing about the canonical message can be settled by reading the contract:
    these vectors were produced AND signed by the real aegis-gateway binary, so
    a canonical message rebuilt even one byte differently fails here.
    """
    core_cases = [c for c in CASES if c["provenance"] == "core-binary"]
    assert len(core_cases) >= 3
    signed = [c for c in core_cases if c["attestation"]["signature"] is not None]
    assert signed, "no signed Core-produced vector"
    for case in signed:
        verdict = verify_attestation(
            case["attestation"],
            _expectation(case["expect"]),
            _state(case["previous"]),
            now=datetime.fromisoformat(case["now"]),
        )
        assert verdict.signature_verified, case["id"]
        assert "signature_valid" not in {c.check for c in verdict.findings}, case["id"]


def test_a_multibyte_capsule_id_is_covered() -> None:
    """Rust's ``str::len()`` counts BYTES. A verifier that length-prefixed the
    findings digest by character count agrees with Core on every ASCII capsule
    and diverges the moment one is not, so the corpus has to contain one."""
    found = any(
        any(
            not f["capsule_id"].isascii()
            for f in case["attestation"].get("findings", [])
        )
        for case in CASES
    )
    assert found, "no corpus case carries a capsule id outside ASCII"


@pytest.mark.parametrize("case", TIMER_CASES, ids=_ids(TIMER_CASES))
def test_report_arrived_timer(case: dict) -> None:
    """The other half of silence: the report that never came.

    Raised by the SDK on its own clock — nothing is asked of Core, because a
    boundary that has stopped reporting cannot be the thing that tells you so.
    """
    check = report_arrived_check(
        _state(case["previous"]),
        interval_seconds=case["interval_seconds"],
        grace_seconds=case["grace_seconds"],
        now=datetime.fromisoformat(case["now"]),
    )
    assert check.to_dict() == case["expected"], case["id"]
    assert check.outcome.value == case["must_outcome"], case["id"]


def test_timer_has_both_outcomes() -> None:
    outcomes = {c["must_outcome"] for c in TIMER_CASES}
    assert outcomes == {"pass", "fail"}, outcomes


# ---------------------------------------------------------------------------
# The contract gate: the SDK and the pinned contract cannot move apart.
# ---------------------------------------------------------------------------

PIN = CORPUS["contract_pin"]


def test_the_contract_pin_is_populated() -> None:
    """A pin that lost its fields would make every test below vacuous."""
    for key in (
        "revision",
        "canonical_message_prefix",
        "canonical_message_fields",
        "findings_digest_parts",
        "max_integer",
        "chain_status_vocabulary",
    ):
        assert PIN.get(key), f"contract_pin.{key} is empty"


def test_canonical_message_matches_the_pinned_contract() -> None:
    """The shipped message is parsed and compared to the pin, field by field.

    The contract lives in another repository, so nothing in this repo's CI can
    watch it move — and it moved three times while this verifier was being
    written, each time found by hand. This is the half that CAN be automated:
    edit ``canonical_message`` without updating the pin and this goes red; edit
    the pin without the code and it goes red too.

    Same mechanism as test_contract_gate.py, which commits aegis-core's
    openapi.json and binds client.py to it.
    """
    att = parse_attestation(_case("healthy-full-green")["attestation"])
    lines = canonical_message(att).split("\n")[:-1]
    assert lines[0] == PIN["canonical_message_prefix"]
    assert [line.split("=", 1)[0] for line in lines[1:]] == PIN[
        "canonical_message_fields"
    ]


def test_findings_digest_parts_match_the_pinned_contract() -> None:
    """Each of the six declared parts must actually change the digest.

    The count is checked as well as the behaviour: a contract that grew a
    seventh part would leave this at six and the digest would silently stop
    covering it.
    """
    parts = PIN["findings_digest_parts"]
    assert len(parts) == 6, parts
    base = CapsuleFinding("cap", "Sealed", True, 29, None, False)
    changed = {
        "capsule_id": CapsuleFinding("cap2", "Sealed", True, 29, None, False),
        "claimed_state": CapsuleFinding("cap", "Destroyed", True, 29, None, False),
        "payload_present": CapsuleFinding("cap", "Sealed", False, 29, None, False),
        "terminal": CapsuleFinding("cap", "Sealed", True, 29, None, True),
        "payload_bytes": CapsuleFinding("cap", "Sealed", True, 30, None, False),
        "issue": CapsuleFinding("cap", "Sealed", True, 29, "gone", False),
    }
    assert sorted(changed) == sorted(parts), (
        "the pin names a part this test cannot vary"
    )
    for name, variant in changed.items():
        assert findings_digest([base]) != findings_digest([variant]), (
            f"{name} is declared as a digested part but changing it does not "
            "change the digest"
        )


def test_the_integer_bound_matches_the_pinned_contract() -> None:
    """Core's fields are usize/u64, which are wider — this is a contract
    promise, not a type guarantee, so it has to be pinned on both sides.
    Widening Core alone would break both SDKs."""
    assert MAX_SAFE_INTEGER == PIN["max_integer"]


def test_every_pinned_chain_status_appears_in_the_corpus() -> None:
    """The vocabulary is closed today. The verifier is still written as
    ``!= "valid"`` rather than a match over these five, so a sixth value lands on
    the abnormal side instead of falling through — but each of the five that
    exists now must actually be exercised."""
    seen = {
        c["attestation"]["chain"]["status"]
        for c in CASES
        if isinstance(c["attestation"].get("chain"), dict)
        and isinstance(c["attestation"]["chain"].get("status"), str)
    }
    missing = sorted(set(PIN["chain_status_vocabulary"]) - seen)
    assert not missing, f"pinned chain statuses with no corpus case: {missing}"


def test_the_pin_names_the_revision_the_vectors_came_from() -> None:
    """Provenance, so a regenerated corpus cannot quietly keep an old claim."""
    assert PIN["revision"] in PIN["vectors_generated_from"]
    core_cases = [c for c in CASES if c["provenance"] == "core-binary"]
    assert core_cases, "the pin claims a Core revision but no Core vector is present"


def test_every_pinned_chain_status_has_a_stated_meaning() -> None:
    """The vocabulary pins the tokens; this pins what they assert.

    A meaning can move while a shape holds still — if ``valid`` were narrowed or
    widened, the pin, the gate and the vocabulary would all stay green and this
    verifier would go on answering a question nobody is asking. Nothing
    mechanical closes that. What this does is make the sentence part of the
    artifact, so the change is visible in a diff instead of living only in a
    document in another repository.
    """
    meaning = PIN["chain_status_meaning"]
    missing = sorted(set(PIN["chain_status_vocabulary"]) - set(meaning))
    assert not missing, f"pinned statuses with no stated meaning: {missing}"
    extra = sorted(set(meaning) - set(PIN["chain_status_vocabulary"]))
    assert not extra, f"meanings for statuses not in the vocabulary: {extra}"
    for status, text in meaning.items():
        assert len(text) > 40, f"{status}: meaning too thin to be worth diffing"


def test_the_empty_ledger_dependency_is_pinned_not_assumed() -> None:
    """Contract §4: an EMPTY ledger is ``valid``, so this verifier has no
    independent check for "capsules exist but nothing was ever recorded".

    Core reports it in ``abnormal``, which ``core_abnormal`` carries. The pair
    of cases pins the dependency in both directions: without Core's line the
    document verifies clean, with it the verdict fails — and ``chain_status``
    stays green either way, because the finding lives in the verdict and was not
    smuggled into the status.
    """
    case = _case("empty-ledger-not-independently-caught")
    assert case["attestation"]["chain"]["status"] == "valid"
    assert case["attestation"]["chain"]["records_checked"] == 0
    assert case["attestation"]["judged"] > 0
    assert case["expected"]["ok"] is True, (
        "if this stopped verifying clean, the SDK grew an independent check — "
        "say which one, and stop calling this a dependency on Core's verdict"
    )
    reported = _case("empty-ledger-core-reports-it")
    assert reported["attestation"]["chain"]["status"] == "valid", (
        "the finding must stay in `abnormal`; moving it to `chain.status` would "
        "change what `valid` means for every other caller"
    )
    failed = {
        c["check"] for c in reported["expected"]["checks"] if c["outcome"] == "fail"
    }
    assert failed == {"core_abnormal"}, failed
    assert "empty" in PIN["chain_status_meaning"]["valid"].lower(), (
        "the pinned meaning of 'valid' no longer mentions the empty-ledger case "
        "that this limit rests on"
    )
