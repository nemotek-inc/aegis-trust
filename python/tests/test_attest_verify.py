"""Attestation verifier behaviour that the shared corpus cannot express (Python).

conformance/attest_verify.v0.json pins the verdict for a given document. What it
cannot pin is what happens *around* the verdict: which exit code the CLI
returns, whether the stored baseline can be rolled backwards, and whether a
corrupt state file degrades into "no previous observation". Those are where a
verifier stops being a verifier without any single check looking wrong.

Mirror: node/tests/attestVerify.test.ts.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_trust.attest_verify import (
    EXIT_ABNORMAL,
    EXIT_CLEAN,
    EXIT_NO_REPORT,
    AttestState,
    AttestStateError,
    CapsuleFinding,
    advance_state,
    canonical_message,
    findings_digest,
    load_state,
    parse_attestation,
    UNSIGNED_FIELDS,
    AttestExpectation,
    save_state,
    verify_attestation,
)
from aegis_trust.cli import main

REPO = Path(__file__).resolve().parents[2]
CORPUS = json.loads(
    (REPO / "conformance" / "attest_verify.v0.json").read_text(encoding="utf-8")
)
PINNED_KEY = CORPUS["signing_keys"]["pinned"]["public_key_hex"]
#: Read from the corpus, never repeated as a literal: two values that must
#: agree with nothing making them agree is the break canonical_digest.v0.json
#: was created for.
HOST = next(
    c["expect"]["host_fingerprint"]
    for c in CORPUS["cases"]
    if c["id"] == "healthy-full-green"
)


def _expectation_for(case_id: str) -> AttestExpectation:
    raw = _case(case_id)["expect"]
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


def _case(case_id: str) -> dict:
    return next(c for c in CORPUS["cases"] if c["id"] == case_id)


def _write(tmp_path: Path, case_id: str) -> Path:
    path = tmp_path / f"{case_id}.json"
    path.write_text(
        json.dumps(_case(case_id)["attestation"], ensure_ascii=False), encoding="utf-8"
    )
    return path


def _cli(*args: str) -> int:
    # The host and key every corpus case is built against.
    return main(
        [
            "attest-verify",
            *args,
            "--expect-key",
            PINNED_KEY,
            "--expect-host",
            HOST,
            # The corpus documents carry fixed timestamps, so the window has to
            # be wide enough that this file does not start failing tomorrow.
            "--max-age",
            "999999999",
        ]
    )


# ---------------------------------------------------------------------------
# Exit codes (contract §5). 2 must never collapse into 1.
# ---------------------------------------------------------------------------


def test_clean_attestation_exits_zero(tmp_path: Path) -> None:
    path = _write(tmp_path, "healthy-full-green")
    assert (
        _cli(
            str(path),
            "--nonce",
            "sdk-contract-001",
            "--state",
            str(tmp_path / "state.json"),
        )
        == EXIT_CLEAN
    )


def test_abnormal_attestation_exits_one(tmp_path: Path) -> None:
    path = _write(tmp_path, "silence-same-head-again")
    state = tmp_path / "state.json"
    save_state(
        state, AttestState.from_dict(_case("silence-same-head-again")["previous"])
    )
    assert (
        _cli(str(path), "--nonce", "sdk-contract-001", "--state", str(state))
        == EXIT_ABNORMAL
    )


def test_unsigned_attestation_exits_one_not_two(tmp_path: Path) -> None:
    """An unsigned attestation IS a report — an unverifiable one.

    Answering 2 here would file it as "the invocation failed" and route it to
    whoever fixes pipelines, when what happened is that a boundary produced a
    statement nobody can authenticate.
    """
    path = _write(tmp_path, "unsigned-is-not-verified")
    assert _cli(str(path), "--allow-unchallenged") == EXIT_ABNORMAL


def test_missing_file_exits_two(tmp_path: Path) -> None:
    """No report could be obtained — distinct from finding problems in one."""
    assert _cli(str(tmp_path / "nope.json"), "--allow-unchallenged") == EXIT_NO_REPORT


def test_empty_input_exits_two(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")
    assert _cli(str(path), "--allow-unchallenged") == EXIT_NO_REPORT


def test_non_json_input_exits_two(tmp_path: Path) -> None:
    """Bytes that are not a document are indistinguishable from a failed
    invocation, so they are reported as one rather than as an anomaly."""
    path = tmp_path / "garbage.json"
    path.write_text("error: could not open capsule root\n", encoding="utf-8")
    assert _cli(str(path), "--allow-unchallenged") == EXIT_NO_REPORT


def test_json_that_is_not_an_attestation_exits_one(tmp_path: Path) -> None:
    """A well-formed JSON document that is not an attestation is a claim that
    arrived, so it is an anomaly rather than a missing report."""
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    assert _cli(str(path), "--allow-unchallenged") == EXIT_ABNORMAL


def test_no_arguments_at_all_exits_two() -> None:
    assert _cli() == EXIT_NO_REPORT


def test_the_three_exit_codes_are_distinct() -> None:
    assert len({EXIT_CLEAN, EXIT_ABNORMAL, EXIT_NO_REPORT}) == 3


# ---------------------------------------------------------------------------
# The timer, with no attestation at all.
# ---------------------------------------------------------------------------


def test_timer_only_mode_reports_the_report_that_never_came(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    save_state(
        state,
        AttestState(
            host_fingerprint=HOST,
            public_key_hex=PINNED_KEY,
            last_seq=12,
            curr_hash="ab" * 32,
            genesis_anchor="cd" * 32,
            generated_at="2020-01-01T00:00:00+00:00",
            observations=3,
        ),
    )
    assert _cli("--state", str(state), "--report-within", "60") == EXIT_ABNORMAL


def test_timer_only_mode_is_clean_when_a_report_did_arrive(tmp_path: Path) -> None:
    """The accept half of the pair: an always-red timer would pass the test
    above on its own."""
    state = tmp_path / "state.json"
    recent = datetime.now(timezone.utc) - timedelta(seconds=5)
    save_state(
        state,
        AttestState(
            host_fingerprint=HOST,
            public_key_hex=PINNED_KEY,
            last_seq=12,
            curr_hash="ab" * 32,
            genesis_anchor="cd" * 32,
            generated_at=recent.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            observations=3,
        ),
    )
    assert _cli("--state", str(state), "--report-within", "3600") == EXIT_CLEAN


# ---------------------------------------------------------------------------
# The stored baseline.
# ---------------------------------------------------------------------------


def test_state_round_trips(tmp_path: Path) -> None:
    state = AttestState(
        host_fingerprint="host_1",
        public_key_hex=PINNED_KEY,
        last_seq=9,
        curr_hash="aa" * 32,
        genesis_anchor="bb" * 32,
        generated_at="2026-09-14T12:00:00+00:00",
        observations=4,
    )
    path = tmp_path / "nested" / "state.json"
    save_state(path, state)
    assert load_state(path) == state


def test_absent_state_is_none_but_corrupt_state_raises(tmp_path: Path) -> None:
    """The distinction the whole silence check rests on.

    If a corrupt state file degraded to "no previous observation", corrupting it
    would make the silence checks SKIP on every run while the report stayed
    green — which is the bypass, not a recovery.
    """
    assert load_state(tmp_path / "absent.json") is None

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    with pytest.raises(AttestStateError):
        load_state(corrupt)

    wrong_schema = tmp_path / "wrong.json"
    wrong_schema.write_text(json.dumps({"schema": "something-else"}), encoding="utf-8")
    with pytest.raises(AttestStateError):
        load_state(wrong_schema)


def test_cli_refuses_a_corrupt_state_file_rather_than_starting_fresh(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, "healthy-full-green")
    corrupt = tmp_path / "state.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert (
        _cli(str(path), "--nonce", "sdk-contract-001", "--state", str(corrupt))
        == EXIT_ABNORMAL
    )


def _verdict(case_id: str, previous: AttestState | None):
    case = _case(case_id)
    from aegis_trust.attest_verify import AttestExpectation

    raw = case["expect"]
    return verify_attestation(
        case["attestation"],
        AttestExpectation(
            public_key_hex=raw["public_key_hex"],
            host_fingerprint=raw["host_fingerprint"],
            nonce=raw["nonce"],
            allow_unchallenged=raw["allow_unchallenged"],
            key_id=raw["key_id"],
            max_age_seconds=raw["max_age_seconds"],
            max_clock_skew_seconds=raw["max_clock_skew_seconds"],
            capsule_ids=None
            if raw["capsule_ids"] is None
            else tuple(raw["capsule_ids"]),
            require_previous=raw["require_previous"],
        ),
        previous,
        now=datetime.fromisoformat(case["now"]),
    )


def test_baseline_moves_forward_on_a_healthy_attestation() -> None:
    previous = AttestState.from_dict(_case("healthy-full-green")["previous"])
    moved = advance_state(previous, _verdict("healthy-full-green", previous))
    assert moved is not None
    assert moved.last_seq == 12
    assert moved.observations == previous.observations + 1


def test_a_shrunken_ledger_does_not_lower_the_stored_head() -> None:
    """A fresh, correctly signed attestation reporting a SMALLER head.

    It is an anomaly (the ledger was truncated or replaced) and the report did
    genuinely arrive — so the last-report axis advances while the head axis
    holds. If the head followed it down, the truncation would be laundered into
    a new baseline and the next attestation would "advance" past it.
    """
    previous = AttestState.from_dict(_case("ledger-went-backwards")["previous"])
    verdict = _verdict("ledger-went-backwards", previous)
    assert not verdict.ok
    moved = advance_state(previous, verdict)
    assert moved is not None
    assert moved.last_seq == previous.last_seq
    assert moved.curr_hash == previous.curr_hash
    assert moved.generated_at != previous.generated_at


def _state_at(seq: int, when: str) -> AttestState:
    return AttestState(
        host_fingerprint=HOST,
        public_key_hex=PINNED_KEY,
        last_seq=seq,
        curr_hash=f"{seq:064d}",
        genesis_anchor="cd" * 32,
        generated_at=when,
        observations=5,
    )


def _verdict_carrying(state: AttestState):
    from aegis_trust.attest_verify import AttestVerdict

    return AttestVerdict(checks=(), signature_verified=True, next_state=state)


@pytest.mark.parametrize(
    "head, when, expect_seq, expect_generated",
    [
        # head forward, newer report: both axes move.
        (20, "2026-09-14T13:00:00+00:00", 20, "2026-09-14T13:00:00+00:00"),
        # head forward, older report: the head moves, the clock does not.
        (20, "2026-09-14T10:00:00+00:00", 20, "2026-09-14T12:00:00+00:00"),
        # head held, newer report: the clock moves, the head does not.
        (10, "2026-09-14T13:00:00+00:00", 12, "2026-09-14T13:00:00+00:00"),
    ],
)
def test_the_baseline_is_monotone_on_each_axis_independently(
    head: int, when: str, expect_seq: int, expect_generated: str
) -> None:
    previous = _state_at(12, "2026-09-14T12:00:00+00:00")
    moved = advance_state(previous, _verdict_carrying(_state_at(head, when)))
    assert moved is not None
    assert moved.last_seq == expect_seq
    assert moved.generated_at == expect_generated


def test_a_replay_that_is_older_on_both_axes_changes_nothing() -> None:
    """The rollback tool a non-monotone baseline would hand an attacker.

    Replay the genuinely signed attestation from head 4, taken an hour ago: the
    baseline would drop to 4, and every attestation between 4 and the real head
    would "advance" again — with the silence check still running, and still
    answering about a boundary that stopped recording.
    """
    previous = _state_at(12, "2026-09-14T12:00:00+00:00")
    replay = _state_at(4, "2026-09-14T11:00:00+00:00")
    assert advance_state(previous, _verdict_carrying(replay)) is None


def test_an_identical_repeat_changes_nothing() -> None:
    """The same attestation delivered twice moves neither axis, so a duplicate
    cannot inflate the observation count into looking like activity."""
    previous = _state_at(12, "2026-09-14T12:00:00+00:00")
    assert (
        advance_state(previous, _verdict_carrying(_state_at(12, previous.generated_at)))
        is None
    )


def test_the_head_and_the_last_report_move_independently() -> None:
    """A report can arrive without the ledger growing — that is exactly the
    silence case — so the timer must see a new report while the head check still
    sees the same head."""
    previous = AttestState.from_dict(_case("silence-same-head-again")["previous"])
    verdict = _verdict("silence-same-head-again", previous)
    moved = advance_state(previous, verdict)
    assert moved is not None
    assert moved.last_seq == previous.last_seq  # the ledger did not grow
    assert moved.curr_hash == previous.curr_hash
    assert moved.generated_at != previous.generated_at  # a report did arrive


def test_a_forged_document_never_sets_the_baseline() -> None:
    """Otherwise one forged attestation poisons the baseline and every real one
    afterwards looks stale."""
    for case_id in (
        "signed-by-an-unexpected-key",
        "attestation-about-another-host",
        "signature-bit-flipped",
        "unsigned-is-not-verified",
    ):
        verdict = _verdict(case_id, None)
        assert verdict.next_state is None, case_id
        assert advance_state(None, verdict) is None, case_id


def test_cli_state_file_only_ever_moves_forward(tmp_path: Path) -> None:
    """End to end: verify a head-12 attestation, then replay a head-4 one, and
    the stored baseline must still read 12."""
    state = tmp_path / "state.json"
    save_state(state, AttestState.from_dict(_case("healthy-full-green")["previous"]))

    good = _write(tmp_path, "healthy-full-green")
    assert (
        _cli(str(good), "--nonce", "sdk-contract-001", "--state", str(state))
        == EXIT_CLEAN
    )
    after_good = load_state(state)
    assert after_good is not None and after_good.last_seq == 12

    replayed = _write(tmp_path, "ledger-went-backwards")
    assert (
        _cli(str(replayed), "--nonce", "sdk-contract-001", "--state", str(state))
        == EXIT_ABNORMAL
    )
    after_replay = load_state(state)
    assert after_replay is not None
    assert after_replay.last_seq == 12, (
        "a replayed attestation rolled the baseline back"
    )


# ---------------------------------------------------------------------------
# The canonical message and the findings digest, directly.
# ---------------------------------------------------------------------------


def _finding(capsule_id: str, claimed_state: str) -> CapsuleFinding:
    return CapsuleFinding(
        capsule_id=capsule_id,
        claimed_state=claimed_state,
        payload_present=True,
        payload_bytes=1,
        issue=None,
        terminal=False,
    )


def test_the_length_prefix_separates_adjacent_fields() -> None:
    """Without the 8-byte length prefix, ("ab", "c") and ("a", "bc") hash the
    same — which is exactly how a rewritten capsule id hides inside an issue
    string. Asserted on the shipped digest, not on a restatement of it."""
    assert findings_digest([_finding("ab", "c")]) != findings_digest(
        [_finding("a", "bc")]
    )


def test_the_length_prefix_counts_bytes_not_characters() -> None:
    """Rust's ``str::len()`` is a byte count. Two ids with the same number of
    characters and different UTF-8 lengths must digest differently — and the
    Core-produced corpus vector is what proves the byte count is the right one.
    """
    ascii_id = findings_digest([_finding("abc", "S")])
    multibyte_id = findings_digest([_finding("あいう", "S")])
    assert ascii_id != multibyte_id


def test_every_digested_part_participates() -> None:
    """A digest that silently dropped a field would let that field be rewritten
    in flight, so each of the six is changed in turn."""
    base = CapsuleFinding("cap", "Sealed", True, 29, None, False)
    variants = [
        CapsuleFinding("cap2", "Sealed", True, 29, None, False),
        CapsuleFinding("cap", "Destroyed", True, 29, None, False),
        CapsuleFinding("cap", "Sealed", False, 29, None, False),
        CapsuleFinding("cap", "Sealed", True, 30, None, False),
        CapsuleFinding("cap", "Sealed", True, None, None, False),
        CapsuleFinding("cap", "Sealed", True, 29, "gone", False),
        CapsuleFinding("cap", "Sealed", True, 29, None, True),
    ]
    digests = {findings_digest([base])} | {findings_digest([v]) for v in variants}
    assert len(digests) == len(variants) + 1


def test_canonical_message_shape() -> None:
    """Eighteen lines, each ending in a newline, in the contract's order."""
    att = parse_attestation(_case("healthy-full-green")["attestation"])
    message = canonical_message(att)
    assert message.endswith("\n")
    lines = message.split("\n")[:-1]
    assert lines[0] == "aegis-attest-v1"
    assert [line.split("=", 1)[0] for line in lines[1:]] == [
        "generated_at",
        "host",
        "root",
        "nonce",
        "judged",
        "payload_missing",
        "inconsistent",
        "chain_status",
        "chain_last_seq",
        "chain_curr_hash",
        "chain_genesis",
        "chain_records_checked",
        "chain_first_break",
        "skipped_non_capsule",
        "self_limit",
        "findings_sha256",
        "abnormal",
    ]


# ---------------------------------------------------------------------------
# What the signature covers, measured rather than described.
# ---------------------------------------------------------------------------

#: Fields whose value is ``null`` in the healthy fixture, and the type to mutate
#: them to. A nullable field this map does not know about fails the test rather
#: than being skipped: a silently skipped field is a field nobody checked.
_NULLABLE_TYPES = {
    "self_limit_tripped": "string",
    "chain.first_break": "string",
    "findings[1].payload_bytes": "number",
    "findings[0].issue": "string",
    "findings[1].issue": "string",
    "findings[2].issue": "string",
}


def _leaf_paths(node: object, prefix: str = "") -> list[str]:
    """Every mutable leaf in the document, as a dotted/indexed path."""
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(_leaf_paths(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            out.extend(_leaf_paths(value, f"{prefix}[{i}]"))
    else:
        out.append(prefix)
    return out


def _get(doc: object, path: str) -> object:
    node = doc
    for part in path.replace("[", ".[").split("."):
        if not part:
            continue
        if part.startswith("["):
            node = node[int(part[1:-1])]  # type: ignore[index]
        else:
            node = node[part]  # type: ignore[index]
    return node


def _set(doc: object, path: str, value: object) -> None:
    parts = [p for p in path.replace("[", ".[").split(".") if p]
    node = doc
    for part in parts[:-1]:
        node = node[int(part[1:-1])] if part.startswith("[") else node[part]  # type: ignore[index]
    last = parts[-1]
    if last.startswith("["):
        node[int(last[1:-1])] = value  # type: ignore[index]
    else:
        node[last] = value  # type: ignore[index]


def _mutated(value: object, path: str) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str):
        return value + "X"
    if value is None:
        kind = _NULLABLE_TYPES.get(path)
        assert kind is not None, (
            f"{path} is null and this test does not know its type; declare it in "
            "_NULLABLE_TYPES rather than leaving the field unchecked"
        )
        return 1 if kind == "number" else "X"
    raise AssertionError(f"{path}: unhandled leaf type {type(value).__name__}")


def test_the_signature_covers_everything_else() -> None:
    """Mutate every field in a signed attestation and require the signature to
    break — except the ones :data:`UNSIGNED_FIELDS` declares it does not cover,
    where the signature must HOLD.

    This is what keeps `UNSIGNED_FIELDS` from becoming a stale comment. A
    contract change that drops a field out of the canonical message turns the
    first half red; one that adds a field to the message without updating the
    tuple turns the second half red.
    """
    base = _case("healthy-full-green")["attestation"]
    empty_lists = {"skipped_non_capsule", "abnormal"}

    covered, uncovered = [], []
    for path in _leaf_paths(base):
        # The signature block describes the signature; mutating signature_hex or
        # message_sha256 is tested elsewhere by its own check.
        if path.startswith("signature.") and path not in UNSIGNED_FIELDS:
            continue
        document = json.loads(json.dumps(base))
        _set(document, path, _mutated(_get(base, path), path))
        verdict = verify_attestation(
            document,
            _expectation_for("healthy-full-green"),
            None,
            now=datetime.fromisoformat(_case("healthy-full-green")["now"]),
        )
        failed = {c.check for c in verdict.checks if c.outcome.value == "fail"}
        assert "document" not in failed, (
            f"{path}: mutation made the document unparseable"
        )
        (uncovered if "signature_valid" not in failed else covered).append(path)

    # An empty list has no leaf to mutate, so append to it instead — otherwise
    # `skipped_non_capsule` (the field this whole exchange was about) would be
    # silently absent from the scan.
    for field in empty_lists:
        assert base[field] == [], f"{field} is no longer empty in the fixture"
        document = json.loads(json.dumps(base))
        document[field] = ["injected"]
        verdict = verify_attestation(
            document,
            _expectation_for("healthy-full-green"),
            None,
            now=datetime.fromisoformat(_case("healthy-full-green")["now"]),
        )
        failed = {c.check for c in verdict.checks if c.outcome.value == "fail"}
        (uncovered if "signature_valid" not in failed else covered).append(field)

    assert sorted(uncovered) == sorted(UNSIGNED_FIELDS), (
        f"fields outside the signature are {sorted(uncovered)}, "
        f"UNSIGNED_FIELDS declares {sorted(UNSIGNED_FIELDS)}"
    )
    # Non-vacuity: the scan has to have actually found fields to mutate.
    assert len(covered) >= 20, f"only {len(covered)} fields were scanned"


def test_skipped_non_capsule_is_now_inside_the_signature() -> None:
    """Named on its own because it is the field this contract exchange was
    about: it is the only window onto what was NOT counted, and blanking it hid
    "nineteen files under the root were skipped" while verification succeeded."""
    case = _case("skipped_non_capsule-rewritten-after-signing")
    assert case["attestation"]["skipped_non_capsule"] == []
    verdict = verify_attestation(
        case["attestation"],
        _expectation_for(case["id"]),
        AttestState.from_dict(case["previous"]),
        now=datetime.fromisoformat(case["now"]),
    )
    assert "signature_valid" in {c.check for c in verdict.findings}


# ---------------------------------------------------------------------------
# The one documented way past the monotone baseline.
# ---------------------------------------------------------------------------


def test_without_the_flag_a_rotated_ledger_stays_red_forever() -> None:
    """The defect this flag exists for, shown rather than described.

    Core's genesis.json survives a rotation, so a sealed-and-rotated ledger
    keeps its genesis: ``chain_identity`` does not notice, and the head simply
    drops. With a monotone baseline that is reported every run from then on,
    and the only escape was deleting the state file — which also destroys the
    last-report baseline and is what an attacker clearing evidence would do.
    """
    previous = _state_at(412, "2026-09-14T12:00:00+00:00")
    # Three attestations after a rotation: heads 1, 2, 3 against a stored 412.
    for head in (1, 2, 3):
        rotated = _state_at(head, f"2026-09-14T13:0{head}:00+00:00")
        moved = advance_state(previous, _verdict_carrying(rotated))
        assert moved is not None
        assert moved.last_seq == 412, (
            "the stored head followed the rotation down, which would launder a "
            "truncation into a new baseline"
        )
        previous = moved
    # Still comparing against the pre-rotation head, so still red.
    assert previous.last_seq == 412
    assert previous.ledger_resets == 0


def test_the_flag_rebases_and_counts_the_assertion() -> None:
    """With the operator's assertion, the baseline moves to the new ledger and
    the assertion is COUNTED — not forgotten, because the SDK cannot verify it.
    """
    previous = _state_at(412, "2026-09-14T12:00:00+00:00")
    rotated = _state_at(1, "2026-09-14T13:00:00+00:00")
    moved = advance_state(
        previous, _verdict_carrying(rotated), accept_ledger_reset=True
    )
    assert moved is not None
    assert moved.last_seq == 1
    assert moved.curr_hash == rotated.curr_hash
    assert moved.ledger_resets == previous.ledger_resets + 1
    # And the next attestation on the new ledger is clean again.
    following = advance_state(
        moved, _verdict_carrying(_state_at(2, "2026-09-14T13:05:00+00:00"))
    )
    assert following is not None
    assert following.last_seq == 2
    assert following.ledger_resets == 1, "the count must survive later advances"


def test_the_flag_does_not_lower_a_head_that_went_up() -> None:
    """It is an acknowledgement of a DROP, not a general override: a normal
    advance must still behave normally when the flag is set."""
    previous = _state_at(10, "2026-09-14T12:00:00+00:00")
    moved = advance_state(
        previous,
        _verdict_carrying(_state_at(20, "2026-09-14T13:00:00+00:00")),
        accept_ledger_reset=True,
    )
    assert moved is not None
    assert moved.last_seq == 20
    assert moved.ledger_resets == 0, "no reset happened, so nothing to count"


def test_the_flag_changes_nothing_about_the_verdict() -> None:
    """The run that sees the drop still reports it. The flag decides only what
    the NEXT run is compared against — an acknowledgement is not a silencer."""
    previous = AttestState.from_dict(_case("ledger-went-backwards")["previous"])
    verdict = _verdict("ledger-went-backwards", previous)
    assert not verdict.ok
    assert "sequence_advanced" in {c.check for c in verdict.findings}
    moved = advance_state(previous, verdict, accept_ledger_reset=True)
    assert moved is not None and moved.ledger_resets == 1
    # Same verdict either way: the flag is not an input to verification.
    assert verdict.to_dict() == _verdict("ledger-went-backwards", previous).to_dict()


def test_a_forged_document_cannot_use_the_flag_to_set_a_baseline() -> None:
    """The flag loosens the monotone rule, not the authenticity rule."""
    for case_id in ("signed-by-an-unexpected-key", "attestation-about-another-host"):
        verdict = _verdict(case_id, None)
        assert (
            advance_state(
                _state_at(412, "2026-09-14T12:00:00+00:00"),
                verdict,
                accept_ledger_reset=True,
            )
            is None
        ), case_id


def test_state_round_trips_the_reset_count(tmp_path: Path) -> None:
    state = _state_at(7, "2026-09-14T12:00:00+00:00")
    state = AttestState(
        host_fingerprint=state.host_fingerprint,
        public_key_hex=state.public_key_hex,
        last_seq=state.last_seq,
        curr_hash=state.curr_hash,
        genesis_anchor=state.genesis_anchor,
        generated_at=state.generated_at,
        observations=state.observations,
        ledger_resets=3,
    )
    path = tmp_path / "state.json"
    save_state(path, state)
    assert load_state(path) == state


def test_a_state_written_before_resets_existed_reads_as_zero(tmp_path: Path) -> None:
    """The field is optional on the way in: a baseline written before resets
    could be acknowledged simply has not had one."""
    path = tmp_path / "state.json"
    raw = _state_at(7, "2026-09-14T12:00:00+00:00").to_dict()
    del raw["ledger_resets"]
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded = load_state(path)
    assert loaded is not None and loaded.ledger_resets == 0
