"""Verifier for Aegis Core attestations (S051 ③ — the SDK half).

Core **produces** an attestation; this module **verifies it and nothing else**.
It never opens the capsule directory and never re-derives a verdict about what
is on the disk. If it did, one disk would have two implementations answering one
question, and the first time they disagreed a customer would be told two things
about their own data. The wire contract is
``aegis-boundary-core/docs/ATTESTATION_CONTRACT.md``.

WHAT IS CHECKED (contract §4). Any single failure is an anomaly; the verifier
does not weigh them against each other:

===========================  ====================================================
``signature_present``        an unsigned attestation is not a verified one
``signature_valid``          Ed25519 over the canonical message, rebuilt here
``message_digest``           ``message_sha256`` describes the message that signed
``signing_key``              the signature is by the key this deployment pinned
``host``                     the attestation is about the host that was pinned
``nonce``                    the freshness challenge came back
``freshness``                ``generated_at`` is inside the expected window
``core_abnormal``            Core's own verdict is empty
``chain_status``             the ledger verified, rather than being absent
``sequence_advanced``        **the ledger grew — see SILENCE below**
``chain_linked``             it grew forward, rather than being rewritten
``chain_identity``           it is still the same ledger (genesis unchanged)
``judged_nonzero``           something was actually examined
``payload_intact``           no non-terminal capsule lost its body
``metadata_consistent``      no capsule disagrees with its recorded state
``inventory``                the capsules you expected are the ones reported
===========================  ====================================================

SILENCE IS THE FAILURE MODE THIS LAYER EXISTS FOR. A boundary that has stopped
writing records produces an attestation that looks calm: nothing abnormal, chain
valid, no losses. ``sequence_advanced`` is what turns "the same head as last
time, again" into a finding instead of "no news", and
:func:`report_arrived_check` is what turns an attestation that never came at all
into one. Neither can work without the previous observation, which is why
:class:`AttestState` is part of the API rather than an implementation detail.

A CHECK THAT DID NOT RUN IS NOT A CHECK THAT PASSED. Every check reports
``pass`` / ``fail`` / ``skip`` with a reason, and :attr:`AttestVerdict.ok` is
false when anything failed. Skips are carried in the verdict and printed by the
CLI rather than folded into the green. S012 is why: a shipped verifier answered
``LEDGER OK`` and exit 0 about evidence that did not exist.

WHAT CORE DOES NOT CLAIM, AND THIS MODULE THEREFORE CANNOT (contract §6):

* **Decryptability.** The attestation proves a body is present and non-empty. It
  does not decrypt — capsule bodies are AEAD-sealed against the sealing host.
  ``aegis-gateway migrate verify-integrity`` is the check that decrypts, on the
  host that can.
* **Completeness against an expected inventory.** ``judged`` is what Core found
  under the root. If twenty capsules should exist and one remains, the
  attestation reads ``judged: 1`` and is otherwise clean. Catching that needs an
  expected set held on this side, so :attr:`AttestExpectation.capsule_ids` is
  where you put it — and when you leave it unset, ``inventory`` reports ``skip``
  rather than ``pass``.

WHAT THE SIGNATURE DOES NOT COVER. Exactly one field an operator reads sits
outside the canonical message: ``signature.key_id``. It is a label, and the key
itself is what authenticates, so pinning it with
:attr:`AttestExpectation.key_id` catches an honest misconfiguration — a rotation
that moved the key without the label, or the reverse — and catches nothing an
attacker does, because an attacker who is rewriting the document can set the
label to whatever is expected. That limit is stated here rather than implied,
and pinned by the ``key-id-is-outside-the-signature`` corpus case.

``records_checked``, ``first_break`` and ``skipped_non_capsule`` were outside it
in the first draft of the contract, which this verifier reported during §8.2 —
none of the three could manufacture false safety, since ``judged`` and the
findings digest were already signed, but ``skipped_non_capsule`` is the only
window onto what was **not** counted, and blanking it hid "nineteen files were
skipped" while verification still succeeded. Core moved all three inside the
message, so rewriting any of them now breaks the signature.

DECLARED ASYMMETRY WITH THE NODE SDK (undeclared asymmetry is how two SDKs stop
being the same product). A count written as ``4.0`` instead of ``4`` is rejected
here as a number where an integer was required, and accepted by
``node/src/attestVerify.ts``, because ``JSON.parse`` cannot tell the two apart.
The verdict is the same either way — ``4.0`` renders into the canonical message
as ``4`` on the Node side, so the signature decides — and the shared conformance
corpus therefore carries no such vector. Both SDKs refuse integers above
:data:`MAX_SAFE_INTEGER` so that the case where the rendering would genuinely
differ is rejected identically instead.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from aegis_trust._ed25519 import ed25519_verify

__all__ = [
    "ATTEST_MESSAGE_PREFIX",
    "STATE_SCHEMA",
    "AttestCheck",
    "AttestExpectation",
    "AttestFormatError",
    "AttestSignature",
    "AttestState",
    "AttestStateError",
    "AttestVerdict",
    "Attestation",
    "CapsuleFinding",
    "ChainReport",
    "CheckOutcome",
    "EXIT_ABNORMAL",
    "EXIT_CLEAN",
    "EXIT_NO_REPORT",
    "MAX_SAFE_INTEGER",
    "UNSIGNED_FIELDS",
    "advance_state",
    "canonical_message",
    "ed25519_verify",
    "findings_digest",
    "load_state",
    "parse_attestation",
    "report_arrived_check",
    "save_state",
    "verify_attestation",
]

ATTEST_MESSAGE_PREFIX = "aegis-attest-v1"
STATE_SCHEMA = "aegis-attest-verifier-state.v1"

#: Exit codes, contract §5. ``EXIT_NO_REPORT`` is deliberately distinct from
#: ``EXIT_ABNORMAL``: "I could not report" is not "I found problems", and
#: collapsing them means a broken invocation pages the same person as a broken
#: deployment.
EXIT_CLEAN = 0
EXIT_ABNORMAL = 1
EXIT_NO_REPORT = 2

#: The document fields the canonical message does NOT cover — the receptacle for
#: "which parts of what a reader is looking at are merely claims".
#:
#: It held three members until Core moved them in (``records_checked``,
#: ``first_break``, ``skipped_non_capsule``), which this verifier reported during
#: §8.2: none of the three could manufacture false safety, since ``judged`` and
#: the findings digest were already signed, but ``skipped_non_capsule`` was the
#: only window onto what was **not** counted and blanking it hid "nineteen files
#: were skipped" while verification still succeeded.
#:
#: What remains is the key label. It is a label — the key itself is what
#: authenticates — so pinning it with :attr:`AttestExpectation.key_id` catches a
#: rotation that moved the key without the label, and catches nothing an
#: attacker does, because an attacker rewriting the document can set the label
#: to whatever is expected.
#:
#: This is not a comment: ``test_the_signature_covers_everything_else`` mutates
#: every other field in a signed attestation and requires the signature to
#: break, and mutates these and requires it to hold. A contract change that
#: takes a field out of the message without updating this tuple fails there.
UNSIGNED_FIELDS = ("signature.key_id",)

# Check identifiers. Stable strings: they are what a caller branches on and what
# the conformance corpus pins, so they are part of the contract.
CHECK_DOCUMENT = "document"
CHECK_SIGNATURE_PRESENT = "signature_present"
CHECK_SIGNATURE_VALID = "signature_valid"
CHECK_MESSAGE_DIGEST = "message_digest"
CHECK_SIGNING_KEY = "signing_key"
CHECK_HOST = "host"
CHECK_NONCE = "nonce"
CHECK_FRESHNESS = "freshness"
CHECK_CORE_ABNORMAL = "core_abnormal"
CHECK_CHAIN_STATUS = "chain_status"
CHECK_SEQUENCE_ADVANCED = "sequence_advanced"
CHECK_CHAIN_LINKED = "chain_linked"
CHECK_CHAIN_IDENTITY = "chain_identity"
CHECK_JUDGED_NONZERO = "judged_nonzero"
CHECK_PAYLOAD_INTACT = "payload_intact"
CHECK_METADATA_CONSISTENT = "metadata_consistent"
CHECK_INVENTORY = "inventory"
CHECK_REPORT_ARRIVED = "report_arrived"

#: Every check :func:`verify_attestation` can report, in the order it reports
#: them. A caller can assert against this list to notice a check that silently
#: stopped being emitted.
ALL_CHECKS = (
    CHECK_DOCUMENT,
    CHECK_SIGNATURE_PRESENT,
    CHECK_SIGNATURE_VALID,
    CHECK_MESSAGE_DIGEST,
    CHECK_SIGNING_KEY,
    CHECK_HOST,
    CHECK_NONCE,
    CHECK_FRESHNESS,
    CHECK_CORE_ABNORMAL,
    CHECK_CHAIN_STATUS,
    CHECK_SEQUENCE_ADVANCED,
    CHECK_CHAIN_LINKED,
    CHECK_CHAIN_IDENTITY,
    CHECK_JUDGED_NONZERO,
    CHECK_PAYLOAD_INTACT,
    CHECK_METADATA_CONSISTENT,
    CHECK_INVENTORY,
)


class AttestFormatError(ValueError):
    """The document is not an attestation.

    Raised by :func:`parse_attestation` for a missing or wrongly typed field.
    Nothing is coerced: a ``judged`` of ``"4"`` is not a 4, because the string
    and the number do not render into the canonical message the same way, and
    silently picking one would mean verifying a signature over a message Core
    never produced.
    """


class AttestStateError(ValueError):
    """The stored previous observation exists but cannot be read.

    Distinct from "there is no previous observation". Treating a corrupt state
    file as a fresh start is the bypass for the whole silence check: delete the
    file and ``sequence_advanced`` skips forever.
    """


class CheckOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class AttestCheck:
    """One check and what it actually did."""

    check: str
    outcome: CheckOutcome
    detail: str

    @property
    def failed(self) -> bool:
        return self.outcome is CheckOutcome.FAIL

    def to_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "outcome": self.outcome.value,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# The document, read strictly.
# --------------------------------------------------------------------------


#: The largest integer JavaScript represents exactly. Both SDKs refuse counts
#: above it: the Node verifier cannot tell 2**53+1 from 2**53+2 after
#: ``JSON.parse``, so it would render a different decimal into the canonical
#: message than the one Core signed and report a forgery. Refusing in both
#: places keeps the two SDKs answering the same thing, at the cost of a ledger
#: limit no real deployment reaches.
MAX_SAFE_INTEGER = 9007199254740991


def _json_type(value: Any) -> str:
    """The JSON type name of a parsed value.

    Deliberately the JSON vocabulary rather than the host language's: Python
    would say ``str``/``dict``/``NoneType`` where Node says
    ``string``/``object``/``null``, and the two SDKs would then produce
    different text for the same malformed document.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return "unknown"


def _q(value: Any) -> str:
    """Quote a value for a human-readable detail line.

    Plain and identical in both SDKs — ``repr`` would not be (Python renders
    ``None`` where JavaScript renders ``null``, and escapes differently).
    """
    return "none" if value is None else f"'{value}'"


def _secs(value: float) -> str:
    """Render a duration for a detail line, truncated toward zero.

    Truncation rather than rounding because Python's ``:.0f`` rounds halves to
    even and JavaScript's ``toFixed(0)`` rounds them away from zero, so the two
    SDKs would print different sentences for the same attestation at exactly
    ``.5`` seconds.
    """
    return str(int(value))


def _require(doc: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in doc:
        return None
    return doc[key]


def _as_str(value: Any, where: str, *, allow_none: bool = False) -> Any:
    if value is None and allow_none:
        return None
    if not isinstance(value, str):
        raise AttestFormatError(f"{where}: expected a string, got {_json_type(value)}")
    return value


def _as_uint(value: Any, where: str, *, allow_none: bool = False) -> Any:
    if value is None and allow_none:
        return None
    # bool is a subclass of int in Python; True would render as "True" here and
    # as nothing Core ever produced.
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttestFormatError(
            f"{where}: expected an integer, got {_json_type(value)}"
        )
    if value < 0:
        raise AttestFormatError(
            f"{where}: expected a non-negative integer, got {value}"
        )
    if value > MAX_SAFE_INTEGER:
        raise AttestFormatError(
            f"{where}: {value} is above the {MAX_SAFE_INTEGER} both SDKs can "
            "render identically"
        )
    return value


def _as_bool(value: Any, where: str, *, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise AttestFormatError(f"{where}: expected a boolean, got {_json_type(value)}")
    return value


def _as_str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise AttestFormatError(f"{where}: expected an array, got {_json_type(value)}")
    out = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise AttestFormatError(
                f"{where}[{i}]: expected a string, got {_json_type(item)}"
            )
        out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class CapsuleFinding:
    """What the attestation found about one capsule. ``claimed_state`` is a
    claim the capsule makes about itself, never a verdict."""

    capsule_id: str
    claimed_state: str
    payload_present: bool
    payload_bytes: int | None
    issue: str | None
    terminal: bool

    @staticmethod
    def from_mapping(raw: Any, where: str) -> "CapsuleFinding":
        if not isinstance(raw, Mapping):
            raise AttestFormatError(f"{where}: expected an object")
        return CapsuleFinding(
            capsule_id=_as_str(
                _require(raw, "capsule_id", where), f"{where}.capsule_id"
            ),
            claimed_state=_as_str(
                _require(raw, "claimed_state", where), f"{where}.claimed_state"
            ),
            payload_present=_as_bool(
                _require(raw, "payload_present", where), f"{where}.payload_present"
            ),
            payload_bytes=_as_uint(
                _require(raw, "payload_bytes", where),
                f"{where}.payload_bytes",
                allow_none=True,
            ),
            issue=_as_str(
                _require(raw, "issue", where), f"{where}.issue", allow_none=True
            ),
            # `#[serde(default)]` on the Rust side: an older attestation without
            # the field means false, and must digest as false.
            terminal=_as_bool(
                _require(raw, "terminal", where), f"{where}.terminal", default=False
            ),
        )


@dataclass(frozen=True)
class ChainReport:
    """The ledger half. ``records_checked`` and ``first_break`` are outside the
    signature (see :data:`UNSIGNED_FIELDS`) and drive no verdict."""

    status: str
    records_checked: int
    last_seq: int
    curr_hash: str
    genesis_anchor: str
    first_break: str | None

    @staticmethod
    def from_mapping(raw: Any) -> "ChainReport":
        if not isinstance(raw, Mapping):
            raise AttestFormatError("chain: expected an object")
        return ChainReport(
            status=_as_str(_require(raw, "status", "chain"), "chain.status"),
            records_checked=_as_uint(
                _require(raw, "records_checked", "chain"), "chain.records_checked"
            ),
            last_seq=_as_uint(_require(raw, "last_seq", "chain"), "chain.last_seq"),
            curr_hash=_as_str(
                raw.get("curr_hash", ""), "chain.curr_hash"
            ),  # serde(default) = ""
            genesis_anchor=_as_str(
                _require(raw, "genesis_anchor", "chain"), "chain.genesis_anchor"
            ),
            first_break=_as_str(
                _require(raw, "first_break", "chain"),
                "chain.first_break",
                allow_none=True,
            ),
        )


@dataclass(frozen=True)
class AttestSignature:
    key_id: str
    public_key_hex: str
    signature_hex: str
    message_sha256: str

    @staticmethod
    def from_mapping(raw: Any) -> "AttestSignature":
        if not isinstance(raw, Mapping):
            raise AttestFormatError("signature: expected an object")
        return AttestSignature(
            key_id=_as_str(_require(raw, "key_id", "signature"), "signature.key_id"),
            public_key_hex=_as_str(
                _require(raw, "public_key_hex", "signature"), "signature.public_key_hex"
            ),
            signature_hex=_as_str(
                _require(raw, "signature_hex", "signature"), "signature.signature_hex"
            ),
            message_sha256=_as_str(
                _require(raw, "message_sha256", "signature"), "signature.message_sha256"
            ),
        )


@dataclass(frozen=True)
class Attestation:
    """One attestation, read from the wire without coercion."""

    generated_at: str
    host_fingerprint: str
    capsule_root: str
    nonce: str | None
    judged: int
    payload_missing: int
    inconsistent: int
    skipped_non_capsule: tuple[str, ...]
    findings: tuple[CapsuleFinding, ...]
    chain: ChainReport
    self_limit_tripped: str | None
    abnormal: tuple[str, ...]
    signature: AttestSignature | None


def parse_attestation(document: Mapping[str, Any]) -> Attestation:
    """Read a JSON-shaped attestation into :class:`Attestation`.

    Raises :class:`AttestFormatError` when a field is absent or the wrong type.
    """
    if not isinstance(document, Mapping):
        raise AttestFormatError("attestation: expected a JSON object")

    raw_findings = document.get("findings")
    if not isinstance(raw_findings, list):
        raise AttestFormatError(
            f"findings: expected an array, got {_json_type(raw_findings)}"
        )

    return Attestation(
        generated_at=_as_str(_require(document, "generated_at", ""), "generated_at"),
        host_fingerprint=_as_str(
            _require(document, "host_fingerprint", ""), "host_fingerprint"
        ),
        capsule_root=_as_str(_require(document, "capsule_root", ""), "capsule_root"),
        nonce=_as_str(_require(document, "nonce", ""), "nonce", allow_none=True),
        judged=_as_uint(_require(document, "judged", ""), "judged"),
        payload_missing=_as_uint(
            _require(document, "payload_missing", ""), "payload_missing"
        ),
        inconsistent=_as_uint(_require(document, "inconsistent", ""), "inconsistent"),
        skipped_non_capsule=_as_str_list(
            document.get("skipped_non_capsule"), "skipped_non_capsule"
        ),
        findings=tuple(
            CapsuleFinding.from_mapping(f, f"findings[{i}]")
            for i, f in enumerate(raw_findings)
        ),
        chain=ChainReport.from_mapping(_require(document, "chain", "")),
        self_limit_tripped=_as_str(
            _require(document, "self_limit_tripped", ""),
            "self_limit_tripped",
            allow_none=True,
        ),
        abnormal=_as_str_list(_require(document, "abnormal", ""), "abnormal"),
        signature=(
            None
            if document.get("signature") is None
            else AttestSignature.from_mapping(document["signature"])
        ),
    )


# --------------------------------------------------------------------------
# The signed message (contract §3).
# --------------------------------------------------------------------------


def findings_digest(findings: Sequence[CapsuleFinding]) -> str:
    """SHA-256, lowercase hex, over every finding in the order given.

    Each of the six parts is fed as an **8-byte little-endian length followed by
    the UTF-8 bytes**. The prefix is not decoration: with plain concatenation
    ``("ab", "c")`` and ``("a", "bc")`` hash identically, which is how a
    rewritten capsule id hides inside an issue string.

    The length is a count of BYTES, matching Rust's ``str::len()``. A capsule id
    outside ASCII is where a character count would silently diverge, so the
    conformance corpus carries one.
    """
    h = hashlib.sha256()
    for f in findings:
        parts = (
            f.capsule_id,
            f.claimed_state,
            "present" if f.payload_present else "absent",
            "terminal" if f.terminal else "live",
            "" if f.payload_bytes is None else str(f.payload_bytes),
            "" if f.issue is None else f.issue,
        )
        for part in parts:
            encoded = part.encode("utf-8")
            h.update(len(encoded).to_bytes(8, "little"))
            h.update(encoded)
    return h.hexdigest()


def canonical_message(att: Attestation) -> str:
    """The exact string Core signed (contract §3).

    Rebuilt field by field rather than by re-serializing the JSON: a signature
    over a re-serialized document breaks the moment either side changes a
    serializer, and the break looks like a forgery.
    """
    return (
        f"{ATTEST_MESSAGE_PREFIX}\n"
        f"generated_at={att.generated_at}\n"
        f"host={att.host_fingerprint}\n"
        f"root={att.capsule_root}\n"
        f"nonce={att.nonce or ''}\n"
        f"judged={att.judged}\n"
        f"payload_missing={att.payload_missing}\n"
        f"inconsistent={att.inconsistent}\n"
        f"chain_status={att.chain.status}\n"
        f"chain_last_seq={att.chain.last_seq}\n"
        f"chain_curr_hash={att.chain.curr_hash}\n"
        f"chain_genesis={att.chain.genesis_anchor}\n"
        f"chain_records_checked={att.chain.records_checked}\n"
        f"chain_first_break={att.chain.first_break or ''}\n"
        f"skipped_non_capsule={','.join(att.skipped_non_capsule)}\n"
        f"self_limit={att.self_limit_tripped or ''}\n"
        f"findings_sha256={findings_digest(att.findings)}\n"
        f"abnormal={';'.join(att.abnormal)}\n"
    )


# --------------------------------------------------------------------------
# What this deployment expects, and what it last saw.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestExpectation:
    """What a healthy attestation for *this* deployment must look like.

    ``public_key_hex`` and ``host_fingerprint`` are required and have no
    defaults. A verifier that accepted whatever key signed the document would be
    checking that an attacker can use Ed25519.
    """

    public_key_hex: str
    host_fingerprint: str
    #: The challenge that was sent with the request. ``None`` means none was
    #: sent, which is reported as a failure unless ``allow_unchallenged`` says
    #: the caller accepted that risk knowingly: without a nonce, an attestation
    #: taken before the data went missing replays perfectly.
    nonce: str | None = None
    allow_unchallenged: bool = False
    #: Optional label pin. The key is what authenticates; this catches a key
    #: rotation that changed the label without changing the key, or vice versa.
    key_id: str | None = None
    max_age_seconds: float = 3600.0
    #: How far ahead of local time ``generated_at`` may sit before it is read as
    #: a forged timestamp rather than clock skew between two honest machines.
    max_clock_skew_seconds: float = 60.0
    #: The capsules this deployment believes exist. Core does not hold an
    #: expected inventory (contract §6), so when this is ``None`` the
    #: ``inventory`` check reports ``skip`` — never ``pass``.
    capsule_ids: tuple[str, ...] | None = None
    #: Refuse to verify without a previous observation. A deployment past its
    #: first attestation should set this: with no baseline the silence check
    #: cannot run, so deleting the state file is otherwise a way to make it
    #: skip forever.
    require_previous: bool = False


@dataclass(frozen=True)
class AttestState:
    """The previous observation — the only thing that makes silence visible."""

    host_fingerprint: str
    public_key_hex: str
    last_seq: int
    curr_hash: str
    genesis_anchor: str
    generated_at: str
    observations: int = 1
    #: How many times a deliberate ledger reset has been acknowledged. Counted
    #: rather than forgotten: an operator asserting "this rotation was mine" is
    #: making a claim the SDK cannot verify, so the claim is kept.
    ledger_resets: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": STATE_SCHEMA,
            "host_fingerprint": self.host_fingerprint,
            "public_key_hex": self.public_key_hex,
            "last_seq": self.last_seq,
            "curr_hash": self.curr_hash,
            "genesis_anchor": self.genesis_anchor,
            "generated_at": self.generated_at,
            "observations": self.observations,
            "ledger_resets": self.ledger_resets,
        }

    @staticmethod
    def from_dict(raw: Any) -> "AttestState":
        if not isinstance(raw, Mapping):
            raise AttestStateError("state: expected a JSON object")
        schema = raw.get("schema")
        if schema != STATE_SCHEMA:
            raise AttestStateError(
                f"state: schema is {_q(schema)}, expected {_q(STATE_SCHEMA)}"
            )
        try:
            return AttestState(
                host_fingerprint=_as_str(
                    raw.get("host_fingerprint"), "state.host_fingerprint"
                ),
                public_key_hex=_as_str(
                    raw.get("public_key_hex"), "state.public_key_hex"
                ),
                last_seq=_as_uint(raw.get("last_seq"), "state.last_seq"),
                curr_hash=_as_str(raw.get("curr_hash"), "state.curr_hash"),
                genesis_anchor=_as_str(
                    raw.get("genesis_anchor"), "state.genesis_anchor"
                ),
                generated_at=_as_str(raw.get("generated_at"), "state.generated_at"),
                observations=_as_uint(raw.get("observations"), "state.observations"),
                # Optional: a state written before resets could be
                # acknowledged simply has not had one.
                ledger_resets=_as_uint(
                    raw.get("ledger_resets", 0), "state.ledger_resets"
                ),
            )
        except AttestFormatError as exc:
            raise AttestStateError(str(exc)) from exc


def load_state(path: str | Path) -> AttestState | None:
    """Read the previous observation.

    Returns ``None`` **only** when the file does not exist. A file that exists
    and cannot be read raises :class:`AttestStateError` instead of degrading to
    "no previous observation": the degradation is the bypass — corrupt the file
    and the silence check skips every run while the report stays green.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AttestStateError(
            f"state file {p} exists but could not be read: {exc}"
        ) from exc
    return AttestState.from_dict(raw)


def save_state(path: str | Path, state: AttestState) -> None:
    """Write the observation to compare the next attestation against."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Time.
# --------------------------------------------------------------------------


#: RFC3339 with a mandatory offset. Written out rather than delegated to
#: ``datetime.fromisoformat`` for two reasons: that function rejects a trailing
#: ``Z`` on Python 3.10 (a supported target, where every attestation would
#: therefore read as unreadable) and it accepts shapes the Node SDK's parser
#: does not, which is a divergence in what the two SDKs call a valid timestamp.
_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def _parse_rfc3339_ms(value: str) -> int:
    """Milliseconds since the epoch for an RFC3339 timestamp.

    Milliseconds, not microseconds, because JavaScript's clock has no finer
    resolution and the two SDKs must describe the same attestation with the same
    sentence. ``chrono`` emits up to 9 fractional digits; the extra ones are
    truncated rather than rounded, identically on both sides.
    """
    m = _RFC3339_RE.match(value.strip())
    if m is None:
        raise ValueError(f"{_q(value)} is not an RFC3339 timestamp with an offset")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    fraction = m.group(7) or ""
    offset = m.group(8)

    # datetime() raises on an impossible date (2026-02-30); Node checks the same
    # thing by round-tripping the constructed date.
    base = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    frac_ms = int((fraction[1:] + "000")[:3]) if fraction else 0
    if offset in ("Z", "z"):
        offset_minutes = 0
    else:
        sign = 1 if offset[0] == "+" else -1
        offset_minutes = sign * (int(offset[1:3]) * 60 + int(offset[4:6]))
    return int(base.timestamp()) * 1000 + frac_ms - offset_minutes * 60_000


def _now_ms(now: datetime | None) -> int:
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return int(now.timestamp() * 1000)


# --------------------------------------------------------------------------
# The verdict.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestVerdict:
    """The result of verifying one attestation."""

    checks: tuple[AttestCheck, ...]
    signature_verified: bool
    #: The observation to carry into the next verification, or ``None`` when the
    #: document did not earn the right to move the baseline.
    next_state: AttestState | None

    @property
    def findings(self) -> tuple[AttestCheck, ...]:
        """The checks that failed. Empty means nothing failed."""
        return tuple(c for c in self.checks if c.outcome is CheckOutcome.FAIL)

    @property
    def skipped(self) -> tuple[AttestCheck, ...]:
        """The checks that could not run. Never counted as clean."""
        return tuple(c for c in self.checks if c.outcome is CheckOutcome.SKIP)

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def exit_code(self) -> int:
        """``0`` clean / ``1`` abnormal. Never ``2``: this verdict exists, so a
        report was produced. ``2`` belongs to the caller that could not obtain
        one at all."""
        return EXIT_CLEAN if self.ok else EXIT_ABNORMAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "signature_verified": self.signature_verified,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [c.to_dict() for c in self.findings],
            "skipped": [c.to_dict() for c in self.skipped],
        }


_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def _hex_bytes(value: str, expected_len: int) -> bytes | None:
    # The syntax is checked before the length because ``bytes.fromhex``
    # tolerates ASCII whitespace between byte pairs (``'d0 4a'`` parses),
    # which the Node SDK's regex does not. Two SDKs that disagree about
    # what a public key looks like disagree about whether a deployment is
    # pinned to the right one.
    if _HEX_RE.match(value) is None or len(value) != expected_len * 2:
        return None
    return bytes.fromhex(value)


def verify_attestation(
    document: Mapping[str, Any],
    expect: AttestExpectation,
    previous: AttestState | None = None,
    *,
    now: datetime | None = None,
) -> AttestVerdict:
    """Verify one attestation against what this deployment expects.

    ``previous`` is the last verified observation (see :func:`load_state`).
    Without it the silence checks report ``skip``, which is why
    :attr:`AttestExpectation.require_previous` exists.

    The content checks run **only when the signature verifies**. On a document
    that is unsigned or forged they report ``skip``, not ``pass``: their answers
    would be about text an attacker chose, and "9 of 11 checks passed" on a
    forged document is a sentence no operator should ever be shown.
    """
    checks: list[AttestCheck] = []
    now_ms = _now_ms(now)

    def add(check: str, outcome: CheckOutcome, detail: str) -> None:
        checks.append(AttestCheck(check, outcome, detail))

    def skip_rest(reason: str, from_index: int) -> AttestVerdict:
        for name in ALL_CHECKS[from_index:]:
            add(name, CheckOutcome.SKIP, reason)
        return AttestVerdict(tuple(checks), False, None)

    # 1. Is this an attestation at all?
    try:
        att = parse_attestation(document)
    except AttestFormatError as exc:
        add(CHECK_DOCUMENT, CheckOutcome.FAIL, f"not a readable attestation: {exc}")
        return skip_rest("the document could not be read as an attestation", 1)
    add(
        CHECK_DOCUMENT,
        CheckOutcome.PASS,
        "the document has the shape of an attestation",
    )

    # 2. Signature. "No key configured" is not "nothing to check".
    if att.signature is None:
        add(
            CHECK_SIGNATURE_PRESENT,
            CheckOutcome.FAIL,
            "the attestation is unsigned — an unsigned statement is not a verified one",
        )
        return skip_rest("the attestation carries no signature", 2)
    add(
        CHECK_SIGNATURE_PRESENT,
        CheckOutcome.PASS,
        f"signed, key_id={_q(att.signature.key_id)}",
    )

    message = canonical_message(att)
    message_bytes = message.encode("utf-8")
    public_key = _hex_bytes(att.signature.public_key_hex, 32)
    signature = _hex_bytes(att.signature.signature_hex, 64)

    if public_key is None or signature is None:
        add(
            CHECK_SIGNATURE_VALID,
            CheckOutcome.FAIL,
            "public_key_hex must be 32 bytes of hex and signature_hex 64",
        )
        return skip_rest("the signature material is malformed", 3)

    if not ed25519_verify(public_key, message_bytes, signature):
        add(
            CHECK_SIGNATURE_VALID,
            CheckOutcome.FAIL,
            "the signature does not verify over the canonical message rebuilt "
            "from this document",
        )
        return skip_rest("the signature does not verify", 3)
    add(CHECK_SIGNATURE_VALID, CheckOutcome.PASS, "Ed25519 over the canonical message")

    # 3. From here the content is authenticated, so a finding about it means
    #    something.
    actual_digest = hashlib.sha256(message_bytes).hexdigest()
    if att.signature.message_sha256 != actual_digest:
        add(
            CHECK_MESSAGE_DIGEST,
            CheckOutcome.FAIL,
            f"message_sha256 says {att.signature.message_sha256} but the signed "
            f"message hashes to {actual_digest}",
        )
    else:
        add(
            CHECK_MESSAGE_DIGEST,
            CheckOutcome.PASS,
            "message_sha256 matches the signed message",
        )

    expected_key = expect.public_key_hex.strip().lower()
    presented_key = att.signature.public_key_hex.strip().lower()
    if presented_key != expected_key:
        add(
            CHECK_SIGNING_KEY,
            CheckOutcome.FAIL,
            f"signed by {presented_key}, expected {expected_key} — a valid "
            "signature by an unexpected key is an attacker with a key",
        )
    elif expect.key_id is not None and att.signature.key_id != expect.key_id:
        add(
            CHECK_SIGNING_KEY,
            CheckOutcome.FAIL,
            f"key_id is {_q(att.signature.key_id)}, expected {_q(expect.key_id)}",
        )
    else:
        add(CHECK_SIGNING_KEY, CheckOutcome.PASS, "signed by the pinned key")

    if att.host_fingerprint != expect.host_fingerprint:
        add(
            CHECK_HOST,
            CheckOutcome.FAIL,
            f"attestation is about {att.host_fingerprint}, this deployment is "
            f"pinned to {expect.host_fingerprint} — an attestation about another "
            "machine is not about your data",
        )
    else:
        add(CHECK_HOST, CheckOutcome.PASS, f"about {att.host_fingerprint}")

    if expect.nonce is not None:
        if att.nonce != expect.nonce:
            add(
                CHECK_NONCE,
                CheckOutcome.FAIL,
                f"nonce is {_q(att.nonce)}, the challenge sent was {_q(expect.nonce)}",
            )
        else:
            add(CHECK_NONCE, CheckOutcome.PASS, "the challenge came back")
    elif expect.allow_unchallenged:
        add(
            CHECK_NONCE,
            CheckOutcome.SKIP,
            "no freshness challenge was issued (allow_unchallenged); a replayed "
            "attestation is excluded by generated_at and the chain head alone",
        )
    else:
        add(
            CHECK_NONCE,
            CheckOutcome.FAIL,
            "no freshness challenge was issued, so this attestation cannot be "
            "distinguished from one taken before the data went missing; set "
            "allow_unchallenged to accept that knowingly",
        )

    try:
        generated_ms = _parse_rfc3339_ms(att.generated_at)
    except ValueError as exc:
        add(CHECK_FRESHNESS, CheckOutcome.FAIL, f"generated_at is unreadable: {exc}")
    else:
        age = (now_ms - generated_ms) / 1000
        if age > expect.max_age_seconds:
            add(
                CHECK_FRESHNESS,
                CheckOutcome.FAIL,
                f"generated {_secs(age)}s ago, older than the {_secs(expect.max_age_seconds)}s window",
            )
        elif -age > expect.max_clock_skew_seconds:
            add(
                CHECK_FRESHNESS,
                CheckOutcome.FAIL,
                f"generated {_secs(-age)}s in the future, beyond the "
                f"{_secs(expect.max_clock_skew_seconds)}s skew allowance",
            )
        else:
            add(CHECK_FRESHNESS, CheckOutcome.PASS, f"generated {_secs(age)}s ago")

    if att.abnormal:
        add(
            CHECK_CORE_ABNORMAL,
            CheckOutcome.FAIL,
            "Core reported: " + "; ".join(att.abnormal),
        )
    else:
        add(CHECK_CORE_ABNORMAL, CheckOutcome.PASS, "Core reported nothing abnormal")

    # Contract §4: `valid` means every record in the inspected range linked and
    # rehashed — and an EMPTY ledger is valid, a genuine zero-record chain.
    # `records_checked` is how a caller tells those apart, and it is inside the
    # signed message (it was not, until this verifier reported that), so it can
    # be relied on. The consequence is pinned as a corpus case rather than
    # silently accepted: a deployment holding capsules whose ledger has never
    # recorded anything verifies clean on a FIRST observation. From the second,
    # `sequence_advanced` catches it, because the head does not move.
    if att.chain.status != "valid":
        add(
            CHECK_CHAIN_STATUS,
            CheckOutcome.FAIL,
            f"audit chain status is {_q(att.chain.status)}, not 'valid' — "
            "absent is not intact",
        )
    else:
        add(CHECK_CHAIN_STATUS, CheckOutcome.PASS, "the audit chain verified")

    # 4. Silence. The check this whole layer exists for.
    if previous is None:
        if expect.require_previous:
            reason = (
                "no previous observation, and require_previous is set — a "
                "deployment past its first attestation must have a baseline, or "
                "deleting the state file silences the silence check"
            )
            add(CHECK_SEQUENCE_ADVANCED, CheckOutcome.FAIL, reason)
            add(CHECK_CHAIN_LINKED, CheckOutcome.FAIL, reason)
            add(CHECK_CHAIN_IDENTITY, CheckOutcome.FAIL, reason)
        else:
            reason = (
                "first attestation for this deployment — there is nothing to "
                "compare against, so silence cannot be ruled out yet"
            )
            add(CHECK_SEQUENCE_ADVANCED, CheckOutcome.SKIP, reason)
            add(CHECK_CHAIN_LINKED, CheckOutcome.SKIP, reason)
            add(CHECK_CHAIN_IDENTITY, CheckOutcome.SKIP, reason)
    else:
        if att.chain.last_seq > previous.last_seq:
            add(
                CHECK_SEQUENCE_ADVANCED,
                CheckOutcome.PASS,
                f"ledger head moved {previous.last_seq} -> {att.chain.last_seq}",
            )
        elif att.chain.last_seq == previous.last_seq:
            add(
                CHECK_SEQUENCE_ADVANCED,
                CheckOutcome.FAIL,
                f"the ledger head is still {att.chain.last_seq} — the same head as "
                "last time, again. A boundary that has stopped recording reports "
                "exactly this: nothing abnormal, chain valid, no losses",
            )
        else:
            add(
                CHECK_SEQUENCE_ADVANCED,
                CheckOutcome.FAIL,
                f"the ledger head went backwards, {previous.last_seq} -> "
                f"{att.chain.last_seq} — the ledger was truncated or replaced",
            )

        if att.chain.curr_hash and att.chain.curr_hash == previous.curr_hash:
            add(
                CHECK_CHAIN_LINKED,
                CheckOutcome.FAIL,
                f"the head hash is unchanged at {att.chain.curr_hash} — the ledger "
                "did not grow forward",
            )
        elif not att.chain.curr_hash:
            add(
                CHECK_CHAIN_LINKED,
                CheckOutcome.FAIL,
                "the attestation reports no head hash, so growth cannot be told "
                "from a rewrite to the same length",
            )
        else:
            add(
                CHECK_CHAIN_LINKED, CheckOutcome.PASS, "a new head hash at a new height"
            )

        if (
            previous.genesis_anchor
            and att.chain.genesis_anchor != previous.genesis_anchor
        ):
            add(
                CHECK_CHAIN_IDENTITY,
                CheckOutcome.FAIL,
                f"genesis anchor changed from {previous.genesis_anchor} to "
                f"{att.chain.genesis_anchor} — this is a different ledger, not a "
                "longer one",
            )
        else:
            add(CHECK_CHAIN_IDENTITY, CheckOutcome.PASS, "same ledger as last time")

    if att.judged == 0:
        add(
            CHECK_JUDGED_NONZERO,
            CheckOutcome.FAIL,
            "judged 0 capsules — an attestation over nothing cannot distinguish "
            "'intact' from 'not looked at'",
        )
    else:
        add(CHECK_JUDGED_NONZERO, CheckOutcome.PASS, f"judged {att.judged} capsule(s)")

    # The two signed loss counts, judged here rather than taken from Core's
    # verdict. Both are inside the canonical message, so reading them costs
    # nothing and removes a dependency: without these, a capsule with a real
    # problem reached this verdict only because Core had also written a line
    # into `abnormal`.
    if att.payload_missing:
        add(
            CHECK_PAYLOAD_INTACT,
            CheckOutcome.FAIL,
            f"{att.payload_missing} capsule(s) have no payload on disk. A "
            "terminal capsule with no body is correct and is not counted here, "
            "so this is loss rather than erasure",
        )
    else:
        add(
            CHECK_PAYLOAD_INTACT,
            CheckOutcome.PASS,
            "every non-terminal capsule examined had a body",
        )

    if att.inconsistent:
        add(
            CHECK_METADATA_CONSISTENT,
            CheckOutcome.FAIL,
            f"{att.inconsistent} capsule(s) disagree with their recorded state. "
            "The per-capsule reason is in findings[].issue, which the signature "
            "covers",
        )
    else:
        add(
            CHECK_METADATA_CONSISTENT,
            CheckOutcome.PASS,
            "no capsule disagreed with its recorded state",
        )

    if expect.capsule_ids is None:
        add(
            CHECK_INVENTORY,
            CheckOutcome.SKIP,
            "no expected capsule set was supplied; Core does not hold one "
            "(contract §6), so nothing here can tell 20 capsules reduced to 1 "
            "from a deployment that only ever had 1",
        )
    else:
        reported = {f.capsule_id for f in att.findings}
        missing = tuple(sorted(set(expect.capsule_ids) - reported))
        unexpected = tuple(sorted(reported - set(expect.capsule_ids)))
        if missing or unexpected:
            parts = []
            if missing:
                parts.append(f"expected but not reported: {', '.join(missing)}")
            if unexpected:
                parts.append(f"reported but not expected: {', '.join(unexpected)}")
            add(CHECK_INVENTORY, CheckOutcome.FAIL, "; ".join(parts))
        else:
            add(
                CHECK_INVENTORY,
                CheckOutcome.PASS,
                f"all {len(expect.capsule_ids)} expected capsule(s) reported",
            )

    # 5. The baseline only moves for an attestation that is about this
    #    deployment and signed by its key. Otherwise an attacker sets the
    #    baseline with one forged document and every later real one looks stale.
    next_state: AttestState | None = None
    if (
        presented_key == expected_key
        and att.host_fingerprint == expect.host_fingerprint
    ):
        next_state = AttestState(
            host_fingerprint=att.host_fingerprint,
            public_key_hex=presented_key,
            last_seq=att.chain.last_seq,
            curr_hash=att.chain.curr_hash,
            genesis_anchor=att.chain.genesis_anchor,
            generated_at=att.generated_at,
            observations=(previous.observations + 1) if previous else 1,
            # The verdict's observation describes THIS attestation. The reset
            # counter belongs to the stored baseline, so advance_state carries
            # it; zero here keeps the two SDKs serialising the same shape.
            ledger_resets=previous.ledger_resets if previous else 0,
        )

    return AttestVerdict(tuple(checks), True, next_state)


def advance_state(
    previous: AttestState | None,
    verdict: AttestVerdict,
    *,
    accept_ledger_reset: bool = False,
) -> AttestState | None:
    """The baseline to store after a verification, or ``None`` to leave it alone.

    **Monotone in both axes, independently.** The stored baseline carries two
    different facts — the highest ledger head that has been verified, and the
    most recent attestation that arrived — and neither may go backwards.

    Without that, a genuinely signed OLD attestation is a rollback tool. Replay
    the one from head 5, the baseline drops to 5, and every attestation between
    5 and the real head now "advances" again. The silence check would still be
    running, and would still be answering about a boundary that stopped
    recording days ago.

    Returns ``None`` when nothing moved forward, which the caller should treat
    as "do not rewrite the state file" rather than as an error.

    ``accept_ledger_reset`` is the one documented way past the monotone rule,
    and it exists because without it there was none. Core's ``genesis.json``
    lives beside the log and is re-read if present, so **sealing and rotating a
    ledger keeps the genesis anchor**: ``chain_identity`` does not notice, and
    ``sequence_advanced`` reports "the ledger went backwards" against the stored
    head — forever, because the head never lowers. The only escape was deleting
    the state file, which also destroys the last-report baseline and is exactly
    what an attacker clearing evidence would do.

    A rotation and a truncation are the same bytes: same genesis, lower head.
    This SDK cannot tell them apart and does not try. The flag records that an
    operator asserted it, increments :attr:`AttestState.ledger_resets`, and
    changes nothing about the verdict for the attestation in hand — that run
    still reports the drop.
    """
    nxt = verdict.next_state
    if nxt is None:
        # The document was not signed by this deployment's key, or was not about
        # its host. It has no business setting the baseline.
        return None
    if previous is None:
        return nxt

    head_forward = nxt.last_seq > previous.last_seq
    try:
        newer_report = _parse_rfc3339_ms(nxt.generated_at) > _parse_rfc3339_ms(
            previous.generated_at
        )
    except ValueError:
        # An unreadable timestamp is not a newer one.
        newer_report = False

    if accept_ledger_reset and nxt.last_seq < previous.last_seq:
        # The operator asserts this drop is a deliberate reset — a sealed and
        # rotated ledger. The SDK cannot check that: `genesis.json` survives a
        # rotation, so a rotation and a truncation are the same bytes on the
        # wire (same genesis, lower head). The assertion is therefore RECORDED,
        # not inferred, and the verification itself still reported the drop —
        # this only decides what the next run is compared against.
        return AttestState(
            host_fingerprint=nxt.host_fingerprint,
            public_key_hex=nxt.public_key_hex,
            last_seq=nxt.last_seq,
            curr_hash=nxt.curr_hash,
            genesis_anchor=nxt.genesis_anchor,
            generated_at=nxt.generated_at if newer_report else previous.generated_at,
            observations=previous.observations + 1,
            ledger_resets=previous.ledger_resets + 1,
        )

    if not head_forward and not newer_report:
        return None

    return AttestState(
        host_fingerprint=nxt.host_fingerprint,
        public_key_hex=nxt.public_key_hex,
        last_seq=nxt.last_seq if head_forward else previous.last_seq,
        curr_hash=nxt.curr_hash if head_forward else previous.curr_hash,
        genesis_anchor=nxt.genesis_anchor if head_forward else previous.genesis_anchor,
        generated_at=nxt.generated_at if newer_report else previous.generated_at,
        observations=previous.observations + 1,
        ledger_resets=previous.ledger_resets,
    )


# --------------------------------------------------------------------------
# The report that never came.
# --------------------------------------------------------------------------


def report_arrived_check(
    previous: AttestState | None,
    *,
    interval_seconds: float,
    now: datetime | None = None,
    grace_seconds: float = 0.0,
) -> AttestCheck:
    """Has an attestation arrived inside the expected interval?

    The contract's other half of silence: *"An expected report that never came
    is an anomaly the SDK raises on its own timer, not something it waits to be
    told about."* Nothing calls into Core here — the input is the last
    observation this verifier recorded and the clock.

    A deployment that has never produced a verified attestation **fails** this
    check rather than skipping it. There is no baseline, but there is also no
    report, and "no report at all" is the most complete form of the silence this
    exists to catch.
    """
    now_ms = _now_ms(now)
    deadline = interval_seconds + grace_seconds
    if previous is None:
        return AttestCheck(
            CHECK_REPORT_ARRIVED,
            CheckOutcome.FAIL,
            "no attestation has ever been verified for this deployment",
        )
    try:
        last_ms = _parse_rfc3339_ms(previous.generated_at)
    except ValueError as exc:
        return AttestCheck(
            CHECK_REPORT_ARRIVED,
            CheckOutcome.FAIL,
            f"the recorded generated_at is unreadable: {exc}",
        )
    age = (now_ms - last_ms) / 1000
    if age > deadline:
        return AttestCheck(
            CHECK_REPORT_ARRIVED,
            CheckOutcome.FAIL,
            f"the last attestation is {_secs(age)}s old, past the {_secs(deadline)}s "
            "interval — a report that never came is an anomaly, not silence to "
            "be waited out",
        )
    return AttestCheck(
        CHECK_REPORT_ARRIVED,
        CheckOutcome.PASS,
        f"the last attestation is {_secs(age)}s old, inside the {_secs(deadline)}s interval",
    )
