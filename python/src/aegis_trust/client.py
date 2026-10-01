"""Aegis-core REST API client wrapper.

Thin facade over the auto-generated client. Provides connection testing
and convenient access to the Aegis enterprise backend endpoints.
"""

from __future__ import annotations

import asyncio
import copy
import gc
import logging
import os
import time
import warnings
from typing import Any, Callable, Coroutine, Literal

import httpx
from dataclasses import dataclass, field

from aegis_trust._constants import AUDIT_SCHEMA_VERSION
from aegis_trust._delegation_context import (
    _delegation_denied,
    current_capability_for,
)
from aegis_trust.errors import (
    AegisAuditError,
    AegisHttpError,
    AegisIngestError,
    AegisValidationError,
    aegis_docs_url,
)
from aegis_trust.receipt_verify import is_value_free_label
from aegis_trust.types import (
    AuditChainStatus,
    CapabilityGrant,
    FieldStats,
    FunctionStats,
    IngestEntry,
    IngestResponse,
    PolicySyncEntry,
    PolicySyncResponse,
    PurposeStats,
    ShieldStats,
    StreamStatus,
)

logger = logging.getLogger("aegis")


# ── coded error envelopes (S022 audit remediation) ──────────────────
# Mirror of node/src/client.ts httpError/ingestError/auditError/aiNativeError:
# the documented error model is "switch on err.code across SDKs". Before this,
# the Python client raised raw ValueError / httpx.HTTPStatusError on the same
# conditions, so AegisHttpError/AegisIngestError were dead exports here.
# Catch-compat: the three shape errors subclass ValueError, and every internal
# fail-closed path catches broad Exception, so existing behavior is preserved.
def _http_error(endpoint: str, status: int) -> AegisHttpError:
    return AegisHttpError(
        f"{endpoint} HTTP {status}",
        code="aegis.http.nonOk",
        remediation="Inspect server logs; verify endpoint + token; retry if 5xx.",
        docs_url=aegis_docs_url("aegis.http.nonOk"),
        status=status,
    )


def _ensure_ok(resp: httpx.Response, endpoint: str) -> None:
    """Raise the coded non-2xx envelope (Node `if (!resp.ok) throw httpError`)."""
    if not resp.is_success:
        raise _http_error(endpoint, resp.status_code)


class _Unset:
    """Sentinel: "the caller passed nothing", distinct from an explicit
    ``None``. Mirrors Node's ``undefined`` vs ``null`` on
    :attr:`CheckBoundaryArgs.capability`: unset = attach the enclosing
    delegation token, ``None`` = opt out of the attachment for this call."""

    __slots__ = ()


_UNSET = _Unset()


def _ensure_boundary_ok(resp: httpx.Response, capability: str | None) -> None:
    """``_ensure_ok`` for ``/check-boundary``, naming the A-1 delegation refusal.

    A monolith-gateway deployment refuses a presented capability with 501
    rather than deciding at full width with the token unread (aegis_gateway
    ``rest.rs`` check_boundary, "A-1 delegation refusal"). That is the correct
    fail-closed answer, but a generic non-2xx makes it read as an outage —
    name the cause so the operator fixes the deployment, not the code.
    """
    if resp.status_code == 501 and capability is not None:
        raise AegisHttpError(
            "check-boundary HTTP 501 — deployment is not plane-fronted",
            code="aegis.boundary.delegationUnsupported",
            remediation=(
                "This deployment does not evaluate delegated capabilities: only "
                "the decide-plane serves check-boundary with A-1 delegation. "
                "Front the deployment with the plane. Do NOT strip the "
                "capability to get a 200 — that trades a refusal for a "
                "full-width answer the delegation was supposed to narrow. "
                "Fix the deployment."
            ),
            docs_url=aegis_docs_url("aegis.boundary.delegationUnsupported"),
            status=501,
        )
    _ensure_ok(resp, "check-boundary")


def _ingest_error(detail: str) -> AegisIngestError:
    return AegisIngestError(
        f"ingest: {detail}",
        code="aegis.ingest.responseShape",
        remediation=(
            "Server returned a malformed shield/ingest response. "
            "Check aegis-core version."
        ),
        docs_url=aegis_docs_url("aegis.ingest.responseShape"),
    )


def _audit_error(detail: str) -> AegisAuditError:
    return AegisAuditError(
        f"verify: {detail}",
        code="aegis.audit.responseShape",
        remediation=(
            "Server returned a malformed audit/verify response. "
            "Check aegis-core version."
        ),
        docs_url=aegis_docs_url("aegis.audit.responseShape"),
    )


def _ai_native_error(detail: str) -> AegisValidationError:
    return AegisValidationError(
        detail,
        code="aegis.aiNative.responseShape",
        remediation=(
            "Server returned a malformed AI-native response. Check the boundary "
            "version against AI_NATIVE_V1_CONTRACT.md (additive-only)."
        ),
        docs_url=aegis_docs_url("aegis.aiNative.responseShape"),
    )


_DEFAULT_BASE_URL = "https://localhost:8443/api/v1"

_base_url_path_completed_warned = False


def normalize_base_url(url: str) -> str:
    """Complete a pathless base URL to ``…/api/v1``.

    S015 install-friction fix (P-37, hit live this sprint): the gateway serves
    every endpoint under ``/api/v1``. A base URL of just host:port (no path)
    makes every call 404 with no hint it is a path problem. If the caller passes
    a pathless URL, complete it and warn once so the assumption is visible. An
    explicit non-root path is respected unchanged. Parity with node
    ``normalizeBaseUrl``.
    """
    global _base_url_path_completed_warned
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.scheme and parts.netloc and parts.path in ("", "/"):
        completed = urlunsplit((parts.scheme, parts.netloc, "/api/v1", "", ""))
        if not _base_url_path_completed_warned:
            _base_url_path_completed_warned = True
            logging.getLogger("aegis").warning(
                "base URL %r has no path; the gateway serves under '/api/v1', so "
                "using %r. Set the full URL to silence this.",
                url,
                completed,
            )
        return completed
    return url


_HEALTH_TIMEOUT = 2.0
_API_TIMEOUT = 10.0


def _resolve_access_cache_ttl() -> float:
    """TTL (seconds) for cached allow decisions.

    The cache spares repeated identical calls a gateway round-trip, but the
    window is also a fail-open exposure: a gateway that goes down or a policy
    that revokes access is not seen until the entry expires (S015 P-27,
    confirmed live). Set ``AEGIS_ACCESS_CACHE_TTL_S=0`` to disable the cache so
    every call re-consults the gateway (zero stale window, higher latency).
    Deny is never cached regardless. Default 30s.
    """
    raw = os.environ.get("AEGIS_ACCESS_CACHE_TTL_S")
    if raw is None or raw.strip() == "":
        return 30.0
    try:
        n = float(raw)
    except ValueError:
        return 30.0
    return n if n >= 0 else 30.0


_ACCESS_CACHE_TTL_S = _resolve_access_cache_ttl()

# Pluggable metrics callback. The SDK does not import any specific metrics
# library so users (or this process's other code) own the registry —
# embedding prometheus_client here would pollute every host process.
MetricsHook = Callable[[str, float, int], None]
_metrics_hook: MetricsHook | None = None


def set_metrics_hook(hook: MetricsHook | None) -> None:
    """Register a callback invoked after every backend request.

    Signature: ``hook(endpoint: str, duration_s: float, status: int) -> None``.
    Called even on non-200 responses. Exceptions raised by the hook are
    swallowed; instrumentation must never break the data path.

    Pass ``None`` to remove the hook. Hook is process-global, not per-client.
    """
    global _metrics_hook
    _metrics_hook = hook


def _emit_metric(endpoint: str, started: float, status: int) -> None:
    hook = _metrics_hook
    if hook is None:
        return
    try:
        hook(endpoint, time.monotonic() - started, status)
    except Exception:
        logger.debug("metrics hook raised; ignoring", exc_info=True)


def _clear_sensitive(*objs: Any) -> None:
    """Best-effort zeroize of sensitive values (AO-005, SDK-side).

    CPython does NOT guarantee prompt memory erasure for str/bytes: PyObject
    refs may survive in caches, tracebacks, or small-int/string interning. For
    bearer tokens and secret payloads this helper:

    1. Overwrites the original buffer in place when the value is a bytearray.
    2. Drops references and triggers a gc.collect() cycle.

    Authoritative zeroize is the gateway's responsibility — aegis-core runs in
    Rust where memory lifetime is deterministic. SDK cannot make that
    guarantee; it minimizes the surface instead. See SECURITY.md §Memory posture.
    """
    for obj in objs:
        if isinstance(obj, bytearray):
            for i in range(len(obj)):
                obj[i] = 0
    gc.collect()


@dataclass(frozen=True)
class CoreDecisionEvidence:
    """Evidence pointer attached to a Core BoundaryDecisionView."""

    decision_id: str
    policy: str
    enforced_by: str
    integrity_checkable_at: str
    recorded_at: str


@dataclass(frozen=True)
class BoundaryDecisionView:
    """Wire shape of the gateway's ``BoundaryDecisionView`` (POST
    ``/check-boundary``). ``outcome`` is the SCREAMING_SNAKE_CASE
    ``DecisionOutcome`` enum (``decision_bundle.rs``); ``reason_code`` is
    snake_case. Field *names* are surfaced (never values)."""

    source: str  # "CORE"
    outcome: (
        str  # PROTECTED | ACCESS_REDUCED | CHECK_REQUIRED | APPROVAL_REQUIRED | BLOCKED
    )
    purpose_label: str
    allowed_fields: list[str] = field(default_factory=list)
    withheld_fields: list[str] = field(default_factory=list)
    reason_code: str = ""
    reason_label: str = ""
    evidence_available: bool = False
    evidence: CoreDecisionEvidence | None = None
    # The response body exactly as received (a deep copy), including keys the
    # typed fields above do not surface. A Core that issues a boundary receipt
    # signs a digest of THIS object (minus the receipt keys), so a caller that
    # forwards the decision to a third party must forward ``raw``, not a view
    # rebuilt from the typed fields — those drop keys and could not reproduce
    # the digest. Excluded from ``==``.
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    # ``raw["boundary_receipt"]`` when the server attached one, else ``None``.
    # Carried, never checked: verification is the Core's public-key verifier
    # (``aegis-receipt-verify``), not something the SDK decides.
    boundary_receipt: dict[str, Any] | None = field(
        default=None, compare=False, repr=False
    )


# ── AI-native `decision` object: typed, fail-closed reader ───────────
# The AI-native wire (POST /tool-call, POST /stream/open) returns a shared
# `decision` object (contract: AI_NATIVE_V1_CONTRACT.md, additive-only) that
# carries more than the flat /check-boundary view does: the SERVER-DERIVED
# `fragment_tags[]`, the attribution trace `parts[]`, and the
# chain pointers `decision_id` / `receipt_event_id` / `ledgered`. Until now the
# SDK handed that object back as an untyped dict, so a caller could not read
# those fields without re-deriving the wire shape. This reader exposes them
# and refuses a malformed object instead of defaulting a field the wire did
# not send (a defaulted `fragment_tags: []` would claim "no tags released"
# for a plane that never said so).

#: The outcome vocabulary the authority can return (wire, SCREAMING_SNAKE_CASE).
AUTHORITY_OUTCOMES: tuple[str, ...] = (
    "PROTECTED",
    "ACCESS_REDUCED",
    "CHECK_REQUIRED",
    "APPROVAL_REQUIRED",
    "BLOCKED",
)
# Validation reads this private copy, so rebinding the public name cannot widen
# the vocabulary (parity with the Node reader's private frozen set).
_AUTHORITY_OUTCOME_SET = frozenset(AUTHORITY_OUTCOMES)
#: Severity rank of each outcome — the authority composes "most restrictive
#: wins", so the composed outcome can never rank below any partial's.
_OUTCOME_SEVERITY = {name: rank for rank, name in enumerate(AUTHORITY_OUTCOMES)}
#: The operator-facing verb is a pure function of the outcome on the wire.
_OUTCOME_VERB = {
    "PROTECTED": "allow",
    "ACCESS_REDUCED": "allow_reduced",
    "CHECK_REQUIRED": "require_classification",
    "APPROVAL_REQUIRED": "require_approval",
    "BLOCKED": "block",
}


@dataclass(frozen=True)
class BoundaryPartialView:
    """One boundary's verdict inside :attr:`AuthorityDecisionView.parts` —
    the attribution trace (which boundary said what). Field *names* and
    server-derived labels only. Immutable: sequences are tuples, and every
    member is required (no defaults — a partial cannot be fabricated with
    members silently left empty)."""

    boundary: str
    outcome: str
    reason_code: str
    reason_label: str
    allowed_fields: tuple[str, ...]
    withheld_fields: tuple[str, ...]
    fragment_tags: tuple[str, ...]


@dataclass(frozen=True)
class AuthorityDecisionView:
    """Typed view of the ``decision`` object the AI-native wire returns
    (``tool_call`` / ``stream_open`` bodies, ``stream_session().decision``).
    Intended to be built by :func:`parse_authority_decision`, which refuses a
    malformed object rather than defaulting a field the wire did not send; an
    instance constructed by hand carries none of that guarantee.

    ``fragment_tags`` are SERVER-DERIVED: the authority classifies the data
    reference and accumulates tags per session; a caller cannot under-declare
    them. ``parts`` is the attribution trace (every boundary partial that
    composed into ``outcome``). ``ledgered`` is the chain witness — an
    unledgered decision carries no evidence claim, so read ``fragment_tags``
    as released only when ``ledgered`` is True. ``decision_id`` doubles as
    the integrity-checkable ledger id.

    Immutable: sequences are tuples and the dataclass is frozen; every
    frozen-wire member is required (no defaults), so a view cannot be
    fabricated with members silently left empty.

    This is NOT the flat ``/check-boundary`` view: :class:`BoundaryDecisionView`
    carries neither ``fragment_tags`` nor ``parts`` (its ``evidence_available``
    is the ``ledgered`` bit and ``evidence.decision_id`` the decision id)."""

    outcome: str
    ledgered: bool
    decision_id: str
    receipt_event_id: str
    reason_code: str
    reason_label: str
    verb: str
    boundary: str
    allowed_fields: tuple[str, ...]
    withheld_fields: tuple[str, ...]
    fragment_tags: tuple[str, ...]
    parts: tuple[BoundaryPartialView, ...]
    policy_generation: int | None = None
    policy_digest: str | None = None
    replayed: bool = False


def _decision_shape_error(detail: str) -> AegisValidationError:
    return AegisValidationError(
        f"authority decision: {detail}",
        code="aegis.aiNative.decisionShape",
        remediation=(
            "The 'decision' object does not have the AI-native wire shape. "
            "Pass the 'decision' member of a tool_call / stream_open response "
            "(not the whole body) and check the boundary version against "
            "AI_NATIVE_V1_CONTRACT.md (additive-only)."
        ),
        docs_url=aegis_docs_url("aegis.aiNative.decisionShape"),
    )


#: Largest ``policy_generation`` both SDKs can carry exactly (JavaScript's
#: ``Number.MAX_SAFE_INTEGER``). A larger wire value would be rounded by one
#: SDK and kept exact by the other, so both refuse it.
_MAX_SAFE_INTEGER = 2**53 - 1


#: "Blank" for chain ids, defined identically in both SDKs: nothing but ASCII
#: whitespace. Python's ``str.strip()`` and JavaScript's ``trim()`` disagree
#: on Unicode whitespace (U+0085 vs U+FEFF), so neither is used.
_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"


def _is_blank(s: str) -> bool:
    return s.strip(_ASCII_WHITESPACE) == ""


def _str_tuple_or_none(raw: Any) -> tuple[str, ...] | None:
    # One traversal: the snapshot that is validated is the snapshot that is
    # returned. Validating ``raw`` and then materialising it again would let a
    # list subclass with a stateful iterator (or a concurrent mutation) hand
    # back elements the check never saw.
    if not isinstance(raw, list):
        return None
    snapshot = tuple(raw)
    if not all(isinstance(x, str) for x in snapshot):
        return None
    return snapshot


def _required_str(obj: dict[str, Any], key: str, where: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise _decision_shape_error(f"{where}'{key}' missing or not a string")
    return v


def _optional_str(obj: dict[str, Any], key: str, where: str) -> str | None:
    if key not in obj:
        return None
    v = obj[key]
    if not isinstance(v, str):
        raise _decision_shape_error(f"{where}'{key}' not a string")
    return v


def _required_outcome(obj: dict[str, Any], where: str) -> str:
    v = obj.get("outcome")
    if not isinstance(v, str) or v not in _AUTHORITY_OUTCOME_SET:
        raise _decision_shape_error(f"{where}'outcome' missing or unknown")
    return v


def _required_str_list(obj: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    v = _str_tuple_or_none(obj.get(key))
    if v is None:
        raise _decision_shape_error(f"{where}'{key}' missing or not a list of strings")
    return v


def _required_labels(obj: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    # Shape rule only (ASCII label charset, length cap — the receipt verifier's
    # gate): it refuses a tag that is not label-shaped, it does not classify
    # what a label-shaped string means. Tags are server-derived labels.
    tags = _required_str_list(obj, key, where)
    for t in tags:
        if not is_value_free_label(t):
            raise _decision_shape_error(
                f"{where}'{key}' member is not a value-free label"
            )
    return tags


def _parse_policy_generation(pg: Any) -> int:
    """A non-negative integer no larger than ``_MAX_SAFE_INTEGER``. JSON has
    one number type: a whole-number float on the wire (``3.0``) is the same
    wire value as ``3`` and is read as the integer 3 in both SDKs; anything
    fractional, non-finite, negative, boolean, or beyond the safe range is
    refused. (Rounding of over-precise literals happens inside the JSON
    decoder, before the reader, and identically in both SDKs.)"""
    if isinstance(pg, bool):
        raise _decision_shape_error("'policy_generation' not a non-negative integer")
    if isinstance(pg, float):
        if pg != pg or pg in (float("inf"), float("-inf")) or not pg.is_integer():
            raise _decision_shape_error(
                "'policy_generation' not a non-negative integer"
            )
        pg = int(pg)
    if not isinstance(pg, int) or pg < 0 or pg > _MAX_SAFE_INTEGER:
        raise _decision_shape_error("'policy_generation' not a non-negative integer")
    return pg


def _parse_part(raw: Any, index: int) -> BoundaryPartialView:
    where = f"'parts[{index}]' "
    if not isinstance(raw, dict):
        raise _decision_shape_error(f"{where}is not an object")
    return BoundaryPartialView(
        boundary=_required_str(raw, "boundary", where),
        outcome=_required_outcome(raw, where),
        reason_code=_required_str(raw, "reason_code", where),
        reason_label=_required_str(raw, "reason_label", where),
        allowed_fields=_required_str_list(raw, "allowed_fields", where),
        withheld_fields=_required_str_list(raw, "withheld_fields", where),
        fragment_tags=_required_labels(raw, "fragment_tags", where),
    )


def parse_authority_decision(decision: Any) -> AuthorityDecisionView:
    """Parse the AI-native ``decision`` object into an
    :class:`AuthorityDecisionView`, fail-closed.

    Required (present and correctly typed, else :class:`AegisValidationError`
    ``aegis.aiNative.decisionShape``) — every member the frozen wire declares:
    ``outcome`` (one of :data:`AUTHORITY_OUTCOMES`), ``ledgered`` (bool),
    ``decision_id``, ``receipt_event_id``, ``reason_code``, ``reason_label``,
    ``verb``, ``boundary`` (str), ``allowed_fields`` / ``withheld_fields``
    (list[str]), ``fragment_tags`` (list of labels that pass the value-free label
    SHAPE rule — ASCII label charset, length cap, the receipt verifier's
    gate; a tag outside that shape is refused. The rule does not classify
    meaning: tags are server-derived labels, and a label-shaped string is
    surfaced as-is), and ``parts`` (list of boundary partials, each validated
    the same way). Optional, typed when present (added to the wire after the
    freeze, or omitted by design): ``policy_generation`` (non-negative
    integer no larger than 2**53 - 1 so both SDKs carry it exactly; a
    whole-number float such as ``3.0`` is the same JSON value as ``3`` and
    reads as 3 in both; never a bool), ``policy_digest``, ``replayed`` (bool;
    the wire omits it when false). The chain witness is
    two-way: ``ledgered=True`` must carry non-blank ``decision_id`` /
    ``receipt_event_id`` (the claim is only as good as the ids that make it
    checkable; blank = nothing but ASCII whitespace, the same rule in both
    SDKs), and ``ledgered=False`` is only the hard-fault form —
    ``outcome`` BLOCKED, blank ids, no composed ``fragment_tags``, no
    ``allowed_fields`` / ``withheld_fields``, not ``replayed`` (the trace ``parts`` is preserved
    verbatim as the diagnostic of what was refused, tags and all — a
    partial's ``allowed_fields`` / ``fragment_tags`` describe what that
    boundary computed, they are never a grant);
    an executable outcome or a chain pointer on an unledgered decision is
    refused. A ledgered decision is also checked against its own trace: the
    composed ``outcome`` is at least as restrictive as every partial's (the
    authority composes most-restrictive-wins) and the composed
    ``fragment_tags`` contain every tag a partial carries (the authority
    composes the union), and the composed ``allowed_fields`` equal the
    winning partial's own allow set (the authority copies it verbatim, so a
    differing composed set is a grant the trace does not support). Unknown
    members are ignored (the contract is additive-only). ``verb`` must be the verb of
    ``outcome``; a ledgered decision with no trace at all is accepted only as
    the fail-closed BLOCKED form with an empty allow set. The returned view
    holds copies —
    mutating the input afterwards does not change it.

    Pass the ``decision`` MEMBER (``body["decision"]``), not the whole
    response body.
    """
    if not isinstance(decision, dict):
        raise _decision_shape_error("not an object")
    where = ""
    outcome = _required_outcome(decision, where)
    ledgered = decision.get("ledgered")
    if not isinstance(ledgered, bool):
        raise _decision_shape_error("'ledgered' missing or not a boolean")
    decision_id = _required_str(decision, "decision_id", where)
    receipt_event_id = _required_str(decision, "receipt_event_id", where)
    reason_code = _required_str(decision, "reason_code", where)
    reason_label = _required_str(decision, "reason_label", where)
    verb = _required_str(decision, "verb", where)
    if verb != _OUTCOME_VERB[outcome]:
        raise _decision_shape_error("'verb' does not match 'outcome'")
    boundary = _required_str(decision, "boundary", where)
    policy_digest = _optional_str(decision, "policy_digest", where)
    policy_generation: int | None = None
    if "policy_generation" in decision:
        policy_generation = _parse_policy_generation(decision["policy_generation"])
    replayed = False
    if "replayed" in decision:
        rp = decision["replayed"]
        if not isinstance(rp, bool):
            raise _decision_shape_error("'replayed' not a boolean")
        replayed = rp
    # The chain witness is two-way. ledgered=True must carry the ids that make
    # the claim checkable (blank counts as missing — receipt precedent).
    # ledgered=False is ONLY the hard-fault form: the union ledger refused the
    # write, so the decision is BLOCKED, carries no chain ids, releases no
    # tags and cannot be a replay. An executable outcome or a chain pointer on
    # an unledgered decision is a claim the chain never witnessed.
    if ledgered:
        if _is_blank(decision_id):
            raise _decision_shape_error("'decision_id' empty on a ledgered decision")
        if _is_blank(receipt_event_id):
            raise _decision_shape_error(
                "'receipt_event_id' empty on a ledgered decision"
            )
    else:
        if outcome != "BLOCKED":
            raise _decision_shape_error(
                "'outcome' must be BLOCKED on an unledgered decision"
            )
        if not _is_blank(decision_id):
            raise _decision_shape_error(
                "'decision_id' present on an unledgered decision"
            )
        if not _is_blank(receipt_event_id):
            raise _decision_shape_error(
                "'receipt_event_id' present on an unledgered decision"
            )
        if replayed:
            raise _decision_shape_error("'replayed' set on an unledgered decision")
        # Blank means blank: a whitespace-only id is normalised so a caller's
        # truthiness check cannot read it as a chain pointer.
        decision_id = ""
        receipt_event_id = ""
    allowed_fields = _required_str_list(decision, "allowed_fields", where)
    withheld_fields = _required_str_list(decision, "withheld_fields", where)
    fragment_tags = _required_labels(decision, "fragment_tags", where)
    if not ledgered and fragment_tags:
        raise _decision_shape_error("'fragment_tags' present on an unledgered decision")
    if not ledgered and allowed_fields:
        raise _decision_shape_error(
            "'allowed_fields' present on an unledgered decision"
        )
    if not ledgered and withheld_fields:
        raise _decision_shape_error(
            "'withheld_fields' present on an unledgered decision"
        )
    parts_raw = decision.get("parts")
    if not isinstance(parts_raw, list):
        raise _decision_shape_error("'parts' missing or not a list")
    # The trace is NOT constrained on a hard fault: the authority keeps the
    # partials the boundaries had already composed (with their own tags and
    # allow sets) as the value-free diagnostic of what was refused, and clears
    # only the composed result. Refusing tags inside the trace would reject a
    # legitimate ledger-outage response (cross-review round 4, codex, from
    # the authority's hard-fault constructor).
    parts = tuple(_parse_part(p, i) for i, p in enumerate(parts_raw))
    if ledgered:
        # The composed decision is derived from its parts: the outcome is the
        # most restrictive partial ("first-max", later gate steps may only
        # raise it) and the composed tags are the union of the partials' tags.
        # A ledgered decision whose top level is LESS restrictive than one of
        # its parts, or that drops a tag a part released, is contradictory —
        # a caller gating on the top level would fail open.
        composed_rank = _OUTCOME_SEVERITY[outcome]
        composed_tags = set(fragment_tags)
        winner: int | None = None
        for i, part in enumerate(parts):
            rank = _OUTCOME_SEVERITY[part.outcome]
            if rank > composed_rank:
                raise _decision_shape_error(
                    f"'outcome' less restrictive than 'parts[{i}]' 'outcome'"
                )
            if not composed_tags.issuperset(part.fragment_tags):
                raise _decision_shape_error(
                    f"'fragment_tags' missing tags carried by 'parts[{i}]'"
                )
            # first-max: only a STRICTLY greater severity replaces the winner
            if winner is None or rank > _OUTCOME_SEVERITY[parts[winner].outcome]:
                winner = i
        # The composed allow set IS the winner partial's own allow set (the
        # authority copies it verbatim, no widening step exists). A composed
        # allow set that differs from the winner's is a widened (or narrowed)
        # grant the trace does not support.
        if winner is not None and set(allowed_fields) != set(
            parts[winner].allowed_fields
        ):
            raise _decision_shape_error(
                f"'allowed_fields' differs from the winning 'parts[{winner}]'"
            )
        # No trace at all: the authority's compose of an empty partial list is
        # the fail-closed BLOCKED form with an empty allow set. A ledgered
        # grant with nothing to attribute it to is a grant without a witness.
        if winner is None and (outcome != "BLOCKED" or allowed_fields):
            raise _decision_shape_error(
                "'parts' empty on a ledgered decision that is not BLOCKED"
            )
    return AuthorityDecisionView(
        outcome=outcome,
        ledgered=ledgered,
        decision_id=decision_id,
        receipt_event_id=receipt_event_id,
        reason_code=reason_code,
        reason_label=reason_label,
        verb=verb,
        boundary=boundary,
        allowed_fields=allowed_fields,
        withheld_fields=withheld_fields,
        fragment_tags=fragment_tags,
        parts=parts,
        policy_generation=policy_generation,
        policy_digest=policy_digest,
        replayed=replayed,
    )


class AegisClient:
    """Client for the Aegis enterprise backend REST API.

    Most users never instantiate this directly — `@shield` auto-detects whether
    a backend is reachable and uses it transparently. Construct one explicitly
    only when you want to override the URL, supply an authentication token, or
    integrate with the enterprise backend from a non-decorator code path.

    Args:
        base_url: Backend base URL. Defaults to the local development endpoint
            when omitted.
        token: Bearer token sent on each request. Empty string disables auth.
        verify_ssl: Whether to verify the backend's TLS certificate. Defaults to
            True; set to False only for trusted local development.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = normalize_base_url(base_url or _DEFAULT_BASE_URL)
        self._token = token
        self._verify_ssl = verify_ssl
        self._httpx: httpx.Client | None = None
        self._async_httpx: httpx.AsyncClient | None = None
        # Cache key embeds _token_epoch so a token rotation invalidates
        # all prior allow decisions (deny is never cached).
        self._access_cache: dict[tuple[int, str, tuple[str, ...]], float] = {}
        self._token_epoch: int = 0
        # High-water mark of every ingest response — drives verify_inclusion().
        self._max_audit_seq: int = 0
        # Strong refs for tasks scheduled by set_token() so asyncio does
        # not drop them before aclose() runs (bpo-44665).
        self._pending_aclose_tasks: set[asyncio.Task[None]] = set()

    def _get_httpx(self) -> httpx.Client:
        """Get a plain httpx client (no auth header when token is empty)."""
        if self._httpx is None:
            self._httpx = httpx.Client(
                base_url=self._base_url,
                verify=self._verify_ssl,
                headers=self._auth_headers(),
                timeout=httpx.Timeout(_API_TIMEOUT),
            )
        return self._httpx

    def _get_async_httpx(self) -> httpx.AsyncClient:
        """Get an async httpx client. Lazily constructed on first async call.

        AsyncClient lets the @shield async path avoid blocking the event loop
        on the underlying POST.
        """
        if self._async_httpx is None:
            self._async_httpx = httpx.AsyncClient(
                base_url=self._base_url,
                verify=self._verify_ssl,
                headers=self._auth_headers(),
                timeout=httpx.Timeout(_API_TIMEOUT),
            )
        return self._async_httpx

    def _auth_headers(self) -> dict[str, str]:
        # Always attach the Aegis-Api-Version dated header.
        # Client contract: server may opt to respond per legacy semantics if it
        # supports older dated versions.
        from aegis_trust import AEGIS_API_VERSION, AEGIS_API_VERSION_HEADER

        headers: dict[str, str] = {AEGIS_API_VERSION_HEADER: AEGIS_API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def is_available(self) -> bool:
        """Check if the Aegis enterprise backend is reachable."""
        try:
            resp = httpx.get(
                f"{self._base_url}/health",
                verify=self._verify_ssl,
                timeout=_HEALTH_TIMEOUT,
            )
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, Exception):
            return False

    @staticmethod
    def _check_access_body(
        purpose: str, scope: list[str], tool_name: str = "shielded_call"
    ) -> dict[str, Any]:
        """Build the ``/check-access`` request body.

        Contract fix (CSR-03): the gateway's ``CheckAccessRequest.scope`` field
        is a single ``Option<String>`` advisory scope identifier (aegis_gateway
        ``rest.rs:296``), NOT an array. Sending a JSON array deserializes as a
        type error server-side (non-200 -> fail-closed), so the prior
        ``{"purpose", "scope": [...]}`` body silently broke every scope-bearing
        ``/check-access`` call. The authoritative gate is the JWT subject +
        purpose; ``scope`` is advisory minimum-disclosure metadata where ``None``
        means "purpose-level access only". This emits what the endpoint expects
        without changing :meth:`authorize`'s grant/deny contract:

        - 0 scopes  -> omit ``scope`` (None / purpose-level)
        - 1 scope   -> send the single string
        - >1 scopes -> see :meth:`authorize`/:meth:`aauthorize`: the caller
          FAILS CLOSED before a request is built (this body builder is never
          invoked with >1 scope on the gate path).

        Review finding B (fail-closed regression fix): a >1-scope check must NOT
        silently drop to purpose-level. Earlier, sending the array produced a
        server type error (non-2xx -> deny); the scope->``Option<String>`` fix
        turned ">1 scope" into "omit scope", which made the server evaluate at
        purpose-level and could ALLOW where the caller asked for a stricter,
        narrower scope — a fail-open regression. :meth:`authorize` therefore
        DENIES a multi-scope check rather than send a purpose-level request the
        single-scope server would evaluate more permissively than asked.

        NOTE: ``/check-boundary`` correctly uses ``scope: list[str]`` and does
        NOT route through here.

        ``tool_name`` is a REQUIRED (non-Option) field on the gateway's
        ``CheckAccessRequest`` (aegis_gateway ``rest.rs``). Omitting it makes the
        gateway reject the body with 422 -> fail-closed deny on EVERY FULL
        authorize, so a FULL gate can never grant against a live gateway. It is
        an audit LABEL only (it does not affect the allow/deny decision — that is
        JWT subject + purpose + scope). (Found by the S015 live SDK<->gateway
        e2e; same class as the Doctor-v1 ``agent_id`` always-BLOCK bug.)
        """
        body: dict[str, Any] = {
            "purpose": purpose,
            "tool_name": tool_name or "shielded_call",
        }
        if len(scope) == 1:
            body["scope"] = scope[0]
        return body

    def check_access(self, purpose: str, scope: list[str]) -> dict[str, Any]:
        """Check access permission via the Aegis enterprise backend."""
        resp = self._get_httpx().post(
            "/check-access",
            json=self._check_access_body(purpose, scope),
        )
        _ensure_ok(resp, "check-access")
        return resp.json()

    async def acheck_access(self, purpose: str, scope: list[str]) -> dict[str, Any]:
        """Async variant of :meth:`check_access`."""
        resp = await self._get_async_httpx().post(
            "/check-access",
            json=self._check_access_body(purpose, scope),
        )
        _ensure_ok(resp, "check-access")
        return resp.json()

    # ── check-boundary (Doctor v1, Core-backed) ───────────
    @staticmethod
    def _check_boundary_body(
        purpose: str,
        scope: list[str],
        *,
        origin: str,
        destination: str | None = None,
        destination_resource_id: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
        attribution: dict[str, Any] | None = None,
        synthetic: bool | None = None,
        capability: str | None | _Unset = _UNSET,
        action: str | None = None,
    ) -> dict[str, Any]:
        """Build the ``/check-boundary`` request body.

        ``action`` declares what the caller will DO at ``destination``:
        ``"read"`` or ``"write"``. It is sent verbatim as top-level ``action``
        and ONLY when set. The SDK does not trim, case-fold or validate it: the
        server compares it byte for byte, and a request that declares nothing,
        ``"write"``, or any other value is treated as a write. A server-side
        exemption for registered public-read sources applies only to a
        declared ``"read"``; servers that predate the field ignore it.

        ``destination_resource_id`` is an OPTIONAL caller-declared identifier
        of the concrete resource behind ``destination`` (for example a folder
        id or a channel id). It is sent verbatim as a top-level string and
        ONLY when set; the SDK neither validates it nor changes its own result
        on it. What the server does with the label is server-side policy, not
        a client guarantee.

        ``purpose`` + ``scope`` are required; ``scope`` is a *list* here (the
        boundary endpoint's contract, unlike ``/check-access``). The
        authenticated principal is the JWT subject server-side and is NEVER sent
        in the body; ``agent_id`` is advisory.

        ``attribution`` / ``synthetic`` are OPTIONAL enforcement-neutral
        witness claims for usage metering. They are NEVER authorization
        inputs — Core cannot change the decision on them; it only freezes hash
        witnesses into the receipt chain (a hash witness only, never the raw ids). Wire shape
        (the server-side consumer of these claims): top-level ``attribution:
        {"human": str, "on_behalf_of": [str]}`` — the human (and delegation
        chain) this request serves — and top-level ``synthetic: bool`` marking
        probe/drill traffic for billing exclusion. Both are sent verbatim and
        ONLY when set, so a claim-free call produces a byte-identical body to
        before these parameters existed.

        ``capability`` is the A-1 delegation token. It defaults to the token
        attached by the enclosing :func:`~aegis_trust.ai_native.delegate`
        window: a boundary the caller must REMEMBER to carry is fail-open by
        forgetting, the same reasoning that put ``guard_tool`` in the call
        path. An explicit value wins; explicit ``None`` opts out for one call.
        Wire shape is TOP-LEVEL ``capability`` — this flat face is not the
        envelope dialect, and sending ``delegation: {capability}`` here is
        refused 422 by the server-side flat-wire handler, precisely so a token in
        the wrong shape is never silently dropped and answered at full width.
        """
        body: dict[str, Any] = {"purpose": purpose, "scope": list(scope)}
        if destination is not None:
            body["destination"] = destination
        if destination_resource_id is not None:
            body["destination_resource_id"] = destination_resource_id
        if agent_id is not None:
            body["agent_id"] = agent_id
        if environment is not None:
            body["environment"] = environment
        if mode is not None:
            body["mode"] = mode
        if schema_version is not None:
            body["schema_version"] = schema_version
        if attribution is not None:
            body["attribution"] = attribution
        if synthetic is not None:
            body["synthetic"] = synthetic
        if action is not None:
            body["action"] = action
        # A denied window refuses HERE, before the wire: the mint failed, so
        # there is no token to narrow with, and asking un-narrowed would answer
        # at the PARENT's full width. ``allowed_fields`` on that answer is what
        # Doctor hands the agent as authorization (doctor.check_with_core →
        # BoundaryDecision.allowed_data), so a full-width answer inside a denied
        # window is a widening even though this method only asks a question.
        # Same local fail-closed as guard_tool / stream_session.
        #
        # The condition is "no concrete token supplied", NOT "argument unset".
        # Scoping it to ``_Unset`` left the explicit opt-out
        # (``capability=None``) as a way to walk straight past the refusal and
        # ask at parent width — the same widening this block exists to stop,
        # reachable by one keystroke. Opting out of attachment is meaningful in
        # a GRANTED window (ask this one question unnarrowed on purpose); inside
        # a DENIED window it is exactly the thing being denied. Only a caller
        # who brings their own token may proceed. Found by cross-review (codex +
        # cursor, independently, 2026-07-29) — the hole adjacent to the hole the
        # previous round closed. Node twin: client.ts checkBoundary.
        #
        # ``""`` counts as no token: it cannot narrow anything, so letting it
        # through would reopen the same door with an extra keystroke.
        if not (isinstance(capability, str) and capability):
            if _delegation_denied():
                raise AegisValidationError(
                    "check-boundary: the enclosing delegation window is "
                    "denied — not asked (fail-closed)",
                    code="aegis.boundary.delegationDenied",
                    remediation=(
                        "The enclosing delegate() window is denied — its "
                        "capability mint failed, so no narrowed decision can "
                        "be obtained. Fix the delegation (narrowing, depth, "
                        "revoked ancestor) or ask outside the window. Nothing "
                        "was sent; the answer would have been at the parent's "
                        "full width."
                    ),
                    docs_url=aegis_docs_url("aegis.boundary.delegationDenied"),
                )
        # Resolution is unchanged by the fix above: unset attaches the ambient
        # token, an explicit ``None`` still opts out for one call (now only
        # reachable outside a denied window), an explicit string wins.
        # Origin-bound read: the ambient token is attached ONLY if this client
        # is the one it was minted against. A bare bearer read would let a
        # second client in the same window ship a capability minted for one
        # boundary to a different base URL (cross-review, codex 2026-07-29,
        # severity high). Node twin: client.ts currentCapabilityFor.
        resolved = (
            current_capability_for(origin)
            if isinstance(capability, _Unset)
            else capability
        )
        if resolved is not None:
            body["capability"] = resolved
        return body

    @staticmethod
    def _parse_boundary_view(body: Any) -> BoundaryDecisionView:
        """Parse a ``/check-boundary`` 200 body into a
        :class:`BoundaryDecisionView`. Raises :class:`ValueError` on a malformed
        shape so the Doctor v1 entry point maps it to a fail-closed BLOCK.

        Review finding A (fail-closed): require the FULL ``BoundaryDecisionView``
        shape — a partial-but-valid-JSON body such as ``{"outcome": "PROTECTED"}``
        (every other field missing/defaulted) MUST NOT be trusted and map to
        ALLOW. Every required field must be present and correctly typed:
        ``source`` (str), ``outcome`` (str), ``allowed_fields`` (list[str]),
        ``withheld_fields`` (list[str]), ``reason_code`` (str). Any
        missing/mistyped required field -> ValueError -> CORE_MALFORMED_RESPONSE
        -> BLOCK.
        """
        if not isinstance(body, dict):
            raise ValueError("check-boundary: body is not a dict")
        source = body.get("source")
        if not isinstance(source, str):
            raise ValueError("check-boundary: 'source' missing or not a str")
        outcome = body.get("outcome")
        if not isinstance(outcome, str):
            raise ValueError("check-boundary: 'outcome' missing or not a str")
        reason_code = body.get("reason_code")
        if not isinstance(reason_code, str):
            raise ValueError("check-boundary: 'reason_code' missing or not a str")
        # allowed_fields / withheld_fields are REQUIRED here (no default): a
        # missing array is a malformed view, not an empty allow set.
        allowed = body.get("allowed_fields")
        withheld = body.get("withheld_fields")
        if not isinstance(allowed, list) or not all(
            isinstance(x, str) for x in allowed
        ):
            raise ValueError("check-boundary: 'allowed_fields' invalid")
        if not isinstance(withheld, list) or not all(
            isinstance(x, str) for x in withheld
        ):
            raise ValueError("check-boundary: 'withheld_fields' invalid")
        ev_raw = body.get("evidence")
        evidence: CoreDecisionEvidence | None = None
        if isinstance(ev_raw, dict):
            evidence = CoreDecisionEvidence(
                decision_id=str(ev_raw.get("decision_id", "")),
                policy=str(ev_raw.get("policy", "")),
                enforced_by=str(ev_raw.get("enforced_by", "")),
                integrity_checkable_at=str(ev_raw.get("integrity_checkable_at", "")),
                recorded_at=str(ev_raw.get("recorded_at", "")),
            )
        raw = copy.deepcopy(body)
        receipt = raw.get("boundary_receipt")
        return BoundaryDecisionView(
            source=source,
            outcome=outcome,
            purpose_label=str(body.get("purpose_label", "")),
            allowed_fields=list(allowed),
            withheld_fields=list(withheld),
            reason_code=reason_code,
            reason_label=str(body.get("reason_label", "")),
            evidence_available=bool(body.get("evidence_available", False)),
            evidence=evidence,
            raw=raw,
            boundary_receipt=receipt if isinstance(receipt, dict) else None,
        )

    def check_boundary(
        self,
        purpose: str,
        scope: list[str],
        *,
        destination: str | None = None,
        destination_resource_id: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
        attribution: dict[str, Any] | None = None,
        synthetic: bool | None = None,
        capability: str | None | _Unset = _UNSET,
        action: str | None = None,
    ) -> BoundaryDecisionView:
        """POST ``/check-boundary`` and return the parsed
        :class:`BoundaryDecisionView`. Reuses the same auth header / base-url /
        timeout / httpx plumbing as :meth:`check_access`. Non-2xx raises the
        coded :class:`AegisHttpError` (``aegis.http.nonOk``) so the Doctor v1
        entry point maps it to a fail-closed BLOCK.

        ``attribution`` (``{"human": str, "on_behalf_of": [str]}``) and
        ``synthetic`` are OPTIONAL enforcement-neutral witness claims: they
        NEVER change the decision (not authorization inputs); Core only
        freezes hash witnesses into the receipt. ``attribution`` claims the
        human (and delegation chain) this request serves; ``synthetic=True``
        marks probe/drill traffic for billing exclusion. Omitted claims leave
        the request body byte-identical to previous SDK versions.

        Deployment caveat (2026-07-16 wire audit): witnessing requires a
        decide-plane-fronted Core — the plane's ``/check-boundary`` wire
        carries both claims. The monolith gateway build's request struct does
        NOT include these fields and silently ignores them (HTTP 200, nothing
        witnessed), and the checkd bin carries ``attribution`` only. Do not
        rely on ``synthetic`` for billing exclusion until the serving
        deployment is confirmed plane-fronted.

        ``capability`` (A-1 delegation) defaults to the token attached by the
        enclosing :func:`~aegis_trust.ai_native.delegate` window; explicit
        ``None`` opts out for this call. A deployment that cannot evaluate a
        presented capability refuses with 501 rather than deciding at full
        width, surfaced here as ``aegis.boundary.delegationUnsupported``.
        """
        body = self._check_boundary_body(
            purpose,
            scope,
            origin=self._base_url,
            destination=destination,
            destination_resource_id=destination_resource_id,
            agent_id=agent_id,
            environment=environment,
            mode=mode,
            schema_version=schema_version,
            attribution=attribution,
            synthetic=synthetic,
            capability=capability,
            action=action,
        )
        resp = self._get_httpx().post("/check-boundary", json=body)
        _ensure_boundary_ok(resp, body.get("capability"))
        return self._parse_boundary_view(resp.json())

    def acheck_boundary(
        self,
        purpose: str,
        scope: list[str],
        *,
        destination: str | None = None,
        destination_resource_id: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
        attribution: dict[str, Any] | None = None,
        synthetic: bool | None = None,
        capability: str | None | _Unset = _UNSET,
        action: str | None = None,
    ) -> Coroutine[Any, Any, BoundaryDecisionView]:
        """Async variant of :meth:`check_boundary` (same enforcement-neutral
        witness-claim contract for ``attribution`` / ``synthetic``, and the
        same A-1 ``capability`` attachment / 501 refusal contract).

        Deliberately a plain ``def`` returning a coroutine, not an ``async
        def``: the ambient delegation token is read when you CALL this, not
        when the coroutine is awaited. An ``async def`` body runs entirely at
        await time, so ``coro = c.acheck_boundary(...)`` inside a
        ``delegate()`` window that is gathered after the window exits would
        read a reset ContextVar and ask at full width — silently, since
        nothing carries the token. Node's ``checkBoundary`` captures at the
        call expression (the sync prefix of the async function runs inside the
        AsyncLocalStorage scope); this keeps the two SDKs identical. The
        denied-window refusal below raises at call time for the same reason.
        """
        body = self._check_boundary_body(
            purpose,
            scope,
            origin=self._base_url,
            destination=destination,
            destination_resource_id=destination_resource_id,
            agent_id=agent_id,
            environment=environment,
            mode=mode,
            schema_version=schema_version,
            attribution=attribution,
            synthetic=synthetic,
            capability=capability,
            action=action,
        )
        return self._acheck_boundary_send(body)

    async def _acheck_boundary_send(self, body: dict[str, Any]) -> BoundaryDecisionView:
        """Send a body already built (and delegation-resolved) by the caller."""
        resp = await self._get_async_httpx().post("/check-boundary", json=body)
        _ensure_boundary_ok(resp, body.get("capability"))
        return self._parse_boundary_view(resp.json())

    # ── check_access enforcement (AO-003) ───────────────────────────
    def _cache_key(
        self, purpose: str, scope: list[str]
    ) -> tuple[int, str, tuple[str, ...]]:
        return (self._token_epoch, purpose, tuple(sorted(scope)))

    def _cached_allow(self, purpose: str, scope: list[str]) -> bool:
        cached = self._access_cache.get(self._cache_key(purpose, scope))
        return cached is not None and time.monotonic() < cached

    def _remember_allow(
        self, purpose: str, scope: list[str], *, epoch_at_request: int
    ) -> None:
        # Only cache when the request was issued under the current token
        # epoch. An in-flight authorize() started before set_token() must
        # not poison the cache for the new principal.
        if epoch_at_request != self._token_epoch:
            return
        self._access_cache[self._cache_key(purpose, scope)] = (
            time.monotonic() + _ACCESS_CACHE_TTL_S
        )

    @staticmethod
    def _check_access_allowed(body: Any) -> bool:
        """A 200 response is fail-OPEN unless the body explicitly says
        ``allowed=true``. Treat missing or malformed payloads as denied:
        AO-003 must default to deny.
        """
        if isinstance(body, dict):
            allowed = body.get("allowed")
            if isinstance(allowed, bool):
                return allowed
        return False

    def authorize(self, purpose: str, scope: list[str]) -> bool:
        """Sync gate: call check_access and return True iff backend allows.

        Returns False on 403 (deny), connection errors, malformed response, or
        a 200 whose body lacks ``{"allowed": true}``. A 200-allow result is
        cached for :data:`_ACCESS_CACHE_TTL_S` seconds, keyed by the current token
        epoch so token rotation invalidates the cache. Deny is never cached.

        Review finding B: a >1-scope request fails closed (deny) before any
        request is sent — see :meth:`_check_access_body`.
        """
        if len(scope) > 1:
            logger.warning(
                "authorize: >1 scope vs single-scope server, fail-closed (finding B)"
            )
            return False
        if self._cached_allow(purpose, scope):
            return True
        epoch_at_request = self._token_epoch
        t0 = time.monotonic()
        try:
            resp = self._get_httpx().post(
                "/check-access",
                json=self._check_access_body(purpose, scope),
            )
        except Exception:
            _emit_metric("check-access", t0, 0)
            logger.warning("authorize: transport error, fail-closed")
            return False
        _emit_metric("check-access", t0, resp.status_code)
        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                logger.warning("authorize: non-JSON 200 body, fail-closed")
                return False
            if self._check_access_allowed(body):
                self._remember_allow(purpose, scope, epoch_at_request=epoch_at_request)
                return True
            return False
        if resp.status_code == 403:
            return False
        logger.warning("authorize: unexpected %s, fail-closed", resp.status_code)
        return False

    async def aauthorize(self, purpose: str, scope: list[str]) -> bool:
        """Async variant of :meth:`authorize`."""
        if len(scope) > 1:
            logger.warning(
                "aauthorize: >1 scope vs single-scope server, fail-closed (finding B)"
            )
            return False
        if self._cached_allow(purpose, scope):
            return True
        epoch_at_request = self._token_epoch
        t0 = time.monotonic()
        try:
            resp = await self._get_async_httpx().post(
                "/check-access",
                json=self._check_access_body(purpose, scope),
            )
        except Exception:
            _emit_metric("check-access", t0, 0)
            logger.warning("aauthorize: transport error, fail-closed")
            return False
        _emit_metric("check-access", t0, resp.status_code)
        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                logger.warning("aauthorize: non-JSON 200 body, fail-closed")
                return False
            if self._check_access_allowed(body):
                self._remember_allow(purpose, scope, epoch_at_request=epoch_at_request)
                return True
            return False
        if resp.status_code == 403:
            return False
        logger.warning("aauthorize: unexpected %s, fail-closed", resp.status_code)
        return False

    def log_audit(
        self,
        *,
        purpose: str,
        tool_name: str,
        requester_id: str,
        decision: str,
        session_id: str | None = None,
        reason: str | None = None,
        bytes_returned: int | None = None,
    ) -> None:
        """Record an audit entry in the Aegis enterprise backend."""
        payload: dict[str, Any] = {
            "purpose": purpose,
            "tool_name": tool_name,
            "requester_id": requester_id,
            "decision": decision,
        }
        if session_id is not None:
            payload["session_id"] = session_id
        if reason is not None:
            payload["reason"] = reason
        if bytes_returned is not None:
            payload["bytes_returned"] = bytes_returned
        resp = self._get_httpx().post("/audit-log", json=payload)
        _ensure_ok(resp, "audit-log")

    # ── Shield API ─────────────────────────────────────────

    @staticmethod
    def _ingest_payload(entries: list[IngestEntry]) -> dict[str, Any]:
        return {
            "entries": [
                {
                    "function": e.function,
                    "purpose": e.purpose,
                    "scope": list(e.scope),
                    "blocked_fields": list(e.blocked_fields),
                    "timestamp": e.timestamp,
                    "count": e.count,
                    "deny_fields": list(e.deny_fields),
                    "schema_version": AUDIT_SCHEMA_VERSION,
                }
                for e in entries
            ]
        }

    @staticmethod
    def _parse_ingest_body(body: Any) -> IngestResponse:
        """Validate and extract an :class:`IngestResponse` from a 200 body.

        aegis-core can in principle return HTTP 200 with a shape that
        differs from the OpenAPI contract (bug, proxy rewrite, version
        drift). This helper centralizes strict schema checks and raises
        :class:`AegisIngestError` (``aegis.ingest.responseShape``, a
        :class:`ValueError` subclass) on any violation. The outer try/except
        in ``_shield_full`` treats that as a transport error and returns the
        AO-002 fail-closed empty result — never raise into the caller.
        """
        if not isinstance(body, dict):
            raise _ingest_error("body is not a dict")
        data = body.get("data")
        if not isinstance(data, dict):
            raise _ingest_error("body['data'] missing or not a dict")
        ingested = data.get("ingested")
        seq_start = data.get("audit_seq_start")
        seq_end = data.get("audit_seq_end")
        if not isinstance(ingested, int) or ingested < 0:
            raise _ingest_error("'ingested' invalid")
        if not isinstance(seq_start, int) or seq_start < 0:
            raise _ingest_error("'audit_seq_start' invalid")
        if not isinstance(seq_end, int) or seq_end < seq_start:
            raise _ingest_error("'audit_seq_end' invalid or non-monotonic")
        return IngestResponse(
            ingested=ingested,
            audit_seq_start=seq_start,
            audit_seq_end=seq_end,
        )

    def _record_seq(self, parsed: IngestResponse) -> IngestResponse:
        """Bump the highest observed audit seq so verify_inclusion() can
        prove later that this client's records landed in the chain."""
        if parsed.audit_seq_end > self._max_audit_seq:
            self._max_audit_seq = parsed.audit_seq_end
        return parsed

    @staticmethod
    def _require_full_acceptance(parsed: IngestResponse, expected: int) -> None:
        """FULL mode is audit-before-release: the gateway must durably accept
        ALL entries before the @shield path releases the filtered data.

        A contract-valid ``200 {"ingested": 0, ...}`` (or any
        ``ingested < expected``) means at least one audit record was NOT durably
        committed — releasing the data anyway is a fail-OPEN on audit
        completeness (AO-003). Raise so the ``_shield_full`` try/except returns
        the type-shaped empty (fail-closed) instead of leaking.

        Only ``ingested == expected`` is asserted: the ``audit_seq_*`` window is
        gateway-assigned and not contracted to equal the batch size (a valid
        response can carry ``ingested == 1`` with a wider seq range), so a
        window-size check would risk fail-closing a legitimate ingest.
        """
        if parsed.ingested != expected:
            raise _ingest_error(
                f"partial acceptance ({parsed.ingested}/{expected}) — "
                "audit incomplete, failing closed"
            )

    def ingest(self, entries: list[IngestEntry]) -> IngestResponse:
        """Send @shield block records to the Aegis enterprise backend (POST /shield/ingest)."""
        t0 = time.monotonic()
        resp = self._get_httpx().post(
            "/shield/ingest", json=self._ingest_payload(entries)
        )
        _emit_metric("shield.ingest", t0, resp.status_code)
        _ensure_ok(resp, "shield/ingest")
        parsed = self._parse_ingest_body(resp.json())
        self._require_full_acceptance(parsed, len(entries))
        return self._record_seq(parsed)

    async def aingest(self, entries: list[IngestEntry]) -> IngestResponse:
        """Async variant of :meth:`ingest`. Uses :class:`httpx.AsyncClient`
        so the @shield async path does not block the event loop.
        """
        t0 = time.monotonic()
        resp = await self._get_async_httpx().post(
            "/shield/ingest", json=self._ingest_payload(entries)
        )
        _emit_metric("shield.ingest", t0, resp.status_code)
        _ensure_ok(resp, "shield/ingest")
        parsed = self._parse_ingest_body(resp.json())
        self._require_full_acceptance(parsed, len(entries))
        return self._record_seq(parsed)

    # ── audit chain verification (AO-004) ───────────────────────────
    @staticmethod
    def _parse_chain_body(body: Any) -> AuditChainStatus:
        if not isinstance(body, dict):
            raise _audit_error("body is not a dict")
        chain_valid = body.get("chain_valid")
        total = body.get("total_entries")
        if not isinstance(chain_valid, bool):
            raise _audit_error("'chain_valid' must be bool")
        if not isinstance(total, int) or total < 0:
            raise _audit_error("'total_entries' invalid")
        return AuditChainStatus(chain_valid=chain_valid, total_entries=total)

    def verify_audit_chain(self) -> AuditChainStatus:
        """Verify the backend audit chain integrity (GET /audit/verify)."""
        resp = self._get_httpx().get("/audit/verify")
        _ensure_ok(resp, "audit/verify")
        return self._parse_chain_body(resp.json())

    async def averify_audit_chain(self) -> AuditChainStatus:
        """Async variant of :meth:`verify_audit_chain`."""
        resp = await self._get_async_httpx().get("/audit/verify")
        _ensure_ok(resp, "audit/verify")
        return self._parse_chain_body(resp.json())

    def verify_inclusion(self, *, seq_end: int | None = None) -> bool:
        """Per-call non-repudiation gate (AO-004).

        Returns True iff the backend chain is currently valid AND it
        contains entries up to ``seq_end`` (defaults to the highest seq
        this client ever ingested via :meth:`ingest`). A bare
        `/audit/verify` only proves chain health; this proves *this*
        call's record is included.
        """
        target = seq_end if seq_end is not None else self._max_audit_seq
        if target <= 0:
            return False
        try:
            status = self.verify_audit_chain()
        except Exception:
            logger.warning("verify_inclusion: chain query failed, fail-closed")
            return False
        return status.chain_valid and status.total_entries >= target

    async def averify_inclusion(self, *, seq_end: int | None = None) -> bool:
        """Async variant of :meth:`verify_inclusion`."""
        target = seq_end if seq_end is not None else self._max_audit_seq
        if target <= 0:
            return False
        try:
            status = await self.averify_audit_chain()
        except Exception:
            logger.warning("averify_inclusion: chain query failed, fail-closed")
            return False
        return status.chain_valid and status.total_entries >= target

    async def ais_available(self) -> bool:
        """Async variant of :meth:`is_available`."""
        try:
            resp = await self._get_async_httpx().get("/health", timeout=_HEALTH_TIMEOUT)
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, Exception):
            return False

    async def aclose(self) -> None:
        """Close any open async client (called from tests / shutdown)."""
        if self._async_httpx is not None:
            await self._async_httpx.aclose()
            self._async_httpx = None

    # ── AI-native v1: tool-call / capability lineage / streaming ─────
    # Wire contract: boundary-core docs/AI_NATIVE_V1_CONTRACT.md (frozen
    # 2026-07-03, additive-only; /api/v1 base is the SDK-canonical form).
    # These are the WIRE-FLOOR methods — the in-path interposition layer
    # (MCP proxy / @guard_tool / delegate() / stream_session()) builds on
    # them; application code should prefer that layer so the boundary sits
    # IN the call path, not beside it.

    #: Decision outcomes that permit the guarded action to proceed.
    PASSING_OUTCOMES = ("PROTECTED", "ACCESS_REDUCED")

    @staticmethod
    def _require_decision(body: Any, op: str) -> dict[str, Any]:
        """Fail-closed shape check for decision-bearing responses."""
        if not isinstance(body, dict):
            raise _ai_native_error(f"{op}: body is not a dict")
        decision = body.get("decision")
        if not isinstance(decision, dict):
            raise _ai_native_error(f"{op}: 'decision' missing or not a dict")
        if not isinstance(decision.get("outcome"), str):
            raise _ai_native_error(f"{op}: 'decision.outcome' missing")
        if not isinstance(decision.get("ledgered"), bool):
            raise _ai_native_error(f"{op}: 'decision.ledgered' missing")
        return body

    @staticmethod
    def _tool_call_body(
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None,
        session_id: str | None,
        destination: str | None,
        capability: str | None,
        action: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": tool,
            "purpose": purpose,
            "owner": owner,
            "fields": list(fields or []),
        }
        if session_id is not None:
            payload["session_id"] = session_id
        if destination is not None:
            payload["destination"] = destination
        if capability is not None:
            payload["capability"] = capability
        if action is not None:
            payload["action"] = action
        return payload

    def tool_call(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
        action: str | None = None,
    ) -> dict[str, Any]:
        """Decide ONE tool invocation at the boundary (POST /tool-call).

        Arguments never leave the caller — refs and labels only.
        Returns ``{"decision": ..., "enforcement": ...}``; a BLOCKED outcome
        is still HTTP 200 — gate on ``decision["outcome"]`` being in
        :data:`PASSING_OUTCOMES` AND ``decision["ledgered"]`` (or use
        :meth:`tool_allowed`).

        ``action`` (``"read"`` / ``"write"``) declares what the tool will do at
        ``destination``; sent verbatim as top-level ``action`` and only when
        set, with the same contract as :meth:`check_boundary`. The returned
        dict is the response body as received, so a ``boundary_receipt`` the
        server attaches stays in it.
        """
        t0 = time.monotonic()
        resp = self._get_httpx().post(
            "/tool-call",
            json=self._tool_call_body(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
                action=action,
            ),
        )
        _emit_metric("tool_call", t0, resp.status_code)
        _ensure_ok(resp, "tool-call")
        return self._require_decision(resp.json(), "tool-call")

    async def atool_call(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
        action: str | None = None,
    ) -> dict[str, Any]:
        """Async variant of :meth:`tool_call` (the per-tool-call hot path)."""
        t0 = time.monotonic()
        resp = await self._get_async_httpx().post(
            "/tool-call",
            json=self._tool_call_body(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
                action=action,
            ),
        )
        _emit_metric("tool_call", t0, resp.status_code)
        _ensure_ok(resp, "tool-call")
        return self._require_decision(resp.json(), "tool-call")

    def tool_allowed(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
        action: str | None = None,
    ) -> bool:
        """Fail-closed boolean gate over :meth:`tool_call` (authorize() parity):
        any transport error, non-200, malformed body, non-passing outcome, or
        unledgered decision is a deny."""
        try:
            body = self.tool_call(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
                action=action,
            )
        except Exception:
            logger.warning("tool_allowed: request failed, fail-closed deny")
            return False
        decision = body["decision"]
        return decision["outcome"] in self.PASSING_OUTCOMES and decision["ledgered"]

    async def atool_allowed(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
        action: str | None = None,
    ) -> bool:
        """Async variant of :meth:`tool_allowed` (same fail-closed contract)."""
        try:
            body = await self.atool_call(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
                action=action,
            )
        except Exception:
            logger.warning("tool_allowed: request failed, fail-closed deny")
            return False
        decision = body["decision"]
        return decision["outcome"] in self.PASSING_OUTCOMES and decision["ledgered"]

    @staticmethod
    def _parse_capability_grant(body: Any) -> CapabilityGrant:
        if not isinstance(body, dict):
            raise _ai_native_error("capability/mint: body is not a dict")
        token = body.get("capability")
        cap_id = body.get("id")
        exp = body.get("exp")
        depth = body.get("depth")
        root = body.get("root_delegator")
        if not isinstance(token, str) or not token:
            raise _ai_native_error("capability/mint: 'capability' missing")
        if not isinstance(cap_id, str) or not cap_id:
            raise _ai_native_error("capability/mint: 'id' missing")
        if not isinstance(exp, int) or exp <= 0:
            raise _ai_native_error("capability/mint: 'exp' invalid")
        if not isinstance(depth, int) or depth <= 0:
            raise _ai_native_error("capability/mint: 'depth' invalid")
        if not isinstance(root, str) or not root:
            raise _ai_native_error("capability/mint: 'root_delegator' missing")
        return CapabilityGrant(
            capability=token, id=cap_id, exp=exp, depth=depth, root_delegator=root
        )

    def capability_mint(
        self,
        for_agent: str,
        purposes: list[str],
        *,
        scope: list[str] | None = None,
        tools: list[str] | None = None,
        ttl_secs: int | None = None,
        parent_capability: str | None = None,
    ) -> CapabilityGrant:
        """Mint a delegation capability (POST /capability/mint).

        Root grants are bounded by the caller's role NOW; a child grant
        (``parent_capability``) can only NARROW its parent. The boundary
        witnesses the mint on the chain BEFORE returning the token.
        """
        payload: dict[str, Any] = {
            "for_agent": for_agent,
            "purposes": list(purposes),
            "scope": list(scope or []),
            "tools": list(tools or []),
        }
        if ttl_secs is not None:
            payload["ttl_secs"] = int(ttl_secs)
        if parent_capability is not None:
            payload["parent_capability"] = parent_capability
        resp = self._get_httpx().post("/capability/mint", json=payload)
        _ensure_ok(resp, "capability/mint")
        return self._parse_capability_grant(resp.json())

    def capability_revoke(
        self,
        *,
        capability: str | None = None,
        capability_id: str | None = None,
    ) -> str:
        """Revoke a capability (POST /capability/revoke). Present the token
        (holder / delegator / root delegator) or, as Admin, the id. Returns
        the revoked id. Revocation is transitive and cuts matching streams."""
        payload: dict[str, Any] = {}
        if capability is not None:
            payload["capability"] = capability
        if capability_id is not None:
            payload["capability_id"] = capability_id
        resp = self._get_httpx().post("/capability/revoke", json=payload)
        _ensure_ok(resp, "capability/revoke")
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise _ai_native_error("capability/revoke: 'ok' missing")
        revoked = body.get("revoked")
        if not isinstance(revoked, str) or not revoked:
            raise _ai_native_error("capability/revoke: 'revoked' missing")
        return revoked

    def stream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Open a continuous-authz stream (POST /stream/open) with a full
        Common Envelope. Returns ``{"decision":…, "enforcement":…, "stream":…}``
        — ``stream`` is non-null (``{"stream_id":…, "status":"open"}``) iff the
        decision passes AND is ledgered."""
        resp = self._get_httpx().post("/stream/open", json={"envelope": envelope})
        _ensure_ok(resp, "stream/open")
        return self._parse_stream_open(
            self._require_decision(resp.json(), "stream/open")
        )

    @staticmethod
    def _parse_stream_open(body: Any) -> dict[str, Any]:
        stream = body.get("stream")
        if stream is not None:
            if not isinstance(stream, dict) or not isinstance(
                stream.get("stream_id"), str
            ):
                raise _ai_native_error("stream/open: 'stream.stream_id' missing")
        return body

    async def astream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Async variant of :meth:`stream_open`."""
        resp = await self._get_async_httpx().post(
            "/stream/open", json={"envelope": envelope}
        )
        _ensure_ok(resp, "stream/open")
        return self._parse_stream_open(
            self._require_decision(resp.json(), "stream/open")
        )

    @staticmethod
    def _parse_stream_status(body: Any) -> StreamStatus:
        if not isinstance(body, dict) or not isinstance(body.get("status"), str):
            raise _ai_native_error("stream/heartbeat: 'status' missing")
        reason = body.get("reason")
        return StreamStatus(
            status=body["status"],
            reason=reason if isinstance(reason, str) else None,
        )

    def stream_heartbeat(self, stream_id: str) -> StreamStatus:
        """Revalidate a stream NOW (POST /stream/heartbeat) against the live
        registries (duress / legal hold / delegation expiry). ``status`` is
        ``ok | revoked | closed``; anything but ``ok`` means STOP."""
        resp = self._get_httpx().post(
            "/stream/heartbeat", json={"stream_id": stream_id}
        )
        _ensure_ok(resp, "stream/heartbeat")
        return self._parse_stream_status(resp.json())

    async def astream_heartbeat(self, stream_id: str) -> StreamStatus:
        """Async variant of :meth:`stream_heartbeat` (the background-loop path)."""
        resp = await self._get_async_httpx().post(
            "/stream/heartbeat", json={"stream_id": stream_id}
        )
        _ensure_ok(resp, "stream/heartbeat")
        return self._parse_stream_status(resp.json())

    def stream_close(self, stream_id: str) -> bool:
        """Close a stream (POST /stream/close; owner or Admin). Witnessed."""
        resp = self._get_httpx().post("/stream/close", json={"stream_id": stream_id})
        _ensure_ok(resp, "stream/close")
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise _ai_native_error("stream/close: 'ok' missing")
        return True

    async def astream_close(self, stream_id: str) -> bool:
        """Async variant of :meth:`stream_close`."""
        resp = await self._get_async_httpx().post(
            "/stream/close", json={"stream_id": stream_id}
        )
        _ensure_ok(resp, "stream/close")
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise _ai_native_error("stream/close: 'ok' missing")
        return True

    # ── token rotation (AO-001 + AO-004) ────────────────────────────
    def set_token(self, new_token: str) -> None:
        """Rotate the bearer token used for subsequent requests.

        The module-level :class:`AegisClient` is cached in :mod:`aegis.shield`
        which previously meant ``os.environ["AEGIS_TOKEN"]`` updates never
        reached the backend — every request kept using the token captured at
        first ``_get_client()`` call. This method:

        1. Updates the stored token.
        2. Schedules a close of the old sync/async httpx clients so their
           sockets are released (no FD leak on rotation).
        3. Invalidates the check-access cache — token changes imply a
           different principal and previous allow decisions are no longer
           authoritative.
        4. Best-effort zeroize of the old token if it was a ``bytearray``.

        Async-client shutdown: if called from a running event loop the
        old ``AsyncClient.aclose()`` is scheduled as a task; if there is
        no running loop a warning is emitted and the client is left for
        GC (the sync path is always closed inline).
        """
        old = self._token
        old_sync = self._httpx
        old_async = self._async_httpx
        self._token = new_token
        # Bump epoch so any in-flight authorize() captured under the prior
        # epoch becomes a no-op when it tries to cache its result.
        self._token_epoch += 1
        if isinstance(old, bytearray):
            _clear_sensitive(old)
        self._httpx = None
        self._async_httpx = None
        self._access_cache.clear()

        # Deterministic close of the sync client — cheap, always safe.
        if old_sync is not None:
            try:
                old_sync.close()
            except Exception:  # pragma: no cover
                logger.debug("set_token: sync client close raised", exc_info=True)

        # Async client close needs an event loop. Schedule it if we have
        # one; warn loudly if we do not, so operators catch rotations
        # happening outside of async contexts.
        if old_async is not None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                task = loop.create_task(old_async.aclose())
                # Keep a strong reference until the task finishes —
                # asyncio stores only a weak ref internally (bpo-44665).
                self._pending_aclose_tasks.add(task)
                task.add_done_callback(self._pending_aclose_tasks.discard)
            else:
                warnings.warn(
                    "AegisClient.set_token() called outside an event loop "
                    "while an async httpx client was open; its socket will "
                    "be released by GC. Call `await client.aclose()` before "
                    "rotating to free the FD immediately.",
                    ResourceWarning,
                    stacklevel=2,
                )

    def policy_sync(self, purposes: dict[str, PolicySyncEntry]) -> PolicySyncResponse:
        """Sync SDK purpose policies to the Aegis enterprise backend (POST /shield/policy-sync).

        Requires Admin role on the the Aegis enterprise backend side.
        """
        payload = {
            "purposes": {
                name: {
                    "scope": list(entry.scope),
                    "deny_fields": list(entry.deny_fields),
                }
                for name, entry in purposes.items()
            }
        }
        resp = self._get_httpx().post("/shield/policy-sync", json=payload)
        _ensure_ok(resp, "shield/policy-sync")
        data = resp.json()["data"]
        return PolicySyncResponse(
            synced=data["synced"],
            added=data.get("added", []),
            updated=data.get("updated", []),
        )

    def get_stats(
        self,
        *,
        from_time: str | None = None,
        to_time: str | None = None,
        purpose: str | None = None,
    ) -> ShieldStats:
        """Retrieve shield statistics (GET /shield/stats)."""
        params: dict[str, str] = {}
        if from_time is not None:
            params["from"] = from_time
        if to_time is not None:
            params["to"] = to_time
        if purpose is not None:
            params["purpose"] = purpose
        resp = self._get_httpx().get("/shield/stats", params=params)
        _ensure_ok(resp, "shield/stats")
        data = resp.json()["data"]
        return ShieldStats(
            period_from=data["period"]["from"],
            period_to=data["period"]["to"],
            total_calls=data["total_calls"],
            total_blocked_fields=data["total_blocked_fields"],
            by_purpose={
                k: PurposeStats(calls=v["calls"], blocked=v["blocked"])
                for k, v in data.get("by_purpose", {}).items()
            },
            by_field={
                k: FieldStats(blocked_count=v["blocked_count"])
                for k, v in data.get("by_field", {}).items()
            },
            by_function={
                k: FunctionStats(calls=v["calls"], purposes=v.get("purposes", []))
                for k, v in data.get("by_function", {}).items()
            },
        )

    def get_report(
        self, *, fmt: Literal["json", "pdf"] = "json"
    ) -> dict[str, Any] | bytes:
        """Retrieve shield audit report (GET /shield/report).

        Args:
            fmt: "json" (default) or "pdf".

        Returns:
            dict for JSON format, bytes for PDF format.
        """
        params = {"format": fmt} if fmt != "json" else {}
        resp = self._get_httpx().get("/shield/report", params=params)
        _ensure_ok(resp, "shield/report")
        if fmt == "pdf":
            return resp.content
        return resp.json()["data"]
