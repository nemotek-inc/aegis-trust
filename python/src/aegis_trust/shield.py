"""@shield decorator — the core of aegis-trust.

Controls what data AI agents can see, based on declared purpose and scope.
Local-first: filters dict return values in-process. An optional enterprise
backend can be configured for centrally managed deployments;
email contact@aegisagentcontrol.com for details.
"""

from __future__ import annotations

import array
import dataclasses
import functools
import importlib
import inspect
import logging
import os
import time as _time
from collections import deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, TypeVar

from aegis_trust.errors import AegisConfigError, AegisValidationError, aegis_docs_url
from aegis_trust.history import record_if_enabled
from aegis_trust.types import IngestEntry, Mode, PolicySyncEntry, ShieldResult

if TYPE_CHECKING:
    # FULL/gateway-mode only. Importing AegisClient at runtime pulls the
    # optional gateway dependencies (httpx, attrs) into the import graph; the
    # real import is deferred into _get_client() so a LITE-only install
    # (`pip install aegis-trust`) carries no runtime dependencies and the
    # in-process filtering path never touches httpx.
    from aegis_trust.client import AegisClient

logger = logging.getLogger("aegis")


class _ConversionFailed:
    """Sentinel: a record→dict conversion (model_dump / asdict / .dict /
    ``__table__`` walk) raised before producing a filterable shape.

    Distinct from a *genuinely unsupported* return type (a bare scalar /
    opaque object that was never convertible). Carrying this sentinel out of
    :func:`_to_filterable` lets the filter helpers fail closed **without**
    re-attributing the failure to ``"cannot filter str"`` — a non-leaking
    developer diagnostic has already been emitted at the conversion site
    (S018 D1; the raw cause/traceback are withheld by default — see
    :func:`_record_conversion_failure`). ``__slots__`` keeps it record-like to
    :func:`_freeze_single_pass` so it passes through the normalize step
    untouched.
    """

    __slots__ = ()


_CONVERSION_FAILED = _ConversionFailed()


def _record_conversion_failure(stage: str) -> _ConversionFailed:
    """Non-leaking developer diagnostic for a conversion that raised
    (S018 D1, P1/P2 secret-leak hardening).

    The default surface emits **only SDK-controlled fixed strings**: a fixed
    ``conversion_failed`` marker, a fixed ``stage=<label>`` enum identifying
    which converter raised, and a fixed remediation. **No** application-controlled
    string is surfaced at all.

    It deliberately withholds every **application-controlled** string:
    - the exception *message* (routinely echoes the filtered field values:
      ``customer_ssn=...``, ``stripe_secret_key=...``, PHI, internal prompts),
    - the traceback (no ``exc_info``),
    - the object's ``repr``/``str`` (its dunders are never invoked),
    - the *type/exception class names* (``type(data).__name__`` /
      ``type(cause).__name__``) — application-named identifiers, and a class
      dynamically named with embedded data would otherwise leak it
      (S018 P2-1), and
    - the ``trace_id`` — even though it is shape-validated, the validator
      (``^[A-Za-z0-9._:-]{1,128}$``) accepts secret-shaped tokens
      (e.g. ``sk_live_…``), so a developer who put a secret in their own
      trace_id would leak it here. It is therefore NOT surfaced on the
      diagnostic surface (S018 P2-2, independent CAG finding). The trace_id
      feature and its "never pass secrets as trace_id" contract remain for the
      audit JSONL; this only removes it from the developer diagnostic.

    The caller passes a fixed ``stage`` label chosen by the SDK at the call
    site, NOT derived from the failing object or exception. No opt-in to dump
    the raw message/traceback/names is provided: minimum-disclosure is the only
    mode (safe by construction). Fail-closed is preserved by the returned
    sentinel.
    """
    logger.warning(
        "shield: conversion_failed stage=%s — returning empty (fail-closed); "
        "the unconverted value was NOT passed through. The exception detail, "
        "traceback, and type/class names are withheld by default to avoid "
        "leaking sensitive values (PII / secrets) into logs; reproduce in a "
        "trusted local environment to inspect the cause.",
        stage,
    )
    return _CONVERSION_FAILED


# Reusable (non-single-pass) built-in containers. Used by
# `_freeze_single_pass` and `_iter_preserving` to decide whether iterating
# a value consumes it (generators, custom __iter__) or can be done
# repeatedly without loss (list, tuple, set, frozenset, deque, memoryview,
# range, array.array).
_REUSABLE_CONTAINERS: tuple[type, ...] = (
    list,
    tuple,
    set,
    frozenset,
    deque,
    memoryview,
    range,
    array.array,
)

F = TypeVar("F", bound=Callable[..., Any])

# Module-level client, lazily initialized
_client: AegisClient | None = None
_detected_mode: Mode | None = None

# Test hook — set by pytest_plugin to capture shield calls in-memory
_test_hook: Callable[..., None] | None = None

# Hosts treated as local dev (TLS verify can be disabled with opt-in).
# Anything else is production-grade and MUST verify TLS.
_DEV_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "0.0.0.0", "::1")


def _is_dev_host(url_or_host: str) -> bool:
    """Return True if the URL (or bare host) points at a local dev address.

    Used by both `_resolve_verify_ssl` (TLS prod-lock) and `_user_intends_full`
    (auto-mode degrade gate) so the two stay in sync.
    """
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url_or_host)
        host = (parsed.hostname or url_or_host).lower()
    except Exception:
        host = url_or_host.lower()
    return host in _DEV_HOSTS or host.endswith(".local")


def _resolve_verify_ssl(base_url: str) -> bool:
    """Resolve TLS verify flag with fail-secure prod-lock (AO-001/AO-005).

    - Production (non-dev host): TLS verify is forced on. AEGIS_VERIFY_SSL=false
      is ignored unless AEGIS_DEV_INSECURE=1 is explicitly set AND the host is
      local. This blocks silent TLS downgrade in prod.
    - Local dev host + AEGIS_VERIFY_SSL=false: allowed (with logger.warning).
    """
    raw = os.environ.get("AEGIS_VERIFY_SSL", "true").lower()
    requested = raw != "false"
    if requested:
        return True

    try:
        from urllib.parse import urlparse

        host = (urlparse(base_url).hostname or "").lower()
    except Exception:
        host = ""
    is_dev = _is_dev_host(base_url)
    dev_opt_in = os.environ.get("AEGIS_DEV_INSECURE", "").lower() in ("1", "true")

    if is_dev and dev_opt_in:
        logger.warning(
            "AEGIS_VERIFY_SSL=false accepted for dev host %r (AEGIS_DEV_INSECURE=1). "
            "Never use this configuration in production.",
            host,
        )
        return False

    logger.warning(
        "AEGIS_VERIFY_SSL=false rejected (host=%r, dev_opt_in=%s). "
        "TLS verify forced on (fail-secure). Set AEGIS_DEV_INSECURE=1 on a "
        "local host to opt in explicitly.",
        host,
        dev_opt_in,
    )
    return True


_base_url_alias_warned: bool = False


def _resolve_base_url() -> str:
    """Resolve aegis-core REST base URL.

    AEGIS_URL is canonical. AEGIS_BASE_URL is accepted as an npm-parity
    alias (npm aegis-trust historically read AEGIS_BASE_URL; both SDKs
    accept both env vars from v0.9.0-rc3 onward, with AEGIS_URL as the
    canonical name. AEGIS_BASE_URL removed in v1.0.0 per docs/VERSIONING.md
    deprecation policy.
    """
    global _base_url_alias_warned
    url = os.environ.get("AEGIS_URL", "").strip()
    if url:
        return url
    base = os.environ.get("AEGIS_BASE_URL", "").strip()
    if base:
        if not _base_url_alias_warned:
            _base_url_alias_warned = True
            logger.warning(
                "aegis-trust: AEGIS_BASE_URL is accepted as an npm-parity "
                "alias but AEGIS_URL is canonical. Migrate to AEGIS_URL; "
                "AEGIS_BASE_URL will be removed in v1.0.0."
            )
        return base
    return "https://localhost:8443/api/v1"


def _get_client() -> AegisClient:
    global _client
    if _client is None:
        # Deferred import: FULL/gateway mode is the only path that needs the
        # gateway client (and its httpx/attrs deps). A LITE-only install never
        # reaches here. If the caller drives FULL without the gateway extra,
        # surface a machine-parseable, actionable error rather than a raw
        # ModuleNotFoundError.
        try:
            from aegis_trust.client import AegisClient
        except ModuleNotFoundError as exc:
            missing = (exc.name or "").split(".")[0]
            if missing in ("httpx", "attrs"):
                code = "aegis.client.gateway_extra_missing"
                raise AegisConfigError(
                    "FULL/gateway mode needs the optional gateway dependencies "
                    f"(missing: {missing!r}). LITE in-process filtering needs "
                    "none of them. Install the gateway extra:\n"
                    "    pip install 'aegis-trust[full]'",
                    code=code,
                    remediation="Install the gateway extra: pip install 'aegis-trust[full]'.",
                    docs_url=aegis_docs_url(code),
                    cause=exc,
                ) from exc
            raise
        base_url = _resolve_base_url()
        _client = AegisClient(
            base_url=base_url,
            token=os.environ.get("AEGIS_TOKEN", ""),
            verify_ssl=_resolve_verify_ssl(base_url),
        )
    return _client


# Mode detection cache TTL. AEGIS_MODE=auto re-probes the backend every
# `_DETECT_MODE_TTL_S` seconds so process state stays in sync with reality
# without per-call probes.
_DETECT_MODE_TTL_S = 60.0
_detected_mode_ts: float = 0.0
# S015 P-38: warn-once flag for "AEGIS_URL set but resolved to LITE".
_lite_despite_url_warned: bool = False


def _user_intends_full() -> bool:
    """Heuristic for "user expects Full mode" under AEGIS_MODE=auto.

    Returns True when AEGIS_TOKEN is set, or AEGIS_URL / AEGIS_BASE_URL
    points at a non-dev host. When True, _detect_mode refuses to silently
    degrade to Lite on a transient backend outage — Gateway-uniqueness
    (AO-001) outranks availability. Local hosts (localhost / 127.0.0.1 /
    ::1 / *.local) are treated as dev regardless of port so dev fixtures
    keep working.
    """
    if os.environ.get("AEGIS_TOKEN", "").strip():
        return True
    url = (
        os.environ.get("AEGIS_URL", "").strip()
        or os.environ.get("AEGIS_BASE_URL", "").strip()
    )
    return bool(url) and not _is_dev_host(url)


def _detect_mode() -> Mode:
    global _detected_mode, _detected_mode_ts
    now = _time.monotonic()
    if _detected_mode is not None and now - _detected_mode_ts < _DETECT_MODE_TTL_S:
        return _detected_mode

    env_mode = os.environ.get("AEGIS_MODE", "auto").lower()
    previous = _detected_mode
    if env_mode == "lite":
        _detected_mode = Mode.LITE
    elif env_mode == "full":
        _detected_mode = Mode.FULL
    else:
        # AUTO branch — intent-first per the README AUTO behaviour matrix:
        #   - no Full intent (no AEGIS_TOKEN, no non-dev URL) → LITE (no probe)
        #   - Full intent + reachable backend                 → FULL
        #   - Full intent + unreachable backend               → fail-closed FULL warn
        # The intent check runs BEFORE the /health probe so a dev
        # environment without credentials does not opportunistically call
        # the gateway. This matches the documented matrix exactly and
        # avoids unnecessary /check-access traffic from no-token AUTO
        # callers (parity with node client.ts detectMode).
        if not _user_intends_full():
            # S015 P-38 (confirmed live): an explicit AEGIS_URL pointing at a
            # dev host (e.g. a localhost sidecar gateway) with no AEGIS_TOKEN
            # resolves to LITE and the gateway is NEVER consulted — shield()
            # filters locally only. That is the documented intent-first matrix,
            # but it is silent, so an operator who stood up a gateway cannot
            # tell it is being bypassed. Make it loud (warn once). Behaviour is
            # unchanged. Parity with node client.ts detectMode.
            global _lite_despite_url_warned
            explicit_url = (
                os.environ.get("AEGIS_URL") or os.environ.get("AEGIS_BASE_URL") or ""
            ).strip()
            if explicit_url and not _lite_despite_url_warned:
                _lite_despite_url_warned = True
                logger.warning(
                    "shield: AEGIS_URL is set but mode resolved to LITE — no Full "
                    "intent (dev-host URL and no AEGIS_TOKEN). The gateway at this "
                    "URL will NOT be consulted; shield() filters locally only. Set "
                    "AEGIS_TOKEN (or AEGIS_MODE=full) to use the gateway."
                )
            _detected_mode = Mode.LITE
        else:
            client = _get_client()
            if client.is_available():
                _detected_mode = Mode.FULL
            else:
                # Explicit URL/TOKEN signals Full intent. Refuse silent Lite
                # degrade — Gateway-uniqueness (AO-001) outranks availability.
                # Calls fail-closed until the backend recovers.
                _detected_mode = Mode.FULL
                logger.warning(
                    "shield: AEGIS_MODE=auto with explicit URL/TOKEN but backend "
                    "unreachable — staying in Full mode (fail-closed). All @shield "
                    "calls will deny until the gateway recovers."
                )
    _detected_mode_ts = now

    # AO-006: emit an explicit event whenever the mode flips so an audit
    # reader can distinguish "always-Lite" from "Full degraded to Lite
    # mid-process" without inferring it from log noise.
    if previous is not None and previous != _detected_mode:
        logger.warning(
            "shield: mode changed %s → %s (env=%s)",
            previous.value,
            _detected_mode.value,
            env_mode,
        )
    elif previous is None:
        logger.info("shield: detected mode=%s (env=%s)", _detected_mode.value, env_mode)
    return _detected_mode


def _validate_field_path(
    path: str,
    *,
    error_cls: type[AegisValidationError] = AegisValidationError,
    code: str = "aegis.shield.field_path.invalid",
) -> None:
    """Validate a dot-notation field path.

    Raises a rich :class:`AegisValidationError` (S018 D2) — which subclasses
    :class:`ValueError`, so existing ``except ValueError`` callers are
    unaffected — for empty strings, leading/trailing dots, or consecutive
    dots. ``error_cls`` / ``code`` let the config loader surface the
    config-namespaced ``aegis.config.fieldPath.invalid`` code for the same
    check (Node parity).
    """
    if not path:
        raise error_cls(
            "Field path must not be empty. "
            "Specify a field name, for example scope=['email'].",
            code=code,
            remediation="Pass a non-empty dot-notation field path, e.g. scope=['email'].",
            docs_url=aegis_docs_url(code),
        )
    if path.startswith(".") or path.endswith("."):
        raise error_cls(
            f"Invalid field path '{path}': leading or trailing dot. "
            f"Use dot-notation like 'profile.age' (no leading or trailing dot).",
            code=code,
            remediation="Remove the leading/trailing dot. Use dot-notation like 'profile.age'.",
            docs_url=aegis_docs_url(code),
        )
    if ".." in path:
        raise error_cls(
            f"Invalid field path '{path}': consecutive dots. "
            f"Use single dots between path segments, like 'profile.age'.",
            code=code,
            remediation="Use single dots between path segments, e.g. 'profile.age'.",
            docs_url=aegis_docs_url(code),
        )


def _parse_paths(fields: list[str], *, broader_wins: bool = False) -> dict[str, Any]:
    """Parse dot-notation field list into a nested tree.

    Example:
        ["name", "profile.age", "profile.address.city"]
        → {"name": {}, "profile": {"age": {}, "address": {"city": {}}}}

    A leaf ({}) means "match this key directly".
    A non-empty dict means "descend into this key and apply sub-tree".

    When ``broader_wins=True`` (used by deny_fields), a parent path
    takes precedence over child paths.  ``["profile", "profile.ssn"]``
    collapses to ``{"profile": {}}`` so the entire subtree is denied.
    This enforces AO-002 fail-closed: broader deny always wins.
    """
    if broader_wins:
        fields = sorted(fields, key=lambda f: f.count("."))
        covered: set[str] = set()

    tree: dict[str, Any] = {}
    for field in fields:
        parts = field.split(".")
        if broader_wins:
            # Skip if any parent path is already a complete leaf
            if any(".".join(parts[: i + 1]) in covered for i in range(len(parts) - 1)):
                continue
            covered.add(field)

        node = tree
        for part in parts:
            if part not in node:
                node[part] = {}
            node = node[part]
    return tree


def _flat_key_hits_deny_leaf(key: str, path_tree: dict[str, Any]) -> bool:
    """Whether a flattened data key (a key literally containing dots) is denied
    by a nested deny ``path_tree``.

    Fail-closed for flattened-key APIs: ``deny_fields=["card.cvv"]`` parses to
    ``{"card": {"cvv": {}}}``. A top-level key LITERALLY named ``"card.cvv"``
    is not in that tree, so the un-fixed deny loop KEPT it and leaked it
    (fail-OPEN on deny). Here we re-interpret the flattened key against the
    deny tree: split on ``.`` and walk; if any prefix lands on a leaf (a denied
    node), the key is denied. This also means ``deny_fields=["profile"]`` drops
    a flattened ``"profile.ssn"`` (everything under a denied node), matching the
    intent of a denylist. Scope (allow-list) needs no analogue — an unmatched
    literal key is simply not allow-listed (already fail-closed).
    """
    if "." not in key:
        return False
    node: Any = path_tree
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
        if node == {}:
            return True
    return False


# Duck-type probes shared between _is_record_like and _to_filterable so the
# two cannot drift: if a new shape is added to the normalization pipeline,
# the leak-detection guard auto-tracks it.


def _is_pydantic_v2_like(x: Any) -> bool:
    return hasattr(x, "model_dump") and callable(getattr(x, "model_dump", None))


def _is_sqla_declarative_like(x: Any) -> bool:
    """Narrow SQLAlchemy Declarative probe.

    Permissive duck typing (``hasattr(x, "__table__")``) is a confused-deputy
    surface: attacker-controlled classes can forge ``__table__.columns`` and
    steer ``_to_filterable`` to emit arbitrary attributes. Accept only when
    SQLAlchemy is importable AND either the instance is a ``DeclarativeBase``
    subclass or ``__table__`` is a real ``sqlalchemy.Table`` instance.
    Fail-closed otherwise.
    """
    if not hasattr(x, "__table__"):
        return False
    try:
        sa = importlib.import_module("sqlalchemy")
    except ImportError:
        return False
    table_cls = getattr(sa, "Table", None)
    if table_cls is not None and isinstance(x.__table__, table_cls):
        return True
    try:
        orm = importlib.import_module("sqlalchemy.orm")
        decl_base = getattr(orm, "DeclarativeBase", None)
        if decl_base is not None and isinstance(x, decl_base):
            return True
    except ImportError:
        pass
    return False


def _is_pydantic_v1_like(x: Any) -> bool:
    return (
        hasattr(x, "dict")
        and callable(getattr(x, "dict", None))
        and not isinstance(x, type)
    )


def _is_dataclass_instance(x: Any) -> bool:
    return dataclasses.is_dataclass(x) and not isinstance(x, type)


def _is_namedtuple_instance(x: Any) -> bool:
    """typing.NamedTuple / collections.namedtuple detection."""
    return (
        isinstance(x, tuple)
        and hasattr(x, "_asdict")
        and callable(getattr(x, "_asdict", None))
        and hasattr(x, "_fields")
    )


def _has_slots(x: Any) -> bool:
    """Attribute-carrying ``__slots__`` instance (no ``__dict__``).

    ``__slots__`` classes don't populate ``__dict__`` but still hold named
    attributes. Treating them as record-like keeps fail-closed as the default
    for otherwise-unknown objects.
    """
    return hasattr(type(x), "__slots__") and not hasattr(x, "__dict__")


def _is_record_like(x: Any) -> bool:
    """True when ``x`` may carry named fields a leaf scope cannot filter.

    A bare ``scope=["key"]`` whitelists the key but not the inner fields
    of its value. When the value is a collection carrying dict-like or
    object-with-fields elements, those inner fields would leak — this
    helper identifies such elements so the leaf-drop rule can fire
    fail-closed.
    """
    if x is None or isinstance(x, (str, bytes, int, float, bool)):
        return False
    if isinstance(x, Mapping):
        return True
    if (
        _is_pydantic_v2_like(x)
        or _is_sqla_declarative_like(x)
        or _is_pydantic_v1_like(x)
        or _is_dataclass_instance(x)
        or _is_namedtuple_instance(x)
    ):
        return True
    # SimpleNamespace / custom classes with attribute storage — their fields
    # would leak through a bare leaf scope since __dict__ carries whatever
    # the caller assigned.
    if hasattr(x, "__dict__"):
        return True
    # __slots__ instances hold named attributes without __dict__.
    return _has_slots(x)


def _is_traversable(x: Any) -> bool:
    """Non-str / non-bytes / non-Mapping iterable that may carry record-like
    elements.

    Generalizes the ``(list, tuple)`` check used by pre-S022 ``_filter_dict``.
    Covers ``list``, ``tuple``, ``set``, ``frozenset``, ``collections.deque``,
    ``memoryview``, ``array.array``, ``range``, generators, and custom
    iterables. Explicitly excludes ``str`` / ``bytes`` / ``bytearray`` (they
    are ``Sequence`` but iterating them char-by-char would corrupt scalar
    data) and ``Mapping`` (handled on a dedicated branch by callers).
    """
    if isinstance(x, (str, bytes, bytearray)):
        return False
    if isinstance(x, Mapping):
        return False
    return isinstance(x, Iterable)


def _materialize(v: Any) -> list[Any]:
    """Materialize a traversable into a list for single-pass iteration.

    Generators and other single-pass iterables would be exhausted by a
    ``_is_record_like`` scan, leaving the caller with an empty iterator
    if we returned the original. For security-critical filtering the
    cost of materialization is acceptable; it also keeps downstream
    recursion deterministic.
    """
    return list(v)


def _freeze_single_pass(data: Any) -> Any:
    """Recursively replace single-pass iterables (generators, custom
    ``__iter__``) with materialized lists.

    S022 Review CR-1 fix: filtering consumes generators via
    ``_materialize``. If the ORIGINAL still holds a consumed generator
    reference, ``_diff_keys`` / ``_collect_removed`` re-iterate it and
    see zero elements — the audit trail under-reports ``blocked_fields``.
    By freezing single-pass iterables at the entry of
    ``_shield_lite`` / ``_shield_full`` / ``_shield_deny``, filter and
    audit diff observe the same concrete structure.

    Reusable containers (``list``, ``tuple``, ``set``, ``frozenset``,
    ``deque``, ``memoryview``, ``range``, ``array.array``) keep their
    type; list/tuple elements recurse so any nested generators are also
    materialized. Non-traversable values are returned as-is.
    """
    if isinstance(data, (str, bytes, bytearray)):
        return data
    if isinstance(data, Mapping):
        return {k: _freeze_single_pass(v) for k, v in data.items()}
    # Pydantic / SQLAlchemy / dataclass / NamedTuple / __slots__ / plain
    # object-with-__dict__ are all record-like (see _is_record_like). They
    # often implement __iter__ in ways that don't match "collection of
    # record-like elements" (e.g., Pydantic BaseModel iterates field names
    # as strings), so treat them as atomic here — _to_filterable handles
    # the per-shape normalization downstream.
    if _is_record_like(data):
        return data
    if isinstance(data, _REUSABLE_CONTAINERS):
        if isinstance(data, list):
            return [_freeze_single_pass(x) for x in data]
        if isinstance(data, tuple):
            return tuple(_freeze_single_pass(x) for x in data)
        # set / frozenset / deque / memoryview / range / array.array:
        # elements are typically scalars, so leave the container as-is
        # to preserve type identity for downstream type-sensitive logic.
        return data
    if _is_traversable(data):
        # Single-pass iterable (generator, custom __iter__): materialize.
        return [_freeze_single_pass(x) for x in data]
    return data


def _iter_preserving(v: Any) -> Any:
    """Return ``v`` iterable both for scanning and as the keep-path value.

    Reusable built-in containers (``list``, ``tuple``, ``set``, ``frozenset``,
    ``deque``, ``memoryview``, ``range``, ``array.array``) can be iterated
    multiple times without consumption, so they pass through unchanged —
    preserving the caller's type contract. Single-pass iterables
    (generators, custom ``__iter__``) are materialized to a list; returning
    the original would leave the caller with an exhausted iterator.
    """
    if isinstance(v, _REUSABLE_CONTAINERS):
        return v
    return list(v)


_HOLDS_RECORD_MAX_DEPTH = 64


def _holds_record(v: Any, _depth: int = 0) -> bool:
    """True when ``v`` is record-like, or a collection holding a record-like
    element at ANY depth.

    A bare leaf scope over ``[[{"ssn": ...}]]`` must drop the key exactly as
    over ``[{"ssn": ...}]``: checking only the immediate elements let a record
    nested one collection deeper pass through unfiltered and unreported.
    Over-deep nesting answers True (fail-closed).
    """
    if _depth > _HOLDS_RECORD_MAX_DEPTH:
        return True
    if _is_record_like(v):
        return True
    if _is_traversable(v):
        return any(_holds_record(x, _depth + 1) for x in _iter_preserving(v))
    return False


def _filter_dict(data: dict[str, Any], path_tree: dict[str, Any]) -> dict[str, Any]:
    """Keep only keys matching path_tree (minimum disclosure).

    If path_tree[k] is {} (leaf): keep data[k] as-is, **except** when the value
    is a list containing dict elements. A leaf scope over a list-of-dicts is a
    silent-pass footgun: the caller whitelisted the key but not the inner
    fields, so the dict elements would pass through unfiltered. In that case
    drop the key (fail-closed) and emit a warning pointing at the
    ``key.<field>`` dot-notation fix.

    If path_tree[k] is non-empty: recurse into data[k] with sub-tree.
    """
    result: dict[str, Any] = {}
    for k, v in data.items():
        if k not in path_tree:
            continue
        subtree = path_tree[k]
        if not subtree:
            # Leaf: keep scalars and collections-of-scalars as-is, but drop
            # fail-closed whenever the value carries named fields a bare leaf
            # cannot filter — i.e. a record-like value itself (dict / mapping /
            # object-with-fields) OR a collection containing record-like
            # elements. A bare ``scope=["config"]`` over ``{"api_key": ...}``
            # would otherwise disclose the *entire* subtree the caller never
            # enumerated (the doctor→shield fail-open class: doctor only saw the
            # parent name, shield expands the whole object). Minimum disclosure
            # requires the explicit ``'<field>.<subfield>'`` form for any nested
            # value. ANY-match on collections, so heterogeneous ``[1, {"ssn":"x"}]``
            # also drops. See ``_is_record_like`` for the full taxonomy.
            # S022 R1/R11 covered the collection case; the bare-Mapping/record
            # case is the doctor-v0 trust-boundary hardening.
            if _holds_record(v):
                logger.warning(
                    "shield: scope_bare_field_over_record_collection — a bare "
                    "scope field matched a record-like value (a mapping/object) "
                    "or a collection of record-like elements; dropping the key "
                    "(fail-closed). Use the dot-notation '<field>.<subfield>' "
                    "form to enumerate the permitted nested fields. The field "
                    "key is withheld (application-controlled identifier)."
                )
                continue
            if _is_traversable(v):
                result[k] = _iter_preserving(v)
            else:
                result[k] = v
        elif isinstance(v, dict):
            result[k] = _filter_dict(v, subtree)
        elif _is_traversable(v):
            result[k] = [_filter_result(item, subtree) for item in _materialize(v)]
        else:
            # subtree expects nested access but value is scalar:
            # drop the key to prevent data leakage (fail-closed).
            logger.warning(
                "shield: scope_nested_path_on_scalar — a scope path expected a "
                "nested object but the value was a non-traversable scalar; "
                "dropping the key (fail-closed). The field key and value type "
                "are withheld (application-controlled identifiers)."
            )
    return result


def _deny_filter_dict(
    data: dict[str, Any], path_tree: dict[str, Any]
) -> dict[str, Any]:
    """Remove keys matching path_tree from data (minimum disclosure).

    Contract (mirror of ``_filter_dict``):
      - ``deny_fields=["users"]``: drops the ``users`` key entirely,
        regardless of whether its value is dict, list, list-of-dicts, or scalar.
      - ``deny_fields=["users.ssn"]``: descends into ``users`` and removes the
        ``ssn`` field from each element when the value is a list-of-dicts, or
        from the single dict when it is a dict.
      - ``deny_fields=["ssn"]`` when the data has no top-level ``ssn`` key:
        top-level match only. To remove nested ``ssn`` occurrences, the caller
        MUST specify the dot-notation path (for example
        ``deny_fields=["users.ssn"]``). This mirrors ``scope`` semantics: a
        bare field name never implicitly recurses into child collections.

    If path_tree[k] is {} (leaf): remove data[k] entirely.
    If path_tree[k] is non-empty: recurse into data[k] with sub-tree.
    """
    result: dict[str, Any] = {}
    for k, v in data.items():
        if k not in path_tree:
            # Flattened-key APIs: a literal "card.cvv" data key is denied by a
            # nested deny path "card.cvv" (S017 H1 fail-open fix).
            if isinstance(k, str) and _flat_key_hits_deny_leaf(k, path_tree):
                continue
            result[k] = v
            continue
        subtree = path_tree[k]
        if not subtree:
            # Leaf — deny this key entirely
            continue
        elif isinstance(v, dict):
            result[k] = _deny_filter_dict(v, subtree)
        elif _is_traversable(v):
            # S022 R1/R11: mirror `_filter_dict` container coverage.
            result[k] = [_deny_filter_result(item, subtree) for item in _materialize(v)]
        else:
            # S022 R2 / A12: subtree expects nested descent but value is
            # scalar. Pre-S022 kept the value; that was asymmetric with
            # `_filter_dict` (which drops fail-closed) and let
            # ``deny_fields=['users.ssn']`` silently pass through a scalar
            # ``users`` value. Drop the key fail-closed so the contract is
            # symmetric with scope semantics.
            logger.warning(
                "shield: deny_fields_nested_path_on_scalar — a deny_fields path "
                "expected a nested object but the value was a non-traversable "
                "scalar; dropping the key (fail-closed, S022 R2). The field key "
                "and value type are withheld (application-controlled identifiers)."
            )
    return result


def _to_filterable(data: Any) -> Any:
    """Normalize ORM / Pydantic / dataclass return values to dict for filtering.

    Detects the following shapes by duck typing (no Pydantic, no SQLAlchemy
    dependency is added):

    1. ``dict`` / ``list`` / ``None`` — returned unchanged (hottest path).
    2. Pydantic v2 — ``.model_dump()``.
    3. SQLAlchemy Declarative — ``{c.name: getattr(obj, c.name) for c in
       obj.__table__.columns}``. Checked before Pydantic v1 because some
       ORM mixins also define a ``.dict`` method, and ``__table__.columns``
       is the more specific signature.
    4. Pydantic v1 — ``.dict()``. Only accepted when the call returns a
       ``dict``; anything else falls through to unknown pass-through.
    5. ``@dataclass`` instance — ``dataclasses.asdict``.
    6. Unknown — returned unchanged. ``_filter_result`` then applies its
       existing non-dict/non-list fail-closed rule.

    A conversion that *raises* returns the :data:`_CONVERSION_FAILED`
    sentinel (after emitting a fixed-string, non-leaking diagnostic — S018
    D1/P1/P2; the original cause is NOT logged) so the downstream
    fail-closed path fires without re-attributing the failure to "cannot
    filter str". A conversion that *succeeds but returns the wrong shape*
    (a confused-deputy surface) returns ``""`` as before.
    """
    if data is None or isinstance(data, (dict, list)):
        return data
    # S022 R10: NamedTuple (typing.NamedTuple / collections.namedtuple) has
    # dict-shaped named fields. Detect before other probes so the tuple
    # branch doesn't swallow it.
    if _is_namedtuple_instance(data):
        try:
            result = data._asdict()
        except Exception:
            return _record_conversion_failure("namedtuple_conversion")
        if isinstance(result, dict):
            return result
    if _is_pydantic_v2_like(data):
        try:
            result = data.model_dump()
        except Exception:
            return _record_conversion_failure("pydantic_model_dump")
        # S022 R9: v2 return-type gate, symmetric with v1 path below. A
        # ``model_dump()`` returning anything other than ``dict`` is a
        # confused-deputy surface; treat as fail-closed.
        if isinstance(result, dict):
            return result
        return ""
    # SQLAlchemy before Pydantic v1: some ORM mixins also define .dict, so
    # ``__table__.columns`` is the more specific signature and must win.
    if _is_sqla_declarative_like(data):
        try:
            # S022 /cso M1: skip dunder column names so a forged/edge-case
            # column mapping can't steer getattr to class metadata
            # (defense-in-depth on top of R3 narrowing).
            return {
                c.name: getattr(data, c.name)
                for c in data.__table__.columns
                if not (isinstance(c.name, str) and c.name.startswith("__"))
            }
        except Exception:
            return _record_conversion_failure("sqlalchemy_conversion")
    if _is_pydantic_v1_like(data):
        try:
            result = data.dict()
        except Exception:
            return _record_conversion_failure("pydantic_dict")
        if isinstance(result, dict):
            return result
    if _is_dataclass_instance(data):
        try:
            return dataclasses.asdict(data)
        except Exception:
            return _record_conversion_failure("dataclass_conversion")
    return data


def _filter_result(data: Any, path_tree: dict[str, Any]) -> Any:
    """Apply scope filtering to function return values.

    Non-dict/non-list values cannot be field-filtered. Returning them
    unfiltered would be an implicit data leak. Return empty string
    instead (fail-closed).
    """
    data = _to_filterable(data)
    if data is _CONVERSION_FAILED:
        # Conversion already raised and was diagnosed at the conversion site
        # (S018 D1). Fail closed without the misleading "cannot filter str".
        return ""
    if isinstance(data, dict):
        return _filter_dict(data, path_tree)
    if isinstance(data, list):
        return [_filter_result(item, path_tree) for item in data]
    if data is None:
        return None
    logger.warning(
        "shield: unsupported_return_shape — cannot field-filter a non-dict / "
        "non-list return value; returning empty (fail-closed). The return "
        "type name is withheld by default (it is an application-controlled "
        "identifier) to avoid leaking sensitive values into logs."
    )
    return ""


def _deny_filter_result(data: Any, path_tree: dict[str, Any]) -> Any:
    """Apply deny_fields filtering to function return values.

    Non-dict/non-list values cannot be field-filtered. Returning them
    unfiltered would be an implicit data leak. Return empty string
    instead (fail-closed).
    """
    data = _to_filterable(data)
    if data is _CONVERSION_FAILED:
        # Conversion already raised and was diagnosed at the conversion site
        # (S018 D1). Fail closed without the misleading "cannot filter str".
        return ""
    if isinstance(data, dict):
        return _deny_filter_dict(data, path_tree)
    if isinstance(data, list):
        return [_deny_filter_result(item, path_tree) for item in data]
    if data is None:
        return None
    logger.warning(
        "shield: unsupported_return_shape — cannot field-filter a non-dict / "
        "non-list return value; returning empty (fail-closed). The return "
        "type name is withheld by default (it is an application-controlled "
        "identifier) to avoid leaking sensitive values into logs."
    )
    return ""


def shield(
    purpose: str,
    scope: list[str] | None = None,
    *,
    deny_fields: list[str] | None = None,
    mode: Mode | str = "auto",
) -> Callable[[F], F]:
    """Decorator that controls data access based on purpose and scope.

    Two filtering modes (mutually exclusive):
      - **scope** (whitelist): keep only these fields.
      - **deny_fields** (blacklist): remove these fields, keep everything else.

    Specifying both raises ValueError (data flow must be explicit).
    Specifying neither raises ValueError (minimum disclosure required).

    Supports **dot-notation** for precise nested path control:
      - ``scope=["name", "profile.age"]``: keep top-level name and profile.age.
      - ``deny_fields=["profile.ssn"]``: remove only profile.ssn.
      - Flat keys (``"name"``) apply to the top level only.

    Supported return types (auto-normalized before filtering):
      - ``dict`` / ``list`` — filtered directly.
      - ``None`` — passes through.
      - ``@dataclass`` instance — converted via ``dataclasses.asdict``.
      - Pydantic v2 ``BaseModel`` — converted via ``.model_dump()``.
      - Pydantic v1 ``BaseModel`` — converted via ``.dict()``.
      - SQLAlchemy Declarative instance — converted via ``__table__.columns``.
      - Anything else (scalar, opaque object) — returns empty (fail-closed).

    A bare leaf ``scope=["key"]`` over a collection containing dict-like
    elements (list or tuple of dict / ``MappingProxyType`` / ``UserDict`` /
    any ``collections.abc.Mapping``) drops the key and emits a warning
    pointing at the ``key.<field>`` dot-notation fix. This closes a
    silent-pass leak path.

    Args:
        purpose: Why the agent needs this data (e.g. "customer_support").
        scope: Dot-notation paths the agent is allowed to see (whitelist).
        deny_fields: Dot-notation paths to hide from the agent (blacklist).
        mode: Operating mode override. Defaults to auto-detection. You almost
            never need to set this manually.

    Usage::

        @shield(purpose="support", scope=["name", "profile.age"])
        def get_customer(id):
            return db.get(id)

        @shield(purpose="support", deny_fields=["profile.ssn"])
        def get_customer_v2(id):
            return db.get(id)
    """
    # S018 D2: the spec/value validation failures below raise the rich
    # AegisValidationError envelope (.code / .remediation / .docs_url /
    # .to_dict()), reaching parity with the Node SDK's machine-parseable
    # errors. AegisValidationError subclasses ValueError, so every existing
    # ``except ValueError`` caller keeps working. The *type-shape* checks
    # (scope/deny_fields must be a list / of strings) deliberately stay raw
    # TypeError — they are not ValueError-family and existing
    # ``except TypeError`` callers must keep catching them.
    if scope is not None and deny_fields is not None:
        raise AegisValidationError(
            "scope and deny_fields are mutually exclusive. "
            "Use scope (whitelist) OR deny_fields (blacklist), not both.",
            code="aegis.shield.spec.conflict",
            remediation="Pass either `scope` (whitelist) or `deny_fields` (blacklist), never both.",
            docs_url=aegis_docs_url("aegis.shield.spec.conflict"),
        )
    if scope is None and deny_fields is None:
        # Fallback: try aegis.yaml config
        from aegis_trust.config import get_purpose_policy

        policy = get_purpose_policy(purpose)
        if policy is not None:
            scope = policy.get("scope")
            deny_fields = policy.get("deny_fields")
        else:
            raise AegisValidationError(
                "Either scope or deny_fields is required. "
                "Use scope (whitelist) OR deny_fields (blacklist), "
                "or define the purpose in aegis.yaml.",
                code="aegis.shield.spec.required",
                remediation=(
                    "Pass `scope` (whitelist) or `deny_fields` (blacklist), or define "
                    "the purpose in aegis.yaml. An empty spec returns all data unfiltered."
                ),
                docs_url=aegis_docs_url("aegis.shield.spec.required"),
            )
    if scope is not None and not isinstance(scope, list):
        raise TypeError("scope must be a list of strings")
    if scope is not None and not all(isinstance(f, str) for f in scope):
        raise TypeError("scope elements must all be strings")
    if deny_fields is not None and not isinstance(deny_fields, list):
        raise TypeError("deny_fields must be a list of strings")
    if deny_fields is not None and not all(isinstance(f, str) for f in deny_fields):
        raise TypeError("deny_fields elements must all be strings")
    if deny_fields is not None and len(deny_fields) == 0:
        raise AegisValidationError(
            "deny_fields must not be empty (minimum disclosure). "
            "An empty deny list hides nothing. "
            "Specify the field names to hide, for example deny_fields=['ssn', 'card'].",
            code="aegis.shield.deny_fields.empty",
            remediation="Provide at least one field path in `deny_fields`, or use `scope` instead.",
            docs_url=aegis_docs_url("aegis.shield.deny_fields.empty"),
        )

    # Validate field paths (dot-notation)
    if scope is not None:
        for path in scope:
            _validate_field_path(path)
    if deny_fields is not None:
        for path in deny_fields:
            _validate_field_path(path)

    if isinstance(mode, str):
        # S018 D2: an unrecognized mode string raised a bare enum ValueError
        # ("'xxx' is not a valid Mode") with no machine-parseable code. Surface
        # the rich envelope with the Node-parity `aegis.shield.mode.invalid`.
        try:
            mode = Mode(mode)
        except ValueError as exc:
            valid = ", ".join(repr(m.value) for m in Mode)
            raise AegisValidationError(
                f"shield: invalid mode {mode!r} — expected one of {valid}.",
                code="aegis.shield.mode.invalid",
                remediation=(
                    f"Set `mode` to one of {valid} (lowercase), or use the Mode enum "
                    "(e.g. Mode.FULL). Omit `mode` to default to auto."
                ),
                docs_url=aegis_docs_url("aegis.shield.mode.invalid"),
                cause=exc,
            ) from exc

    use_deny = deny_fields is not None
    # Defensive copy + parse into path tree for dot-notation support
    _scope_tree = _parse_paths(list(scope)) if scope is not None else None
    _scope = list(scope) if scope is not None else None
    _deny_tree = (
        _parse_paths(list(deny_fields), broader_wins=True)
        if deny_fields is not None
        else None
    )
    _deny = list(deny_fields) if deny_fields is not None else None

    def decorator(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                active_mode = mode if mode != Mode.AUTO else _detect_mode()
                # FULL mode: gate /check-access BEFORE running fn (parity
                # with Node T-SDK-FULL-GATE-01). The trust gate prevents
                # the wrapped function's side effects (DB writes, billing,
                # etc.), not merely discards their result. On deny /
                # unreachable / network error the wrapped function never
                # runs and the call returns None.
                if active_mode == Mode.FULL:
                    client = _get_client()
                    gate_scope: list[str] = [] if use_deny else list(_scope or [])
                    try:
                        granted = await client.aauthorize(purpose, gate_scope)
                    except Exception:
                        logger.warning(
                            "shield: /check-access raised for purpose=%s — "
                            "fn '%s' not invoked (fail-closed)",
                            purpose,
                            fn.__name__,
                        )
                        return None
                    if not granted:
                        logger.warning(
                            "shield: purpose=%s denied by /check-access — "
                            "fn '%s' not invoked (fail-closed)",
                            purpose,
                            fn.__name__,
                        )
                        return None
                    # Gate granted — safe to run fn.
                    try:
                        result = await fn(*args, **kwargs)
                    except Exception:
                        logger.error(
                            "shield: wrapped function '%s' raised after gate "
                            "grant, returning empty (fail-closed)",
                            fn.__name__,
                        )
                        return ""
                    if use_deny:
                        return await _shield_deny_async(
                            result,
                            purpose,
                            _deny,
                            _deny_tree,
                            fn.__name__,
                            active_mode,
                            pre_authorized=True,
                        )
                    return await _shield_full_async(
                        result,
                        purpose,
                        _scope,
                        _scope_tree,
                        fn.__name__,
                        pre_authorized=True,
                    )
                # LITE (or AUTO→LITE): no pre-call gate; existing flow.
                try:
                    result = await fn(*args, **kwargs)
                except Exception:
                    logger.error(
                        "shield: wrapped function '%s' raised an exception, "
                        "returning empty (fail-closed)",
                        fn.__name__,
                    )
                    return ""
                if use_deny:
                    return _shield_deny(
                        result, purpose, _deny, _deny_tree, fn.__name__, active_mode
                    )
                return _shield_lite(result, purpose, _scope, _scope_tree, fn.__name__)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            active_mode = mode if mode != Mode.AUTO else _detect_mode()
            # FULL mode: gate /check-access BEFORE running fn (parity with
            # Node T-SDK-FULL-GATE-01). The trust gate prevents the wrapped
            # function's side effects, not merely discards their result. On
            # deny / unreachable / network error the wrapped function never
            # runs and the call returns None.
            if active_mode == Mode.FULL:
                client = _get_client()
                gate_scope: list[str] = [] if use_deny else list(_scope or [])
                try:
                    granted = client.authorize(purpose, gate_scope)
                except Exception:
                    logger.warning(
                        "shield: /check-access raised for purpose=%s — "
                        "fn '%s' not invoked (fail-closed)",
                        purpose,
                        fn.__name__,
                    )
                    return None
                if not granted:
                    logger.warning(
                        "shield: purpose=%s denied by /check-access — "
                        "fn '%s' not invoked (fail-closed)",
                        purpose,
                        fn.__name__,
                    )
                    return None
                # Gate granted — safe to run fn.
                try:
                    result = fn(*args, **kwargs)
                except Exception:
                    logger.error(
                        "shield: wrapped function '%s' raised after gate "
                        "grant, returning empty (fail-closed)",
                        fn.__name__,
                    )
                    return ""
                if use_deny:
                    return _shield_deny(
                        result,
                        purpose,
                        _deny,
                        _deny_tree,
                        fn.__name__,
                        active_mode,
                        pre_authorized=True,
                    )
                return _shield_full(
                    result,
                    purpose,
                    _scope,
                    _scope_tree,
                    fn.__name__,
                    pre_authorized=True,
                )
            # LITE (or AUTO→LITE): no pre-call gate; existing flow.
            try:
                result = fn(*args, **kwargs)
            except Exception:
                logger.error(
                    "shield: wrapped function '%s' raised an exception, "
                    "returning empty (fail-closed)",
                    fn.__name__,
                )
                return ""
            if use_deny:
                return _shield_deny(
                    result, purpose, _deny, _deny_tree, fn.__name__, active_mode
                )
            return _shield_lite(result, purpose, _scope, _scope_tree, fn.__name__)

        return wrapper  # type: ignore[return-value]

    return decorator


def wrap(
    value: Any,
    *,
    purpose: str,
    scope: list[str] | None = None,
    deny_fields: list[str] | None = None,
) -> ShieldResult:
    """Filter a value directly and report what was removed (Node SDK parity: ``wrap``).

    Where :func:`shield` is a decorator over an accessor, ``wrap`` filters an
    already-materialized value in-process and returns a :class:`ShieldResult`
    whose ``filtered_keys`` names the dot-notation paths that were stripped — the
    ergonomic way to *observe* and verify LITE filtering in Python (closes the
    Node-only ``wrap()``/``filteredKeys`` observability gap). It reuses the exact
    filtering primitives :func:`shield` uses, so behaviour is identical by
    construction. LITE-only: no gateway call is made.

    ``scope`` (whitelist) and ``deny_fields`` (blacklist) are mutually exclusive;
    minimum disclosure requires at least one. An explicit ``scope=[]`` discloses
    nothing and is valid.
    """
    if not isinstance(purpose, str) or not purpose:
        raise AegisValidationError(
            "wrap: purpose must be a non-empty string.",
            code="aegis.wrap.purpose.required",
            remediation='Pass a non-empty string to `purpose`, e.g. "customer_support".',
            docs_url=aegis_docs_url("aegis.wrap.purpose.required"),
        )
    if scope is not None and deny_fields is not None:
        raise AegisValidationError(
            "wrap: scope and deny_fields are mutually exclusive. "
            "Use scope (whitelist) OR deny_fields (blacklist), not both.",
            code="aegis.wrap.spec.conflict",
            remediation="Pass either `scope` (whitelist) or `deny_fields` (blacklist), never both.",
            docs_url=aegis_docs_url("aegis.wrap.spec.conflict"),
        )
    scope_provided = scope is not None
    deny = deny_fields if deny_fields is not None else []
    if not scope_provided and len(deny) == 0:
        raise AegisValidationError(
            "wrap: either scope or deny_fields is required (minimum disclosure). "
            "An empty spec would return the value unfiltered.",
            code="aegis.wrap.spec.required",
            remediation=(
                "Pass `scope` (whitelist) or `deny_fields` (blacklist). An empty "
                "spec returns all data unfiltered."
            ),
            docs_url=aegis_docs_url("aegis.wrap.spec.required"),
        )
    if scope is not None and not isinstance(scope, list):
        raise TypeError("scope must be a list of strings")
    if scope is not None and not all(isinstance(f, str) for f in scope):
        raise TypeError("scope elements must all be strings")
    if deny_fields is not None and not isinstance(deny_fields, list):
        raise TypeError("deny_fields must be a list of strings")
    if deny_fields is not None and not all(isinstance(f, str) for f in deny_fields):
        raise TypeError("deny_fields elements must all be strings")
    if deny_fields is not None and len(deny_fields) == 0:
        raise AegisValidationError(
            "wrap: deny_fields must not be empty (minimum disclosure). "
            "An empty deny list hides nothing.",
            code="aegis.wrap.deny_fields.empty",
            remediation="Provide at least one field path in `deny_fields`, or use `scope` instead.",
            docs_url=aegis_docs_url("aegis.wrap.deny_fields.empty"),
        )
    for path in scope or []:
        _validate_field_path(path)
    for path in deny:
        _validate_field_path(path)

    # Normalize once so filter + diff observe the same shape (mirrors _shield_lite).
    normalized = _freeze_single_pass(_to_filterable(value))
    if deny_fields is not None:
        deny_tree = _parse_paths(list(deny_fields), broader_wins=True)
        filtered = _deny_filter_result(normalized, deny_tree)
        used_scope: list[str] = []
    else:
        scope_tree = _parse_paths(list(scope or []))
        filtered = _filter_result(normalized, scope_tree)
        used_scope = list(scope or [])
    return ShieldResult(
        data=filtered,
        mode=Mode.LITE,
        purpose=purpose,
        scope=used_scope,
        filtered_keys=_diff_keys(normalized, filtered),
    )


def _shield_deny(
    data: Any,
    purpose: str,
    deny_fields: list[str],
    deny_tree: dict[str, Any],
    fn_name: str,
    active_mode: Mode,
    *,
    pre_authorized: bool = False,
) -> Any:
    """Apply deny_fields filtering. Full mode sends ingest record.

    When ``pre_authorized=True``, skip the in-helper gate call (the shield
    wrapper has already gated /check-access). See T-SDK-FULL-GATE-01.
    """
    # AO-003: enforce purpose authorization in Full mode (deny-list uses
    # empty scope; the backend decides whether the purpose is allowed at
    # all for this caller).
    if active_mode == Mode.FULL and not pre_authorized:
        client = _get_client()
        if not client.authorize(purpose, []):
            logger.warning(
                "shield(deny): purpose=%s denied by check-access (AO-003)",
                purpose,
            )
            return _empty_for(data)
    try:
        # Normalize once so both the filter and the audit diff see the same
        # dict shape. `_diff_keys` recurses on dict / list only — passing a
        # raw Pydantic / dataclass / ORM instance would yield an empty
        # ``removed`` set and silently lose the audit trail.
        normalized = _freeze_single_pass(_to_filterable(data))
        filtered = _deny_filter_result(normalized, deny_tree)
        removed = _diff_keys(normalized, filtered)
    except Exception:
        logger.error(
            "shield: filtering raised an exception in '%s', "
            "returning empty (fail-closed)",
            fn_name,
        )
        return ""
    logger.debug(
        "shield(deny) purpose=%s deny_fields=%s removed=%s",
        purpose,
        deny_fields,
        removed,
    )
    ts = datetime.now(timezone.utc).isoformat()
    if active_mode == Mode.FULL:
        client = _get_client()
        try:
            entry = IngestEntry(
                function=fn_name,
                purpose=purpose,
                scope=[],
                blocked_fields=removed,
                timestamp=ts,
                deny_fields=list(deny_fields),
            )
            client.ingest([entry])
        except Exception:
            logger.error("Failed to send ingest to backend, returning empty")
            if isinstance(filtered, list):
                return []
            if isinstance(filtered, dict):
                return {}
            return ""
    record_if_enabled(
        function=fn_name,
        purpose=purpose,
        scope=[],
        deny_fields=list(deny_fields),
        blocked_fields=removed,
        timestamp=ts,
        mode=active_mode.value,
    )
    if _test_hook is not None:
        _test_hook(
            function=fn_name,
            purpose=purpose,
            scope=[],
            deny_fields=list(deny_fields),
            blocked_fields=removed,
            timestamp=ts,
            mode=active_mode.value,
        )
    return filtered


def _shield_lite(
    data: Any,
    purpose: str,
    scope: list[str],
    scope_tree: dict[str, Any],
    fn_name: str = "unknown",
) -> Any:
    """Lite mode: local dict filtering only."""
    try:
        # Normalize once so both the filter and the audit diff agree on shape.
        normalized = _freeze_single_pass(_to_filterable(data))
        filtered = _filter_result(normalized, scope_tree)
        removed = _diff_keys(normalized, filtered)
    except Exception:
        logger.error(
            "shield: filtering raised an exception in '%s', "
            "returning empty (fail-closed)",
            fn_name,
        )
        return ""
    logger.debug(
        "shield(lite) purpose=%s scope=%s filtered=%s",
        purpose,
        scope,
        removed,
    )
    ts = datetime.now(timezone.utc).isoformat()
    record_if_enabled(
        function=fn_name,
        purpose=purpose,
        scope=list(scope),
        deny_fields=[],
        blocked_fields=removed,
        timestamp=ts,
        mode="lite",
    )
    if _test_hook is not None:
        _test_hook(
            function=fn_name,
            purpose=purpose,
            scope=list(scope),
            deny_fields=[],
            blocked_fields=removed,
            timestamp=ts,
            mode="lite",
        )
    return filtered


def _empty_for(data: Any) -> Any:
    """Shape-preserving empty: list → [], dict → {}, else ''."""
    if isinstance(data, list):
        return []
    if isinstance(data, dict):
        return {}
    return ""


def _shield_full(
    data: Any,
    purpose: str,
    scope: list[str],
    scope_tree: dict[str, Any],
    fn_name: str = "unknown",
    *,
    pre_authorized: bool = False,
) -> Any:
    """Connected mode: filter locally + send block record to the backend.

    Fail-closed: if ingest fails, return empty result.

    When ``pre_authorized=True``, the caller (typically the shield wrapper
    in FULL mode) has already invoked ``/check-access`` and the gate
    granted; this function skips the in-helper gate call to avoid a double
    audit and just performs filter + ingest. See T-SDK-FULL-GATE-01.
    """
    client = _get_client()
    if not pre_authorized:
        # AO-003 gate.
        if not client.authorize(purpose, list(scope)):
            logger.warning(
                "shield: purpose=%s scope=%s denied by check-access (AO-003)",
                purpose,
                scope,
            )
            return _empty_for(data)

    try:
        # Normalize once so both the filter and the audit diff agree on shape.
        normalized = _freeze_single_pass(_to_filterable(data))
        filtered = _filter_result(normalized, scope_tree)
        removed = _diff_keys(normalized, filtered)
    except Exception:
        logger.error(
            "shield: filtering raised an exception in '%s', "
            "returning empty (fail-closed)",
            fn_name,
        )
        return ""
    ts = datetime.now(timezone.utc).isoformat()

    try:
        entry = IngestEntry(
            function=fn_name,
            purpose=purpose,
            scope=scope,
            blocked_fields=removed,
            timestamp=ts,
        )
        client.ingest([entry])
    except Exception:
        logger.error("Failed to send ingest to backend, returning empty")
        if isinstance(filtered, list):
            return []
        if isinstance(filtered, dict):
            return {}
        return ""

    record_if_enabled(
        function=fn_name,
        purpose=purpose,
        scope=list(scope),
        deny_fields=[],
        blocked_fields=removed,
        timestamp=ts,
        mode="full",
    )
    if _test_hook is not None:
        _test_hook(
            function=fn_name,
            purpose=purpose,
            scope=list(scope),
            deny_fields=[],
            blocked_fields=removed,
            timestamp=ts,
            mode="full",
        )
    return filtered


async def _shield_full_async(
    data: Any,
    purpose: str,
    scope: list[str],
    scope_tree: dict[str, Any],
    fn_name: str = "unknown",
    *,
    pre_authorized: bool = False,
) -> Any:
    """Async variant of :func:`_shield_full`. Uses ``AegisClient.aingest`` so
    the decorated coroutine never blocks the event loop on the ingest POST.

    When ``pre_authorized=True``, skip the in-helper gate call (the shield
    wrapper has already gated /check-access before invoking fn).
    See T-SDK-FULL-GATE-01.
    """
    client = _get_client()
    if not pre_authorized:
        # AO-003 gate.
        if not await client.aauthorize(purpose, list(scope)):
            logger.warning(
                "shield: purpose=%s scope=%s denied by check-access (AO-003)",
                purpose,
                scope,
            )
            return _empty_for(data)

    try:
        normalized = _freeze_single_pass(_to_filterable(data))
        filtered = _filter_result(normalized, scope_tree)
        removed = _diff_keys(normalized, filtered)
    except Exception:
        logger.error(
            "shield: filtering raised an exception in '%s', "
            "returning empty (fail-closed)",
            fn_name,
        )
        return ""
    ts = datetime.now(timezone.utc).isoformat()

    try:
        entry = IngestEntry(
            function=fn_name,
            purpose=purpose,
            scope=scope,
            blocked_fields=removed,
            timestamp=ts,
        )
        await client.aingest([entry])
    except Exception:
        logger.error("Failed to send ingest to backend, returning empty")
        if isinstance(filtered, list):
            return []
        if isinstance(filtered, dict):
            return {}
        return ""

    record_if_enabled(
        function=fn_name,
        purpose=purpose,
        scope=list(scope),
        deny_fields=[],
        blocked_fields=removed,
        timestamp=ts,
        mode="full",
    )
    if _test_hook is not None:
        _test_hook(
            function=fn_name,
            purpose=purpose,
            scope=list(scope),
            deny_fields=[],
            blocked_fields=removed,
            timestamp=ts,
            mode="full",
        )
    return filtered


async def _shield_deny_async(
    data: Any,
    purpose: str,
    deny_fields: list[str],
    deny_tree: dict[str, Any],
    fn_name: str,
    active_mode: Mode,
    *,
    pre_authorized: bool = False,
) -> Any:
    """Async variant of :func:`_shield_deny`.

    When ``pre_authorized=True``, skip the in-helper gate call (the shield
    wrapper has already gated /check-access). See T-SDK-FULL-GATE-01.
    """
    # T-151 AO-003: enforce purpose authorization in Full mode.
    if active_mode == Mode.FULL and not pre_authorized:
        client = _get_client()
        if not await client.aauthorize(purpose, []):
            logger.warning(
                "shield(deny): purpose=%s denied by check-access (AO-003)",
                purpose,
            )
            return _empty_for(data)
    try:
        normalized = _freeze_single_pass(_to_filterable(data))
        filtered = _deny_filter_result(normalized, deny_tree)
        removed = _diff_keys(normalized, filtered)
    except Exception:
        logger.error(
            "shield: filtering raised an exception in '%s', "
            "returning empty (fail-closed)",
            fn_name,
        )
        return ""
    logger.debug(
        "shield(deny) purpose=%s deny_fields=%s removed=%s",
        purpose,
        deny_fields,
        removed,
    )
    ts = datetime.now(timezone.utc).isoformat()
    if active_mode == Mode.FULL:
        client = _get_client()
        try:
            entry = IngestEntry(
                function=fn_name,
                purpose=purpose,
                scope=[],
                blocked_fields=removed,
                timestamp=ts,
                deny_fields=list(deny_fields),
            )
            await client.aingest([entry])
        except Exception:
            logger.error("Failed to send ingest to backend, returning empty")
            if isinstance(filtered, list):
                return []
            if isinstance(filtered, dict):
                return {}
            return ""
    record_if_enabled(
        function=fn_name,
        purpose=purpose,
        scope=[],
        deny_fields=list(deny_fields),
        blocked_fields=removed,
        timestamp=ts,
        mode=active_mode.value,
    )
    if _test_hook is not None:
        _test_hook(
            function=fn_name,
            purpose=purpose,
            scope=[],
            deny_fields=list(deny_fields),
            blocked_fields=removed,
            timestamp=ts,
            mode=active_mode.value,
        )
    return filtered


def _diff_keys(original: Any, filtered: Any) -> list[str]:
    """Return keys removed by filtering as dot-notation paths."""
    removed: set[str] = set()
    _collect_removed(original, filtered, "", removed)
    # sort by str(): a non-string top-level key (e.g. an int dict key) produces
    # a non-string path, and `sorted` of mixed str/int raises TypeError — that
    # crash propagated out of the public wrap() API (the @shield path caught it
    # and fail-closed). Sorting by the string form keeps the order total.
    return sorted(removed, key=str)


_COLLECT_REMOVED_MAX_DEPTH = 128


def _collect_removed(
    original: Any,
    filtered: Any,
    prefix: str,
    removed: set[str],
    _path_seen: frozenset[int] | None = None,
    _depth: int = 0,
) -> None:
    """Recursively collect all keys removed by filtering as dot-notation paths.

    Cycle-safe: attacker-shaped circular structures (``d["self"] = d``) used
    to cause unbounded recursion — either RecursionError (AO-002 leak via
    traceback) or hang (DoS). The helper tracks visited container ids on the
    current recursion path only (a shared `_seen` would also suppress
    legitimate aliasing) and caps recursion at
    :data:`_COLLECT_REMOVED_MAX_DEPTH` frames. On cycle/over-depth the
    function returns without raising; the fail-closed filter has already
    pruned the user-visible payload.
    """
    if _depth > _COLLECT_REMOVED_MAX_DEPTH:
        return
    if _path_seen is None:
        _path_seen = frozenset()
    if isinstance(original, (dict, list, tuple, set, frozenset)):
        oid = id(original)
        if oid in _path_seen:
            return
        _path_seen = _path_seen | {oid}
    if isinstance(original, dict) and isinstance(filtered, dict):
        for k in original:
            path = f"{prefix}.{k}" if prefix else str(k)
            if k not in filtered:
                removed.add(path)
            elif isinstance(original[k], dict) and isinstance(filtered[k], dict):
                _collect_removed(
                    original[k], filtered[k], path, removed, _path_seen, _depth + 1
                )
            elif _is_traversable(original[k]) and _is_traversable(filtered[k]):
                # S022 R4 / A11: mirror the allow/deny container coverage so
                # the audit diff doesn't silently under-report removed keys
                # inside tuple / deque / set / generator containers.
                _collect_removed(
                    _materialize(original[k]),
                    _materialize(filtered[k]),
                    path,
                    removed,
                    _path_seen,
                    _depth + 1,
                )
    elif _is_traversable(original) and _is_traversable(filtered):
        for orig_item, filt_item in zip(_materialize(original), _materialize(filtered)):
            _collect_removed(
                orig_item, filt_item, prefix, removed, _path_seen, _depth + 1
            )


def sync_policies(policies: dict[str, PolicySyncEntry]) -> None:
    """Synchronize purpose policies with the configured enterprise backend.

    Available only when an enterprise backend is configured and reachable.
    For local-only deployments, define policies inline with
    ``@shield(purpose=..., scope=[...])`` or in an ``aegis.yaml`` file.

    Args:
        policies: Mapping of purpose name to ``PolicySyncEntry``.

    Raises:
        RuntimeError: If no enterprise backend is configured.
            Define policies locally via ``@shield(...)`` or ``aegis.yaml``,
            or email contact@aegisagentcontrol.com for enterprise deployment.
    """
    if _detect_mode() != Mode.FULL:
        raise RuntimeError(
            "Backend policy synchronization is unavailable: "
            "no enterprise backend is configured. "
            "For local-only filtering, define policies via @shield(scope=...) "
            "or aegis.yaml. For enterprise deployment, email contact@aegisagentcontrol.com."
        )
    client = _get_client()
    client.policy_sync(policies)


def reset() -> None:
    """Reset cached client, mode detection, and deprecation-warning state.

    Useful for testing. Mirrors npm ``resetModuleClient()`` (which also
    re-arms the AEGIS_BASE_URL deprecation warning) so test fixtures
    behave identically across both SDKs.
    """
    global _client, _detected_mode, _detected_mode_ts, _base_url_alias_warned
    global _lite_despite_url_warned
    _client = None
    _detected_mode = None
    _detected_mode_ts = 0.0
    _base_url_alias_warned = False
    _lite_despite_url_warned = False


def refresh_token() -> None:
    """Re-read ``AEGIS_TOKEN`` from the environment and rotate the module
    client's bearer token (T-155).

    Call this after rotating the deployed secret — e.g. a scheduled JWT
    refresh hook — so subsequent requests use the new token without a
    process restart. Safe to call from both sync and async code.
    """
    new_token = os.environ.get("AEGIS_TOKEN", "")
    client = _get_client()
    client.set_token(new_token)
