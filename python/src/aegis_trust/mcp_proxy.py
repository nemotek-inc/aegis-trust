"""shield-proxy: MCP process-boundary enforcement point (canonical contract v0).

Sits between any MCP host (Claude Code, codex, agy, Claude Desktop, ...) and
any MCP server, with zero modification to either side:

    host  <--stdio-->  aegis-mcp-proxy  <--stdio-->  real MCP server

Every ``tools/call`` *result* coming back from the server is filtered through
the canonical policy (purpose resolved via the policy's ``tools`` map or the
call's explicit ``purpose`` argument) before the host's model ever sees it,
and a canonical audit event v0 is emitted (``enforcement_point=mcp_proxy``).

Fail-closed doctrine:
- tool not in the policy's ``tools`` map and no declared purpose ⇒ the call is
  NOT forwarded; the host receives an ``isError`` result (unknown_tool).
- any filtering error ⇒ empty content is returned, never the raw payload.

Gated data paths: ``tools/call`` plus the sibling server->host data methods
``resources/read``, ``prompts/get`` and ``completion/complete`` (each requires a
purpose mapping in the policy's ``tools`` map, else blocked). JSON-RPC batches
are rejected outright (no batching in current MCP; a batch would bypass per-id
result filtering). Task-augmented calls and ``tasks/*`` are refused: their
results would arrive out of band.

Every server->host line is classified, and no line is relayed as the server
wrote it. Each relayed line is rebuilt from a projection fixed for its
kind; anything the proxy does not recognise is dropped:
- a reply to a gated request: every carrier goes through the purpose's field
  rule (``structuredContent``, a text that is JSON as a whole, an embedded
  resource's text); every other carrier (free text, binary data, resource
  links, ``_meta``, unknown keys) is *uninspected*;
- an error reply to a gated request: ``data`` through the field rule, the
  message uninspected;
- replies to ``initialize`` and the listings: interface metadata, spec keys
  only, and only the tools and families the policy maps; each entry is relayed
  as the operator approved it (``--interface-pins``) — an entry that is not
  pinned, or differs from its pin, is withheld (a tool keeps its policy-known
  name and an empty object schema; a prompt / resource / template is left out;
  ``initialize`` gets a neutral ``serverInfo``) and named
  ``interface_unapproved``;
- a reply that matches no outstanding host request (a duplicate) is dropped;
- server notifications: cancel / progress / list_changed / resources-updated
  are projected; server logs are uninspected; anything else is dropped;
- server requests: ``ping`` and ``roots/list`` are relayed under a proxy id;
  ``sampling/createMessage``, ``elicitation/create`` and anything else are
  refused (the server gets -32601, the host sees nothing).

``--uninspected withhold`` (default) replaces or removes uninspected carriers and
the event says ``access_reduced`` with a ``<withheld:path>`` marker per carrier.
``--uninspected pass`` relays them; the event then never says ``protected`` —
it carries ``reason_code=unfiltered_passthrough`` and ``<unfiltered:path>``
markers in ``allowed_fields``.

The call's purpose comes from the policy's ``tools`` map. In the proxy the host's
model writes ``arguments.purpose``, so a declared purpose that differs from the
mapping is refused (``declared_purpose_refused``) unless the operator passes
``--allow-declared-purpose``.

A ``tools/call``'s arguments (host->server) pass only by the tool's rule
(``--tool-rules``, the same shape as aegis-mcp-relay's ``tools``): every
argument leaf must be on the tool's ``arguments.allow`` list
(``argument_not_allowed``, the refused names in the event); a tool with no rule
is refused (``argument_rule_missing``). ``--unchecked-arguments pass`` forwards
a call whose tool has no rule and the reply's event names it unfiltered (never
``protected``).

Progress numbers are made by the proxy: a notification for a token the host
sent carries ``progress`` = how many the proxy has relayed for that token, never
the server's numbers, and no ``total``.

Named limits (documented, not closed):
- the presence and timing of lines are low-bandwidth channels a server can
  signal through on purpose; a relay cannot close them.
- a ``prompts/get`` or ``completion/complete`` argument reaches the server as
  the host wrote it (the call itself is gated by the policy's ``tools`` map).
- egress policy (``destinations``) is enforced by the SDK/gateway forms in v0.

Usage:
    python -m aegis_trust.mcp_proxy --policy policy.json --tool-rules rules.json \
        --interface-pins pins.json [--interface-candidates candidates.json] \
        [--agent-id claude-code] -- <real-server-command> [args...]

Host registration (e.g. Claude Code .mcp.json):
    {"mcpServers": {"crm": {"command": "python3",
        "args": ["-m", "aegis_trust.mcp_proxy", "--policy", "/etc/aegis/policy.json",
                 "--agent-id", "claude-code", "--", "node", "crm-server.js"]}}}
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, BinaryIO

from aegis_trust.canonical import (
    ENFORCEMENT_MCP_PROXY,
    CanonicalEmitter,
    CanonicalPolicy,
    CanonicalPurpose,
    load_canonical_policy,
)
from aegis_trust.errors import AegisConfigError, aegis_docs_url

try:  # single-source runtime version
    from aegis_trust import __version__ as _sdk_version
except Exception:  # pragma: no cover
    _sdk_version = "unknown"

PROXY_RUNTIME = f"mcp-proxy/{_sdk_version}"


class GatewayGate:
    """FULL-mode per-call gate for the proxy path (the third PEP grows teeth).

    LITE keeps today's behavior (local canonical filtering only). In FULL the
    proxy consults the gateway BEFORE forwarding a gated call, so a policy
    deny stops the tool from ever running — same fail-closed conventions as
    ``@shield``: a gate error is a deny, never a pass-through.

    Two gate kinds, EXPLICIT (never auto-probed — a silent up/downgrade of the
    enforcement primitive is exactly the drift Aegis refuses):

    - ``check-access``: the ``@shield``-parity purpose gate (POST
      /check-access) — works against every live gateway today. Scope-form
      purposes are checked one scope per call (the client fail-closes
      multi-scope requests, finding B).
    - ``tool-call``: the AI-native per-tool-call gate (POST /tool-call,
      AI_NATIVE_V1_CONTRACT.md) — role-keyed tool whitelist + chain-witnessed
      decision. Requires a boundary that serves the AI-native family.
    """

    def __init__(self, client: Any, kind: str, owner: str) -> None:
        if kind not in ("check-access", "tool-call"):
            raise ValueError(f"unknown gate kind {kind!r}")
        self.client = client
        self.kind = kind
        self.owner = owner

    def check(self, tool: str, purpose: CanonicalPurpose) -> tuple[bool, str]:
        """Returns (allowed, reason_code). Fail-closed on every error path."""
        scope = list(purpose.scope or [])
        if self.kind == "tool-call":
            # tool_allowed() is fail-closed internally (transport / non-200 /
            # malformed / non-passing / unledgered are all a deny).
            allowed = self.client.tool_allowed(
                tool, purpose.name, self.owner, fields=scope
            )
            return (True, "") if allowed else (False, "gateway_denied")
        # check_access (not authorize): authorize() swallows transport errors
        # into False, which would collapse "policy denied" and "gateway down"
        # into one audit reason. Both are a deny — but an auditor/on-call needs
        # to tell them apart, so the raising primitive + distinct reason codes.
        try:
            if scope:
                granted = all(
                    bool(self.client.check_access(purpose.name, [s]).get("allowed"))
                    for s in scope
                )
            else:
                granted = bool(
                    self.client.check_access(purpose.name, []).get("allowed")
                )
        except Exception:
            return False, "gateway_unavailable"
        return (True, "") if granted else (False, "gateway_denied")


#: Notice put in place of a text the proxy could not check against the purpose.
WITHHELD_NOTICE = (
    "[Aegis: withheld — content could not be checked against purpose '{purpose}']"
)
#: Message put in place of an upstream error message the proxy could not check.
UPSTREAM_ERROR_NOTICE = "upstream error (withheld by Aegis)"

# (ii-a) The finite sets a relayed protocol value must belong to. A value that
# merely matches a grammar can still carry a server-chosen string, so
# membership is the rule, never a pattern.
_PROTOCOL_VERSIONS = frozenset({"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"})
_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "text/plain",
        "text/markdown",
        "text/csv",
        "text/html",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "audio/wav",
        "audio/mpeg",
        "application/pdf",
    }
)
_ERROR_CODES = frozenset({-32700, -32600, -32601, -32602, -32603, -32002})
_LOG_LEVELS = frozenset(
    {"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}
)
_ROLES = frozenset({"user", "assistant"})
_CAPABILITY_FLAGS = {
    "logging": (),
    "completions": (),
    "prompts": ("listChanged",),
    "resources": ("subscribe", "listChanged"),
    "tools": ("listChanged",),
}
_TOOL_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

# Data-bearing host->server methods: each needs a purpose in the policy's tools
# map, and its reply goes through the field rule (G2) or the error rule (G3).
_GATED_METHODS = ("tools/call", "resources/read", "prompts/get", "completion/complete")
# Listing replies are interface metadata, projected per method. The value is the
# result key that holds the entries, and the data method that must be mapped for
# the family to be listed at all ("tools/call" is checked per tool name).
_LISTING_METHODS = {
    "tools/list": ("tools", "tools/call"),
    "resources/list": ("resources", "resources/read"),
    "resources/templates/list": ("resourceTemplates", "resources/read"),
    "prompts/list": ("prompts", "prompts/get"),
}
_EMPTY_RESULT_METHODS = frozenset(
    {"ping", "resources/subscribe", "resources/unsubscribe", "logging/setLevel"}
)
_RELAYED_SERVER_REQUESTS = frozenset({"ping", "roots/list"})
_LIST_CHANGED = frozenset(
    {
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/prompts/list_changed",
    }
)


#: The pin file's section for each listing, and the key that names an entry.
_PIN_SECTIONS = {
    "tools/list": ("tools", "name"),
    "prompts/list": ("prompts", "name"),
    "resources/list": ("resources", "uri"),
    "resources/templates/list": ("resourceTemplates", "uriTemplate"),
}
#: What a tool with no approved metadata is listed as: its policy-known name only.
_NEUTRAL_SCHEMA = {"type": "object"}
_NEUTRAL_SERVER_INFO = {"name": "mcp-server", "version": "0"}


def _obj(value: Any) -> dict[str, Any]:
    """The value when it is a JSON object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _json_equal(a: Any, b: Any) -> bool:
    """Equality of two parsed JSON values, the same in the three implementations:
    numbers by value, a boolean never equal to a number, objects by key set,
    arrays in order."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        return isinstance(a, (int, float)) and isinstance(b, (int, float)) and a == b
    if isinstance(a, dict):
        return (
            isinstance(b, dict)
            and a.keys() == b.keys()
            and all(_json_equal(a[k], b[k]) for k in a)
        )
    if isinstance(a, list):
        return (
            isinstance(b, list)
            and len(a) == len(b)
            and all(_json_equal(x, y) for x, y in zip(a, b))
        )
    return type(a) is type(b) and a == b


def _config_error(message: str, code: str) -> AegisConfigError:
    return AegisConfigError(
        message,
        code=code,
        remediation="Fix the proxy's --tool-rules / --interface-pins document; see schemas/v0/mcp-hosts.md.",
        docs_url=aegis_docs_url(code),
    )


def validate_tool_rules(raw: Any) -> dict[str, dict[str, Any]]:
    """The ``--tool-rules`` document, checked: ``{tool: {"access": "read" |
    "write", "arguments": {"allow": [path, ...]}}}``. ``query`` and ``fields``
    rules are judged by aegis-mcp-relay only; a document that has them is
    refused rather than read as if they were enforced here."""
    if not isinstance(raw, dict):
        raise _config_error(
            "tool rules must be a JSON object", "aegis.mcp_proxy.tool_rules_invalid"
        )
    out: dict[str, dict[str, Any]] = {}
    for tool, rule in raw.items():
        if not isinstance(tool, str) or not tool or not isinstance(rule, dict):
            raise _config_error(
                f"tool rule {tool!r} must be an object",
                "aegis.mcp_proxy.tool_rules_invalid",
            )
        unknown = set(rule) - {"access", "arguments"}
        if unknown:
            raise _config_error(
                f"tool rule {tool!r}: unknown keys {sorted(unknown)}",
                code="aegis.mcp_proxy.tool_rules_invalid",
            )
        if rule.get("access", "write") not in ("read", "write"):
            raise _config_error(
                f"tool rule {tool!r}: access must be read or write",
                code="aegis.mcp_proxy.tool_rules_invalid",
            )
        args = rule.get("arguments")
        if args is not None:
            if not isinstance(args, dict):
                raise _config_error(
                    f"tool rule {tool!r}: arguments must be an object",
                    code="aegis.mcp_proxy.tool_rules_invalid",
                )
            relay_only = set(args) & {"query", "fields"}
            if relay_only:
                raise _config_error(
                    f"tool rule {tool!r}: {sorted(relay_only)} are judged by aegis-mcp-relay "
                    "only; this proxy does not enforce them",
                    code="aegis.mcp_proxy.tool_rules_relay_only",
                )
            if set(args) - {"allow"}:
                raise _config_error(
                    f"tool rule {tool!r}: unknown argument keys {sorted(set(args) - {'allow'})}",
                    code="aegis.mcp_proxy.tool_rules_invalid",
                )
            allow = args.get("allow")
            if not isinstance(allow, list) or not all(
                isinstance(p, str) and p for p in allow
            ):
                raise _config_error(
                    f"tool rule {tool!r}: arguments.allow must be a list of paths",
                    code="aegis.mcp_proxy.tool_rules_invalid",
                )
        out[tool] = rule
    return out


def validate_interface_pins(raw: Any) -> dict[str, Any]:
    """The ``--interface-pins`` document: ``{"version": 0, "initialize": {...},
    "tools": {name: entry}, "prompts": {...}, "resources": {...},
    "resourceTemplates": {...}}``, each value a projected entry."""
    if not isinstance(raw, dict) or raw.get("version") != 0:
        raise _config_error(
            "interface pins must be an object with version 0",
            "aegis.mcp_proxy.interface_pins_invalid",
        )
    sections = {s for s, _ in _PIN_SECTIONS.values()}
    unknown = set(raw) - sections - {"version", "initialize"}
    if unknown:
        raise _config_error(
            f"interface pins: unknown keys {sorted(unknown)}",
            "aegis.mcp_proxy.interface_pins_invalid",
        )
    for section in sections:
        if not isinstance(raw.get(section, {}), dict):
            raise _config_error(
                f"interface pins: {section} must be an object",
                "aegis.mcp_proxy.interface_pins_invalid",
            )
    if "initialize" in raw and not isinstance(raw["initialize"], dict):
        raise _config_error(
            "interface pins: initialize must be an object",
            "aegis.mcp_proxy.interface_pins_invalid",
        )
    return raw


def _leaf_paths(value: Any, prefix: str, out: list[str], bad: list[str]) -> None:
    """Every leaf path of a tool call's arguments (an array or an empty object is
    a leaf). A key that is empty or contains '.' cannot be named by a path and is
    reported in ``bad``."""
    if isinstance(value, dict) and value:
        for key, item in value.items():
            if not key or "." in key:
                bad.append(f"{prefix}.{key}" if prefix else key)
                continue
            _leaf_paths(item, f"{prefix}.{key}" if prefix else key, out, bad)
    elif prefix:
        out.append(prefix)


def check_arguments(
    rule: dict[str, Any] | None, arguments: Any
) -> tuple[str, list[str]] | None:
    """The argument rule of one ``tools/call``: None = passes, else (reason,
    refused argument names). The same rule as aegis-mcp-relay's: a read tool and
    a write tool alike pass only with every leaf on ``arguments.allow``."""
    if rule is None:
        return "argument_rule_missing", []
    allow = _obj(rule.get("arguments")).get("allow")
    if not isinstance(allow, list):
        return "argument_rule_missing", []
    if arguments is None:
        return None
    if not isinstance(arguments, dict):
        return "argument_not_allowed", ["<arguments>"]
    paths: list[str] = []
    bad: list[str] = []
    _leaf_paths(arguments, "", paths, bad)
    refused = bad + [
        p for p in paths if not any(p == a or p.startswith(a + ".") for a in allow)
    ]
    if refused:
        return "argument_not_allowed", sorted(set(refused))
    return None


def _member(value: Any, allowed: frozenset[Any]) -> bool:
    """(ii-a) membership. A server value of any JSON type may arrive, and an
    object or array is unhashable: only a string or integer can be a member."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return False
    return value in allowed


def _id_key(value: Any) -> Any:
    """A JSON-RPC id usable as a dict key, or None when it cannot name a request
    (null, a boolean, an object or array)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int, float)):
        return (type(value).__name__, value)
    return None


@dataclass
class _HostRequest:
    """A request the proxy forwarded from the host, awaiting its one reply."""

    method: str
    operation: str
    purpose: str | None = None  # set only for gated methods
    uri: str | None = None  # resources/read: the URI the host asked for
    declared_override: bool = False  # the purpose came from arguments.purpose
    arguments_unchecked: bool = (
        False  # forwarded without a rule (--unchecked-arguments pass)
    )


class _Disclosure:
    """What one gated reply released, removed, withheld, or passed uninspected."""

    def __init__(self, purpose: str, uninspected: str) -> None:
        self.purpose = purpose
        self.pass_mode = uninspected == "pass"
        self.blocked: list[str] = []
        self.unfiltered: list[str] = []

    def uninspected(self, path: str) -> bool:
        """Record a carrier the field rule cannot apply to. True = relay it."""
        if self.pass_mode:
            self.unfiltered.append(f"<unfiltered:{path}>")
            return True
        self.blocked.append(f"<withheld:{path}>")
        return False

    def notice(self) -> str:
        return WITHHELD_NOTICE.format(purpose=self.purpose)

    def verdict(self) -> tuple[str | None, str | None, list[str], list[str]]:
        """(outcome, reason_code, blocked_fields, unfiltered markers).

        `protected` only when every carrier was inspected and nothing was
        removed; an uninspected carrier that was relayed never reads as
        protected (the outcome is omitted, or access_reduced if something was
        also removed)."""
        blocked = sorted(set(self.blocked))
        unfiltered = sorted(set(self.unfiltered))
        if unfiltered:
            return (
                "access_reduced" if blocked else None,
                "unfiltered_passthrough",
                blocked,
                unfiltered,
            )
        if blocked:
            return "access_reduced", "minimum_disclosure", blocked, unfiltered
        return "protected", None, blocked, unfiltered


class ShieldProxy:
    """JSON-RPC line proxy with tool-result minimization.

    No server line is relayed as the server wrote it: every relayed line is
    rebuilt from a projection fixed per kind of line, and anything the proxy
    does not recognise is dropped. A value in a projection is inspected by the
    purpose's field rule, is a protocol value that carries no server-chosen
    string (a member of a finite set, an echo of a host value, or a handle the
    proxy owns), or is uninspected and handled by ``uninspected``.
    """

    def __init__(
        self,
        policy: CanonicalPolicy,
        emitter: CanonicalEmitter,
        agent_id: str,
        session_id: str | None = None,
        gate: GatewayGate | None = None,
        uninspected: str = "withhold",
        allow_declared_purpose: bool = False,
        tool_rules: dict[str, dict[str, Any]] | None = None,
        unchecked_arguments: str = "refuse",
        interface_pins: dict[str, Any] | None = None,
        candidates_path: str | None = None,
    ) -> None:
        if uninspected not in ("withhold", "pass"):
            raise ValueError(f"unknown uninspected mode {uninspected!r}")
        if unchecked_arguments not in ("refuse", "pass"):
            raise ValueError(
                f"unknown unchecked_arguments mode {unchecked_arguments!r}"
            )
        self.policy = policy
        self.emitter = emitter
        self.agent_id = agent_id
        self.session_id = session_id
        self.gate = gate
        self.uninspected = uninspected
        self.allow_declared_purpose = allow_declared_purpose
        self.tool_rules = validate_tool_rules(tool_rules or {})
        self.unchecked_arguments = unchecked_arguments
        # No pin file = nothing approved (the metadata is withheld, not relayed).
        self.interface_pins = validate_interface_pins(interface_pins or {"version": 0})
        #: Projected server entries that were not relayed as pinned, for the
        #: operator to review and approve (``--interface-candidates``).
        self.candidates: dict[str, Any] = {"version": 0}
        self.candidates_path = candidates_path
        self._progress_counts: dict[Any, int] = {}
        self._pending: dict[Any, _HostRequest] = {}
        self._cursors: dict[
            str, tuple[str, Any]
        ] = {}  # handle -> (method, server cursor)
        self._server_requests: dict[str, Any] = {}  # proxy id -> server id
        self._server_ids: dict[Any, str] = {}  # server id key -> proxy id
        self._progress_tokens: set[Any] = set()
        self._subscriptions: set[str] = set()
        self._to_server: list[bytes] = []
        self._log_event_pending = True
        self._lock = threading.Lock()

    # -- host -> server ----------------------------------------------------
    def handle_client_line(self, line: bytes) -> tuple[bytes | None, bytes | None]:
        """Returns (forward_to_server, reply_to_client). Exactly one is set."""
        try:
            msg = json.loads(line)
        except ValueError:
            return line, None  # not ours to judge; transport passthrough
        if isinstance(msg, list):
            # JSON-RPC batch: a batched tools/call response would come back as
            # a batch and bypass result filtering. Current MCP spec has no
            # batching; fail-closed, never forward.
            self._deny("unknown", "<batch>", "batch_rejected")
            return None, self._block_reply(None, "<batch>", "batch_rejected")
        if not isinstance(msg, dict):
            return line, None
        method = msg.get("method")
        if not isinstance(method, str):
            # The host's reply to a server request the proxy relayed under its
            # own id goes back under the server's id.
            proxy_id = msg.get("id") if isinstance(msg.get("id"), str) else None
            with self._lock:
                server_id = (
                    self._server_requests.pop(proxy_id, None) if proxy_id else None
                )
                if server_id is not None:
                    self._server_ids.pop(_id_key(server_id), None)
            if server_id is not None:
                msg["id"] = server_id
                return _line(msg), None
            return line, None
        if "id" not in msg:
            return line, None  # a host notification
        msg_id = msg.get("id")
        params = _obj(msg.get("params"))
        self._remember_host_values(method, params)

        if method.startswith("tasks/"):
            # 2025-11-25 tasks carry a call's result out of band; refused.
            self._deny("unknown", method, "task_refused")
            return None, self._block_reply(msg_id, method, "task_refused")

        if method in _LISTING_METHODS and "cursor" in params:
            with self._lock:
                entry = (
                    self._cursors.get(params.get("cursor"))
                    if isinstance(params.get("cursor"), str)
                    else None
                )
            if entry is None or entry[0] != method:
                return None, _error_reply(msg_id, -32602, "Aegis: unknown cursor")
            params["cursor"] = entry[1]
            msg["params"] = params
            line = _line(msg)

        if method not in _GATED_METHODS:
            self._remember(msg_id, _HostRequest(method=method, operation=method))
            return line, None

        if method == "tools/call":
            operation = (
                params.get("name")
                if isinstance(params.get("name"), str)
                else "<unknown>"
            )
            if "task" in params:
                self._deny("unknown", operation, "task_augmented_refused")
                return None, self._block_reply(
                    msg_id, operation, "task_augmented_refused"
                )
            arguments = params.get("arguments")
            declared = arguments.get("purpose") if isinstance(arguments, dict) else None
            declared = declared if isinstance(declared, str) and declared else None
            lookup = operation
        else:
            ref = params.get("uri") or params.get("name") or ""
            if method == "completion/complete" and isinstance(params.get("ref"), dict):
                ref = params["ref"].get("name") or params["ref"].get("uri") or ""
            operation = f"{method}:{ref}" if isinstance(ref, str) else method
            lookup = method
            declared = None

        mapped = self.policy.tools.get(lookup)
        override = False
        if self.allow_declared_purpose:
            purpose = self.policy.purpose_for_tool(lookup, declared_purpose=declared)
            override = declared is not None and declared != mapped
        else:
            # The model writes arguments.purpose; in the proxy it is not the
            # caller the policy's "explicit declaration wins" rule trusts.
            if mapped is not None and declared is not None and declared != mapped:
                self._deny(declared, operation, "declared_purpose_refused")
                return None, self._block_reply(
                    msg_id, operation, "declared_purpose_refused"
                )
            purpose = self.policy.purposes.get(mapped) if mapped is not None else None

        if purpose is None:
            # fail-closed: unmapped tool/method => block, never forward
            self._deny(declared or "unknown", operation, "unknown_tool")
            return None, self._block_reply(msg_id, operation, "unknown_tool")

        # host->server: a tools/call's arguments pass only by the tool's rule.
        arguments_unchecked = False
        if method == "tools/call":
            rule = self.tool_rules.get(lookup)
            if rule is None and self.unchecked_arguments == "pass":
                arguments_unchecked = True
            else:
                refusal = check_arguments(rule, params.get("arguments"))
                if refusal is not None:
                    reason, names = refusal
                    self._deny(purpose.name, operation, reason, blocked_fields=names)
                    return None, self._block_reply(msg_id, operation, reason)

        if self.gate is not None:
            allowed, reason = self.gate.check(operation, purpose)
            if not allowed:
                # FULL gate deny: the tool NEVER runs (pre-call, like @shield —
                # side effects prevented, not just output discarded).
                self._deny(purpose.name, operation, reason)
                return None, self._block_reply(msg_id, operation, reason)

        uri = (
            params.get("uri")
            if method == "resources/read" and isinstance(params.get("uri"), str)
            else None
        )
        self._remember(
            msg_id,
            _HostRequest(
                method=method,
                operation=operation,
                purpose=purpose.name,
                uri=uri,
                declared_override=override,
                arguments_unchecked=arguments_unchecked,
            ),
        )
        return line, None

    def _remember(self, msg_id: Any, request: _HostRequest) -> None:
        key = _id_key(msg_id)
        if key is not None:
            with self._lock:
                self._pending[key] = request

    def _remember_host_values(self, method: str, params: dict[str, Any]) -> None:
        """(ii-b) values the host itself sent, which the server may echo back."""
        meta = params.get("_meta")
        token = meta.get("progressToken") if isinstance(meta, dict) else None
        uri = params.get("uri") if isinstance(params.get("uri"), str) else None
        with self._lock:
            if _id_key(token) is not None:
                self._progress_tokens.add(_id_key(token))
            if method == "resources/subscribe" and uri:
                self._subscriptions.add(uri)
            elif method == "resources/unsubscribe" and uri:
                self._subscriptions.discard(uri)

    @staticmethod
    def _block_reply(msg_id: Any, operation: str, reason: str) -> bytes:
        reply = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Aegis shield-proxy: '{operation}' blocked ({reason}, fail-closed).",
                    }
                ],
                "isError": True,
            },
        }
        return json.dumps(reply, ensure_ascii=False).encode() + b"\n"

    # -- server -> host ----------------------------------------------------
    def handle_server_line(self, line: bytes) -> bytes:
        """Returns the line to relay to the host (b"" = nothing). Lines the
        proxy owes the server (a refusal of a server request) are queued for
        ``drain_to_server``."""
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError):
            # MCP stdio frames are JSON lines. A non-JSON stdout line is a
            # protocol violation and could be a raw data dump around the
            # filter — drop it (fail-closed), never relay.
            sys.stderr.write("aegis-mcp-proxy: dropped non-JSON server stdout line\n")
            return b""
        if isinstance(msg, list):
            sys.stderr.write("aegis-mcp-proxy: dropped JSON-RPC batch from server\n")
            return b""
        if not isinstance(msg, dict):
            sys.stderr.write("aegis-mcp-proxy: dropped non-object server line\n")
            return b""
        method = msg.get("method")
        if isinstance(method, str):
            if "id" in msg:
                return self._server_request(msg, method)
            return self._server_notification(msg, method)
        if "id" in msg and ("result" in msg or "error" in msg):
            return self._server_reply(msg)
        sys.stderr.write("aegis-mcp-proxy: dropped unrecognised server line\n")
        return b""

    def drain_to_server(self) -> list[bytes]:
        """Lines the proxy itself owes the server, in order."""
        with self._lock:
            out, self._to_server = self._to_server, []
        return out

    def _server_reply(self, msg: dict[str, Any]) -> bytes:
        key = _id_key(msg.get("id"))
        with self._lock:
            request = self._pending.pop(key, None) if key is not None else None
        if request is None:
            # No outstanding host request has this id: a duplicate reply, or
            # one the host never asked for. Dropped — the first reply already
            # popped the pending entry, so relaying would bypass the filter.
            self._deny("unknown", "<reply>", "unmatched_response")
            return b""
        msg_id = msg.get("id")
        if request.purpose is not None:
            return self._gated_reply(msg_id, msg, request)
        if "error" in msg:
            return _line(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": self._ungated_error(msg["error"]),
                }
            )
        result = msg.get("result")
        if request.method == "initialize":
            projected = self._project_initialize(result)
            if projected is None:
                self._deny("unknown", "initialize", "protocol_version_unsupported")
                return _error_reply(
                    msg_id, -32603, "Aegis: unsupported protocol version"
                )
            pinned = self._pin_initialize(projected)
            self._flush_candidates()
            return _line({"jsonrpc": "2.0", "id": msg_id, "result": pinned})
        if request.method in _LISTING_METHODS:
            listing = self._project_listing(request.method, result)
            self._flush_candidates()
            return _line({"jsonrpc": "2.0", "id": msg_id, "result": listing})
        if request.method in _EMPTY_RESULT_METHODS:
            return _line({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        # A reply to a method the proxy has no projection for.
        self._deny("unknown", request.method, "unrecognized_method_reply")
        return _error_reply(
            msg_id, -32603, "Aegis: reply to an unrecognized method withheld"
        )

    def _gated_reply(
        self, msg_id: Any, msg: dict[str, Any], request: _HostRequest
    ) -> bytes:
        purpose = self.policy.purposes[request.purpose]  # type: ignore[index]
        disclosure = _Disclosure(purpose.name, self.uninspected)
        if request.arguments_unchecked:
            # The call went out without an argument rule: the reply never says protected.
            disclosure.unfiltered.append("<unfiltered:arguments>")
        if "error" in msg:
            out = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": self._gated_error(disclosure, purpose, msg["error"]),
            }
        else:
            out = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": self._project_gated_result(
                    disclosure, purpose, msg.get("result"), request
                ),
            }
        outcome, reason, blocked, unfiltered = disclosure.verdict()
        if request.declared_override:
            reason = "declared_purpose_override"
        self.emitter.emit(
            principal=self._principal(),
            purpose=purpose.name,
            operation=request.operation,
            decision="allow",
            outcome=outcome,
            reason_code=reason,
            blocked_fields=blocked,
            allowed_fields=unfiltered or None,
            scope=purpose.scope,
            deny_fields=purpose.deny_fields,
        )
        with self._lock:
            self._log_event_pending = True
        return _line(out)

    # G2: a gated result, rebuilt from the projection only.
    def _project_gated_result(
        self,
        d: _Disclosure,
        purpose: CanonicalPurpose,
        result: Any,
        request: _HostRequest,
    ) -> Any:
        if not isinstance(result, dict):
            return result if d.uninspected("result") else {}
        out: dict[str, Any] = {}
        for key, value in result.items():
            if key == "structuredContent" and isinstance(value, (dict, list)):
                out[key] = self._apply_rule(d, purpose, value)
            elif key == "isError" and isinstance(value, bool):
                out[key] = value
            elif (
                key == "content"
                and isinstance(value, list)
                and request.method == "tools/call"
            ):
                out[key] = [
                    self._project_block(d, purpose, item, f"content[{i}]")
                    for i, item in enumerate(value)
                ]
            elif (
                key == "contents"
                and isinstance(value, list)
                and request.method == "resources/read"
            ):
                out[key] = [
                    self._project_contents(
                        d, purpose, item, f"contents[{i}]", request.uri
                    )
                    for i, item in enumerate(value)
                ]
            elif (
                key == "messages"
                and isinstance(value, list)
                and request.method == "prompts/get"
            ):
                messages = []
                for i, item in enumerate(value):
                    projected = self._project_message(
                        d, purpose, item, f"messages[{i}]"
                    )
                    if projected is not None:
                        messages.append(projected)
                out[key] = messages
            elif (
                key == "completion"
                and isinstance(value, dict)
                and request.method == "completion/complete"
            ):
                out[key] = self._project_completion(d, value)
            elif d.uninspected(key):
                out[key] = value
        return out

    def _apply_rule(
        self, d: _Disclosure, purpose: CanonicalPurpose, payload: Any
    ) -> Any:
        filtered, removed = self.policy.filter_payload(purpose, payload)
        d.blocked.extend(removed)
        return filtered

    def _project_text(
        self, d: _Disclosure, purpose: CanonicalPurpose, text: Any, path: str
    ) -> Any:
        """The text to relay: the field rule's output when the text is JSON as a
        whole, the text itself when uninspected carriers pass, else None."""
        if isinstance(text, str):
            try:
                payload = json.loads(text)
            except (ValueError, RecursionError):
                payload = None
            if isinstance(payload, (dict, list)):
                return json.dumps(
                    self._apply_rule(d, purpose, payload), ensure_ascii=False
                )
        return text if d.uninspected(path) else None

    def _rest(
        self,
        d: _Disclosure,
        source: dict[str, Any],
        out: dict[str, Any],
        path: str,
        known: tuple[str, ...],
    ) -> None:
        """Every key outside the projection is uninspected."""
        for key, value in source.items():
            if key not in known and d.uninspected(f"{path}.{key}"):
                out[key] = value

    def _media(
        self, d: _Disclosure, source: dict[str, Any], out: dict[str, Any], path: str
    ) -> None:
        mime = source.get("mimeType")
        if mime is None:
            return
        if _member(mime, _MEDIA_TYPES):
            out["mimeType"] = mime
        elif d.uninspected(f"{path}.mimeType"):
            out["mimeType"] = mime

    def _project_block(
        self, d: _Disclosure, purpose: CanonicalPurpose, item: Any, path: str
    ) -> Any:
        """A content block (tools/call content, prompts/get message content)."""
        if not isinstance(item, dict):
            return item if d.uninspected(path) else {"type": "text", "text": d.notice()}
        kind = item.get("type")
        if kind == "text":
            text = self._project_text(d, purpose, item.get("text"), f"{path}.text")
            out: dict[str, Any] = {
                "type": "text",
                "text": d.notice() if text is None else text,
            }
            self._rest(d, item, out, path, ("type", "text"))
            return out
        if kind == "resource" and isinstance(item.get("resource"), dict):
            resource = item["resource"]
            text = (
                self._project_text(
                    d, purpose, resource.get("text"), f"{path}.resource.text"
                )
                if "text" in resource
                else None
            )
            if text is None and not d.pass_mode:
                # Nothing in the item could be inspected (blob, or text that is
                # not JSON): the whole item becomes the notice.
                self._rest(d, resource, {}, f"{path}.resource", ("text", "mimeType"))
                return {"type": "text", "text": d.notice()}
            inner: dict[str, Any] = {}
            uri = resource.get("uri")
            if uri is not None:
                if d.uninspected(f"{path}.resource.uri"):
                    inner["uri"] = uri
                else:
                    inner["uri"] = "aegis:withheld"
            self._media(d, resource, inner, f"{path}.resource")
            if text is not None:
                inner["text"] = text
            self._rest(
                d, resource, inner, f"{path}.resource", ("uri", "mimeType", "text")
            )
            out = {"type": "resource", "resource": inner}
            self._rest(d, item, out, path, ("type", "resource"))
            return out
        # image / audio data, resource_link, an unknown type: nothing to apply
        # the field rule to.
        if d.uninspected(path):
            return item
        return {"type": "text", "text": d.notice()}

    def _project_contents(
        self,
        d: _Disclosure,
        purpose: CanonicalPurpose,
        item: Any,
        path: str,
        asked: str | None,
    ) -> Any:
        """resources/read contents: {uri, mimeType?, text | blob}."""
        if not isinstance(item, dict):
            return (
                item
                if d.uninspected(path)
                else {"uri": asked or "aegis:withheld", "text": d.notice()}
            )
        out: dict[str, Any] = {}
        uri = item.get("uri")
        if isinstance(uri, str) and uri == asked:
            out["uri"] = uri  # (ii-b) the URI the host asked for
        elif uri is not None and d.uninspected(f"{path}.uri"):
            out["uri"] = uri
        else:
            out["uri"] = asked or "aegis:withheld"
        self._media(d, item, out, path)
        if "text" in item:
            text = self._project_text(d, purpose, item.get("text"), f"{path}.text")
            out["text"] = d.notice() if text is None else text
        elif not d.pass_mode:
            out["text"] = d.notice()
        self._rest(d, item, out, path, ("uri", "mimeType", "text"))
        return out

    def _project_message(
        self, d: _Disclosure, purpose: CanonicalPurpose, item: Any, path: str
    ) -> Any:
        if not isinstance(item, dict) or not _member(item.get("role"), _ROLES):
            return item if d.uninspected(path) else None
        out: dict[str, Any] = {"role": item["role"]}
        out["content"] = self._project_block(
            d, purpose, item.get("content"), f"{path}.content"
        )
        self._rest(d, item, out, path, ("role", "content"))
        return out

    def _project_completion(
        self, d: _Disclosure, completion: dict[str, Any]
    ) -> dict[str, Any]:
        out: dict[str, Any] = {"values": []}
        for key, value in completion.items():
            if d.uninspected(f"completion.{key}"):
                out[key] = value
        return out

    # G3: an error reply to a gated request.
    def _gated_error(
        self, d: _Disclosure, purpose: CanonicalPurpose, error: Any
    ) -> dict[str, Any]:
        if not isinstance(error, dict):
            d.uninspected("error")
            return {"code": -32603, "message": UPSTREAM_ERROR_NOTICE}
        code = error.get("code")
        out: dict[str, Any] = {"code": code if _member(code, _ERROR_CODES) else -32603}
        message = error.get("message")
        if message is not None and d.uninspected("error.message"):
            out["message"] = message
        else:
            out["message"] = UPSTREAM_ERROR_NOTICE
        if "data" in error:
            data = error["data"]
            if isinstance(data, (dict, list)):
                out["data"] = self._apply_rule(d, purpose, data)
            elif d.uninspected("error.data"):
                out["data"] = data
        self._rest(d, error, out, "error", ("code", "message", "data"))
        return out

    def _ungated_error(self, error: Any) -> dict[str, Any]:
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        return {
            "code": code if _member(code, _ERROR_CODES) else -32603,
            "message": message
            if self.uninspected == "pass" and isinstance(message, str)
            else UPSTREAM_ERROR_NOTICE,
        }

    # Ungated replies: interface metadata, projected per method.
    def _project_initialize(self, result: Any) -> dict[str, Any] | None:
        if not isinstance(result, dict) or not _member(
            result.get("protocolVersion"), _PROTOCOL_VERSIONS
        ):
            return None
        out: dict[str, Any] = {"protocolVersion": result["protocolVersion"]}
        caps = _obj(result.get("capabilities"))
        projected_caps: dict[str, Any] = {}
        for name, flags in _CAPABILITY_FLAGS.items():
            value = caps.get(name)
            if isinstance(value, dict):
                projected_caps[name] = {
                    f: value[f] for f in flags if isinstance(value.get(f), bool)
                }
        out["capabilities"] = projected_caps
        info = _obj(result.get("serverInfo"))
        server_info = {
            k: info[k]
            for k in ("name", "title", "version")
            if isinstance(info.get(k), str)
        }
        server_info.setdefault("name", "mcp-server")
        server_info.setdefault("version", "0")
        out["serverInfo"] = server_info
        if isinstance(result.get("instructions"), str):
            out["instructions"] = result["instructions"]
        return out

    def _family_mapped(self, method: str) -> bool:
        data_method = _LISTING_METHODS[method][1]
        return data_method == "tools/call" or data_method in self.policy.tools

    def _pin_initialize(self, projected: dict[str, Any]) -> dict[str, Any]:
        """``serverInfo`` and ``instructions`` are server-written: relayed only as
        approved (the pin's ``initialize``)."""
        interface = {
            k: projected[k] for k in ("serverInfo", "instructions") if k in projected
        }
        pinned = self.interface_pins.get("initialize")
        if pinned is not None and _json_equal(pinned, interface):
            return projected
        with self._lock:
            self.candidates["initialize"] = interface
        if self.uninspected == "pass":
            self._interface_event("initialize", [], ["<unfiltered:initialize>"])
            return projected
        out = {k: v for k, v in projected.items() if k not in interface}
        out["serverInfo"] = dict(_NEUTRAL_SERVER_INFO)
        self._interface_event("initialize", ["<withheld:initialize>"], [])
        return out

    def _pin_entry(
        self,
        method: str,
        index: int,
        projected: dict[str, Any],
        withheld: list[str],
        unfiltered: list[str],
    ) -> dict[str, Any] | None:
        """One listing entry: the pinned value when the server's projected entry
        equals it; otherwise withheld (a tool keeps its policy-known name only)
        or, under ``uninspected=pass``, relayed and named."""
        section, key_name = _PIN_SECTIONS[method]
        key = projected.get(key_name)
        pinned = (
            _obj(self.interface_pins.get(section)).get(key)
            if isinstance(key, str)
            else None
        )
        if pinned is not None and _json_equal(pinned, projected):
            return pinned
        if isinstance(key, str):
            with self._lock:
                self.candidates.setdefault(section, {})[key] = projected
        # A tool's name comes from the operator's policy; any other entry's name
        # or URI is server-written, so the marker names its position only.
        marker = f"{method}:{key}" if method == "tools/list" else f"{method}[{index}]"
        if self.uninspected == "pass":
            unfiltered.append(f"<unfiltered:{marker}>")
            return projected
        withheld.append(f"<withheld:{marker}>")
        if method == "tools/list":
            return {"name": key, "inputSchema": dict(_NEUTRAL_SCHEMA)}
        return None

    def _flush_candidates(self) -> None:
        """Write the candidates for the operator (owner-only, replaced whole).
        The file holds server-written metadata: it is for review, never relayed."""
        if not self.candidates_path:
            return
        with self._lock:
            body = json.dumps(
                self.candidates, ensure_ascii=False, indent=1, sort_keys=True
            )
        tmp = f"{self.candidates_path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        os.replace(tmp, self.candidates_path)

    def _interface_event(
        self, operation: str, withheld: list[str], unfiltered: list[str]
    ) -> None:
        if not withheld and not unfiltered:
            return
        self.emitter.emit(
            principal=self._principal(),
            purpose="unknown",
            operation=operation,
            decision="allow",
            outcome="access_reduced" if withheld else None,
            reason_code="interface_unapproved"
            if withheld
            else "unfiltered_passthrough",
            blocked_fields=sorted(set(withheld)),
            allowed_fields=sorted(set(unfiltered)) or None,
        )

    def _project_listing(self, method: str, result: Any) -> dict[str, Any]:
        key = _LISTING_METHODS[method][0]
        entries = result.get(key) if isinstance(result, dict) else None
        out: dict[str, Any] = {key: []}
        if not self._family_mapped(method) or not isinstance(entries, list):
            return out
        withheld: list[str] = []
        unfiltered: list[str] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            projected = self._project_entry(method, entry)
            if projected is not None:
                relayed = self._pin_entry(
                    method, index, projected, withheld, unfiltered
                )
                if relayed is not None:
                    out[key].append(relayed)
        self._interface_event(method, withheld, unfiltered)
        cursor = result.get("nextCursor")
        if isinstance(cursor, str) and cursor:
            handle = "aegis-cursor-" + secrets.token_hex(16)  # (ii-c)
            with self._lock:
                self._cursors[handle] = (method, cursor)
            out["nextCursor"] = handle
        return out

    def _project_entry(
        self, method: str, entry: dict[str, Any]
    ) -> dict[str, Any] | None:
        def strings(*keys: str) -> dict[str, Any]:
            return {k: entry[k] for k in keys if isinstance(entry.get(k), str)}

        if method == "tools/list":
            name = entry.get("name")
            if not isinstance(name, str):
                return None
            if not self.allow_declared_purpose and name not in self.policy.tools:
                return None  # calling it would be blocked anyway
            out = strings("name", "title", "description")
            out["inputSchema"] = (
                entry["inputSchema"]
                if isinstance(entry.get("inputSchema"), dict)
                else {"type": "object"}
            )
            if isinstance(entry.get("outputSchema"), dict):
                out["outputSchema"] = entry["outputSchema"]
            hints = entry.get("annotations")
            if isinstance(hints, dict):
                kept = {
                    h: hints[h] for h in _TOOL_HINTS if isinstance(hints.get(h), bool)
                }
                if kept:
                    out["annotations"] = kept
            return out
        if method == "prompts/list":
            if not isinstance(entry.get("name"), str):
                return None
            out = strings("name", "title", "description")
            args = entry.get("arguments")
            if isinstance(args, list):
                out["arguments"] = [
                    {
                        **{
                            k: a[k]
                            for k in ("name", "title", "description")
                            if isinstance(a.get(k), str)
                        },
                        **(
                            {"required": a["required"]}
                            if isinstance(a.get("required"), bool)
                            else {}
                        ),
                    }
                    for a in args
                    if isinstance(a, dict) and isinstance(a.get("name"), str)
                ]
            return out
        locator = "uri" if method == "resources/list" else "uriTemplate"
        if not isinstance(entry.get(locator), str) or not isinstance(
            entry.get("name"), str
        ):
            return None
        out = strings(locator, "name", "title", "description")
        if _member(entry.get("mimeType"), _MEDIA_TYPES):
            out["mimeType"] = entry["mimeType"]
        return out

    # Server notifications and server requests.
    def _server_notification(self, msg: dict[str, Any], method: str) -> bytes:
        params = _obj(msg.get("params"))
        out: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if method == "notifications/cancelled":
            # The server cancels a request it sent; relayed only under the id
            # the host saw (ii-c).
            with self._lock:
                proxy_id = self._server_ids.get(_id_key(params.get("requestId")))
            if proxy_id is None:
                return b""
            out["params"] = {"requestId": proxy_id}
            reason = params.get("reason")
            if reason is not None and self.uninspected == "pass":
                out["params"]["reason"] = reason
            return _line(out)
        if method == "notifications/progress":
            token = params.get("progressToken")
            with self._lock:
                known = (
                    _id_key(token) is not None
                    and _id_key(token) in self._progress_tokens
                )
            if not known:
                return b""
            # The number is the proxy's own count, never the server's: a number a
            # server chooses can carry a value one notification at a time.
            with self._lock:
                count = self._progress_counts.get(_id_key(token), 0) + 1
                self._progress_counts[_id_key(token)] = count
            projected: dict[str, Any] = {"progressToken": token, "progress": count}
            if params.get("message") is not None and self.uninspected == "pass":
                projected["message"] = params["message"]
            out["params"] = projected
            return _line(out)
        if method in _LIST_CHANGED:
            return _line(out)
        if method == "notifications/resources/updated":
            uri = params.get("uri")
            with self._lock:
                subscribed = isinstance(uri, str) and uri in self._subscriptions
            if not subscribed:
                return b""
            out["params"] = {"uri": uri}
            return _line(out)
        if method == "notifications/message":
            # A server log: free-form diagnostics nothing can be filtered on.
            with self._lock:
                first = self._log_event_pending
                self._log_event_pending = False
            if self.uninspected == "pass":
                if first:
                    self._event_uninspected_log(passed=True)
                projected = (
                    {"level": params["level"]}
                    if _member(params.get("level"), _LOG_LEVELS)
                    else {"level": "info"}
                )
                for key in ("logger", "data"):
                    if key in params:
                        projected[key] = params[key]
                out["params"] = projected
                return _line(out)
            if first:
                self._event_uninspected_log(passed=False)
            return b""
        self._deny("unknown", method, "server_notification_dropped")
        return b""

    def _event_uninspected_log(self, *, passed: bool) -> None:
        marker = "notifications/message.params"
        self.emitter.emit(
            principal=self._principal(),
            purpose="unknown",
            operation="notifications/message",
            decision="allow" if passed else "deny",
            outcome=None if passed else "blocked",
            reason_code="unfiltered_passthrough" if passed else "server_log_withheld",
            blocked_fields=[] if passed else [f"<withheld:{marker}>"],
            allowed_fields=[f"<unfiltered:{marker}>"] if passed else None,
        )

    def _server_request(self, msg: dict[str, Any], method: str) -> bytes:
        server_id = msg.get("id")
        if method in _RELAYED_SERVER_REQUESTS and _id_key(server_id) is not None:
            proxy_id = "aegis-srv-" + secrets.token_hex(8)  # (ii-c)
            with self._lock:
                self._server_requests[proxy_id] = server_id
                self._server_ids[_id_key(server_id)] = proxy_id
            return _line({"jsonrpc": "2.0", "id": proxy_id, "method": method})
        # sampling/createMessage, elicitation/create, tasks/*, anything else:
        # never relayed to the host; the server is told no.
        self._deny("unknown", method, "server_request_refused")
        with self._lock:
            self._to_server.append(
                _error_reply(server_id, -32601, "Aegis: server-to-host request refused")
            )
        return b""

    def _deny(
        self,
        purpose: str,
        operation: str,
        reason: str,
        blocked_fields: list[str] | None = None,
    ) -> None:
        """A refusal. ``blocked_fields`` names what was refused (argument names,
        never values)."""
        self.emitter.emit(
            principal=self._principal(),
            purpose=purpose,
            operation=operation,
            decision="deny",
            outcome="blocked",
            reason_code=reason,
            blocked_fields=sorted(set(blocked_fields or [])),
        )

    def _principal(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "transport": "mcp",
        }


def _read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise _config_error(
            f"cannot read {path}: {exc}", "aegis.mcp_proxy.proxy_config_unreadable"
        ) from exc


def _line(msg: Any) -> bytes:
    return json.dumps(msg, ensure_ascii=False).encode() + b"\n"


def _error_reply(msg_id: Any, code: int, message: str) -> bytes:
    return _line(
        {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
    )


def _pump_client_to_server(
    proxy: ShieldProxy,
    client_in: BinaryIO,
    server_in: BinaryIO,
    client_out: BinaryIO,
    server_lock: threading.Lock,
    client_lock: threading.Lock,
) -> None:
    for line in iter(client_in.readline, b""):
        if not line.strip():
            continue
        forward, reply = proxy.handle_client_line(line)
        if reply is not None:
            with client_lock:
                client_out.write(reply)
                client_out.flush()
        if forward is not None:
            with server_lock:
                server_in.write(forward if forward.endswith(b"\n") else forward + b"\n")
                server_in.flush()
    try:
        server_in.close()
    except OSError:
        pass


def _pump_server_to_client(
    proxy: ShieldProxy,
    server_out: BinaryIO,
    client_out: BinaryIO,
    server_in: BinaryIO,
    server_lock: threading.Lock,
    client_lock: threading.Lock,
) -> None:
    for line in iter(server_out.readline, b""):
        if not line.strip():
            continue
        relayed = proxy.handle_server_line(line)
        if relayed:
            with client_lock:
                client_out.write(relayed)
                client_out.flush()
        owed = proxy.drain_to_server()
        if owed:
            with server_lock:
                try:
                    for out in owed:
                        server_in.write(out)
                    server_in.flush()
                except (OSError, ValueError):
                    pass  # the server's stdin is gone; nothing more to tell it


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-mcp-proxy",
        description="Aegis shield-proxy: canonical-policy enforcement at the MCP process boundary.",
    )
    parser.add_argument(
        "--policy", required=True, help="aegis-policy v0 document (JSON or YAML)"
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("AEGIS_AGENT_ID", "mcp-host"),
        help="advisory principal id of the host agent (e.g. claude-code, codex, agy)",
    )
    parser.add_argument("--session-id", default=os.environ.get("AEGIS_SESSION_ID"))
    parser.add_argument("--audit-path", default=None, help="canonical event JSONL path")
    parser.add_argument(
        "--gate",
        choices=["check-access", "tool-call"],
        default=os.environ.get("AEGIS_MCP_GATE", "check-access"),
        help=(
            "FULL-mode gate primitive (explicit, never auto-probed): "
            "'check-access' = @shield-parity purpose gate (works on every live "
            "gateway); 'tool-call' = AI-native per-tool-call gate "
            "(AI_NATIVE_V1_CONTRACT.md; requires a boundary serving it)"
        ),
    )
    parser.add_argument(
        "--owner",
        default=os.environ.get("AEGIS_OWNER"),
        help="principal.owner for the tool-call gate (defaults to --agent-id)",
    )
    parser.add_argument(
        "--uninspected",
        choices=["withhold", "pass"],
        default="withhold",
        help=(
            "what to do with server output the field rule cannot apply to (free "
            "text, binary data, _meta, unknown keys, server logs): 'withhold' "
            "(default) replaces or removes it; 'pass' relays it and the event "
            "names each carrier as unfiltered, never 'protected'"
        ),
    )
    parser.add_argument(
        "--allow-declared-purpose",
        action="store_true",
        help=(
            "honour arguments.purpose over the policy's tools map (the earlier "
            "rule). In the proxy the host's model writes that argument, so this "
            "lets the model choose its purpose; events say declared_purpose_override"
        ),
    )
    parser.add_argument(
        "--tool-rules",
        default=None,
        help=(
            "per-tool argument rules (JSON, aegis-mcp-relay's `tools` shape): "
            "every argument leaf must be on the tool's arguments.allow; a tool with "
            "no rule is refused"
        ),
    )
    parser.add_argument(
        "--unchecked-arguments",
        choices=["refuse", "pass"],
        default="refuse",
        help=(
            "a call whose tool has no rule: 'refuse' (default), or 'pass' — "
            "forwarded, and the reply's event names the arguments unfiltered"
        ),
    )
    parser.add_argument(
        "--interface-pins",
        default=None,
        help=(
            "approved interface metadata (JSON): an entry is relayed only as "
            "pinned; without a pin it is withheld (a tool keeps its name only)"
        ),
    )
    parser.add_argument(
        "--interface-candidates",
        default=None,
        help="where to write the server's unapproved entries for review (0600)",
    )
    parser.add_argument(
        "server_cmd", nargs=argparse.REMAINDER, help="-- real MCP server command"
    )
    args = parser.parse_args(argv)

    # argparse validates `choices` only for the flag form; an invalid
    # AEGIS_MCP_GATE env value arrives via `default` unchecked. Validate the
    # merged value like the Node proxy does (exit 2, same message shape).
    if args.gate not in ("check-access", "tool-call"):
        parser.error(f"unknown --gate {args.gate} (check-access | tool-call)")

    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing real MCP server command after --")

    try:
        policy = load_canonical_policy(
            args.policy
        )  # fail-closed: structural error aborts startup
    except AegisConfigError as exc:
        # Coded one-liner on stderr, exit 2 — parity with the Node proxy.
        # A raw traceback here hid the machine-parseable `code` operators grep
        # for, and exit 1 diverged from Node's exit 2 for the same mistake.
        print(f"aegis-mcp-proxy: {exc} [{exc.code}]", file=sys.stderr)
        return 2
    try:
        tool_rules = (
            validate_tool_rules(_read_json(args.tool_rules)) if args.tool_rules else {}
        )
        pins = (
            validate_interface_pins(_read_json(args.interface_pins))
            if args.interface_pins
            else None
        )
    except AegisConfigError as exc:
        print(f"aegis-mcp-proxy: {exc} [{exc.code}]", file=sys.stderr)
        return 2
    emitter = CanonicalEmitter(
        ENFORCEMENT_MCP_PROXY,
        PROXY_RUNTIME,
        path=args.audit_path,
        policy_id=policy.policy_id,
    )
    # FULL-mode gate: armed only on explicit intent (AEGIS_MODE=full, or
    # AEGIS_MODE=auto resolving FULL via the same detector @shield uses).
    # Unset/lite keeps today's LITE-only proxy byte-for-byte.
    gate = None
    mode_env = os.environ.get("AEGIS_MODE", "").strip().lower()
    if mode_env and mode_env != "lite":
        from aegis_trust.shield import _detect_mode, _get_client
        from aegis_trust.types import Mode

        if _detect_mode() == Mode.FULL:
            gate = GatewayGate(
                _get_client(), args.gate, owner=args.owner or args.agent_id
            )
            print(
                f"aegis-mcp-proxy: FULL gate armed ({args.gate}) — gateway consulted "
                "before every gated call (deny = tool never runs, fail-closed)",
                file=sys.stderr,
            )

    proxy = ShieldProxy(
        policy,
        emitter,
        agent_id=args.agent_id,
        session_id=args.session_id,
        gate=gate,
        uninspected=args.uninspected,
        allow_declared_purpose=args.allow_declared_purpose,
        tool_rules=tool_rules,
        unchecked_arguments=args.unchecked_arguments,
        interface_pins=pins,
        candidates_path=args.interface_candidates,
    )
    if args.unchecked_arguments == "pass":
        print(
            "aegis-mcp-proxy: --unchecked-arguments pass — a call whose tool has no "
            "rule is forwarded and recorded as unfiltered",
            file=sys.stderr,
        )
    if pins is None:
        print(
            "aegis-mcp-proxy: no --interface-pins — the server's interface metadata is "
            "withheld until approved (tools keep their names)",
            file=sys.stderr,
        )
    if args.uninspected == "pass":
        print(
            "aegis-mcp-proxy: --uninspected pass — output the field rule cannot "
            "check is relayed and recorded as unfiltered",
            file=sys.stderr,
        )
    if args.allow_declared_purpose:
        print(
            "aegis-mcp-proxy: --allow-declared-purpose — arguments.purpose overrides "
            "the tools map (the host's model chooses the purpose)",
            file=sys.stderr,
        )

    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr.fileno(),
    )
    assert server.stdin is not None and server.stdout is not None

    client_in = sys.stdin.buffer
    client_out = sys.stdout.buffer
    # Both pumps write to each side (the proxy answers the host for blocked
    # calls and the server for refused server requests), so each side's
    # stream has one lock.
    server_lock = threading.Lock()
    client_lock = threading.Lock()
    t1 = threading.Thread(
        target=_pump_client_to_server,
        args=(proxy, client_in, server.stdin, client_out, server_lock, client_lock),
        daemon=True,
    )
    t2 = threading.Thread(
        target=_pump_server_to_client,
        args=(proxy, server.stdout, client_out, server.stdin, server_lock, client_lock),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join(timeout=5)
    server.terminate()
    return server.wait(timeout=5) or 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
