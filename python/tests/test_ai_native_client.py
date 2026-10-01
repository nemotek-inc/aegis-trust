"""AI-native v1 client methods (tool-call / capability / stream) — wire-floor
unit tests against the frozen boundary contract (AI_NATIVE_V1_CONTRACT.md).

MockTransport house pattern (test_client_boundary.py): capture the outgoing
body, return canned responses, assert fail-closed parsing.
"""

from __future__ import annotations

import json

import httpx
import pytest

from aegis_trust.client import AegisClient
from aegis_trust.types import CapabilityGrant, StreamStatus

DECISION_OK = {
    "outcome": "PROTECTED",
    "ledgered": True,
    "decision_id": "d-1",
}


def _client_with_transport(handler) -> AegisClient:
    c = AegisClient(base_url="https://localhost:8443/api/v1", verify_ssl=False)
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    return c


# ── tool-call ────────────────────────────────────────────────────────


def test_tool_call_body_and_parse():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})

    c = _client_with_transport(handler)
    out = c.tool_call(
        "query_business_data",
        "customer_data",
        "acme",
        fields=["name"],
        session_id="s-1",
        destination="llm:anthropic",
    )
    assert captured["path"].endswith("/tool-call")
    assert captured["body"] == {
        "tool": "query_business_data",
        "purpose": "customer_data",
        "owner": "acme",
        "fields": ["name"],
        "session_id": "s-1",
        "destination": "llm:anthropic",
    }
    assert out["decision"]["outcome"] == "PROTECTED"


def test_tool_call_capability_attached_only_when_given():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})

    c = _client_with_transport(handler)
    c.tool_call("t", "p", "o")
    assert "capability" not in captured["body"]
    c.tool_call("t", "p", "o", capability="tok")
    assert captured["body"]["capability"] == "tok"


def test_tool_call_malformed_decision_raises():
    c = _client_with_transport(
        lambda req: httpx.Response(200, json={"decision": {"outcome": "PROTECTED"}})
    )
    with pytest.raises(ValueError, match="ledgered"):
        c.tool_call("t", "p", "o")


def test_tool_allowed_fail_closed_paths():
    # transport error → deny
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    assert _client_with_transport(boom).tool_allowed("t", "p", "o") is False
    # non-200 → deny
    c = _client_with_transport(lambda req: httpx.Response(503, json={}))
    assert c.tool_allowed("t", "p", "o") is False
    # BLOCKED (HTTP 200) → deny
    c = _client_with_transport(
        lambda req: httpx.Response(
            200, json={"decision": {"outcome": "BLOCKED", "ledgered": True}}
        )
    )
    assert c.tool_allowed("t", "p", "o") is False
    # passing but NOT ledgered → deny (a decision the chain did not witness)
    c = _client_with_transport(
        lambda req: httpx.Response(
            200, json={"decision": {"outcome": "PROTECTED", "ledgered": False}}
        )
    )
    assert c.tool_allowed("t", "p", "o") is False
    # passing + ledgered → allow
    c = _client_with_transport(
        lambda req: httpx.Response(
            200, json={"decision": DECISION_OK, "enforcement": None}
        )
    )
    assert c.tool_allowed("t", "p", "o") is True


# ── capability lineage ───────────────────────────────────────────────

GRANT_OK = {
    "capability": "tok-abc",
    "id": "c1d2",
    "exp": 1_900_000_000,
    "depth": 1,
    "root_delegator": "root-agent",
}


def test_capability_mint_body_and_parse():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=GRANT_OK)

    c = _client_with_transport(handler)
    grant = c.capability_mint(
        "sub-agent",
        ["customer_data"],
        scope=["name"],
        tools=["t1"],
        ttl_secs=600,
        parent_capability="parent-tok",
    )
    assert captured["path"].endswith("/capability/mint")
    assert captured["body"] == {
        "for_agent": "sub-agent",
        "purposes": ["customer_data"],
        "scope": ["name"],
        "tools": ["t1"],
        "ttl_secs": 600,
        "parent_capability": "parent-tok",
    }
    assert grant == CapabilityGrant(
        capability="tok-abc",
        id="c1d2",
        exp=1_900_000_000,
        depth=1,
        root_delegator="root-agent",
    )


@pytest.mark.parametrize(
    "missing", ["capability", "id", "exp", "depth", "root_delegator"]
)
def test_capability_mint_malformed_raises(missing):
    body = {k: v for k, v in GRANT_OK.items() if k != missing}
    c = _client_with_transport(lambda req: httpx.Response(200, json=body))
    with pytest.raises(ValueError, match=missing):
        c.capability_mint("a", ["p"])


def test_capability_revoke_by_token_and_id():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True, "revoked": "c1d2"})

    c = _client_with_transport(handler)
    assert c.capability_revoke(capability="tok") == "c1d2"
    assert captured["body"] == {"capability": "tok"}
    assert c.capability_revoke(capability_id="c1d2") == "c1d2"
    assert captured["body"] == {"capability_id": "c1d2"}


def test_capability_revoke_not_ok_raises():
    c = _client_with_transport(lambda req: httpx.Response(200, json={"ok": False}))
    with pytest.raises(ValueError):
        c.capability_revoke(capability="tok")


# ── streaming ────────────────────────────────────────────────────────


def test_stream_open_passes_envelope_and_parses_stream():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "decision": DECISION_OK,
                "enforcement": None,
                "stream": {"stream_id": "s-9", "status": "open"},
            },
        )

    c = _client_with_transport(handler)
    env = {"schema_version": "1.0", "purpose": "p"}
    out = c.stream_open(env)
    assert captured["body"] == {"envelope": env}
    assert out["stream"]["stream_id"] == "s-9"


def test_stream_open_blocked_has_null_stream():
    c = _client_with_transport(
        lambda req: httpx.Response(
            200,
            json={
                "decision": {"outcome": "BLOCKED", "ledgered": True},
                "enforcement": None,
                "stream": None,
            },
        )
    )
    assert c.stream_open({"purpose": "p"})["stream"] is None


def test_stream_open_malformed_stream_raises():
    c = _client_with_transport(
        lambda req: httpx.Response(
            200,
            json={
                "decision": DECISION_OK,
                "stream": {"status": "open"},
            },
        )
    )
    with pytest.raises(ValueError, match="stream_id"):
        c.stream_open({"purpose": "p"})


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"status": "ok"}, StreamStatus(status="ok", reason=None)),
        (
            {"status": "revoked", "reason": "duress_active"},
            StreamStatus(status="revoked", reason="duress_active"),
        ),
        ({"status": "closed"}, StreamStatus(status="closed", reason=None)),
    ],
)
def test_stream_heartbeat_statuses(body, expected):
    c = _client_with_transport(lambda req: httpx.Response(200, json=body))
    assert c.stream_heartbeat("s-9") == expected


def test_stream_heartbeat_malformed_raises():
    c = _client_with_transport(lambda req: httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="status"):
        c.stream_heartbeat("s-9")


def test_stream_close_ok_and_malformed():
    c = _client_with_transport(lambda req: httpx.Response(200, json={"ok": True}))
    assert c.stream_close("s-9") is True
    c = _client_with_transport(lambda req: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        c.stream_close("s-9")


# ── declared action (read / write) ─────────────────────────────────


def test_tool_call_action_sent_verbatim_only_when_given():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})

    c = _client_with_transport(handler)
    c.tool_call("t", "p", "o", destination="https://facts.example/c/1")
    assert "action" not in captured["body"]
    c.tool_call("t", "p", "o", destination="https://facts.example/c/1", action="read")
    assert captured["body"]["action"] == "read"
    c.tool_call("t", "p", "o", action=" Read ")
    assert captured["body"]["action"] == " Read "


def test_tool_allowed_passes_action_through():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})

    c = _client_with_transport(handler)
    assert c.tool_allowed("t", "p", "o", action="read") is True
    assert captured["body"]["action"] == "read"


def test_tool_call_returns_the_body_with_its_receipt():
    receipt = {"schema": "aegis-span-crypto.v0", "envelope_id": "e" * 64}
    body = {"decision": DECISION_OK, "enforcement": None, "boundary_receipt": receipt}
    c = _client_with_transport(lambda req: httpx.Response(200, json=body))
    out = c.tool_call("t", "p", "o")
    assert out["boundary_receipt"] == receipt


@pytest.mark.asyncio
async def test_atool_call_and_atool_allowed_send_action():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})

    c = AegisClient(base_url="https://localhost:8443/api/v1", verify_ssl=False)
    c._async_httpx = httpx.AsyncClient(
        base_url=c._base_url, transport=httpx.MockTransport(handler), timeout=10.0
    )
    await c.atool_call("t", "p", "o", action="write")
    assert captured["body"]["action"] == "write"
    assert await c.atool_allowed("t", "p", "o", action="read") is True
    assert captured["body"]["action"] == "read"
