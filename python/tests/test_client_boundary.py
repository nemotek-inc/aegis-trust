"""Client tests for the /check-access scope contract fix (CSR-03) and the
Doctor v1 /check-boundary request/response plumbing.
"""

from __future__ import annotations

import json

import httpx
import pytest

from aegis_trust.client import AegisClient


def _client_with_transport(handler) -> AegisClient:
    c = AegisClient(base_url="https://localhost:8443/api/v1", verify_ssl=False)
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    return c


# ── /check-access scope contract (CSR-03 fix) ───────────────


def test_check_access_single_scope_sent_as_string():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", ["name"])
    assert captured["body"]["purpose"] == "p"
    # Single string, NOT an array — matches server Option<String>.
    assert captured["body"]["scope"] == "name"


def test_check_access_always_sends_required_tool_name():
    # The gateway's CheckAccessRequest requires a non-Option `tool_name`. Omit
    # it and the body is 422 → every FULL authorize fail-closes, so a FULL gate
    # can never grant against a live gateway (S015 live bug). Pin that the field
    # is always present with the default placeholder.
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", ["name"])
    assert captured["body"]["tool_name"] == "shielded_call"


def test_check_access_empty_scope_omits_field():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", [])
    assert "scope" not in captured["body"]


def test_authorize_multi_scope_fails_closed():
    # Review finding B: a >1-scope authorize must DENY without even sending a
    # request — dropping to purpose-level could let the single-scope server
    # ALLOW more than the caller asked for (fail-open regression).
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    assert c.authorize("p", ["name", "issue"]) is False
    # No request was issued at all.
    assert called["n"] == 0


def test_check_access_body_omits_scope_for_multi_scope():
    # The body builder still omits scope for >1 (defensive), but the gate path
    # never reaches it because authorize() denies first.
    body = AegisClient._check_access_body("p", ["name", "issue"])
    assert "scope" not in body
    assert body["purpose"] == "p"


# ── /check-boundary (Doctor v1) ─────────────────────────────


def test_check_boundary_posts_array_scope_and_snake_cases_fields():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": ["name"],
                "withheld_fields": [],
                "reason_code": "minimum_disclosure",
                "reason_label": "Minimum disclosure",
                "evidence_available": True,
                "evidence": None,
            },
        )

    c = _client_with_transport(handler)
    view = c.check_boundary(
        "p",
        ["name", "issue"],
        destination="external_llm",
        agent_id="agent-7",
        environment="prod",
        mode="full",
        schema_version=1,
    )
    assert captured["path"].endswith("/check-boundary")
    body = captured["body"]
    assert body["scope"] == ["name", "issue"]
    assert body["destination"] == "external_llm"
    assert body["agent_id"] == "agent-7"
    assert body["environment"] == "prod"
    assert body["mode"] == "full"
    assert body["schema_version"] == 1
    assert "principal" not in body
    # Usage-metering witness claims are opt-in — absent claims must leave
    # the body byte-identical to prior SDKs (no attribution/synthetic keys).
    assert "attribution" not in body
    assert "synthetic" not in body
    assert view.outcome == "PROTECTED"
    assert view.allowed_fields == ["name"]
    # destination_resource_id is opt-in too: absent -> no key (byte-identical body).
    assert "destination_resource_id" not in captured["body"]


def test_check_boundary_witness_claims_passed_verbatim():
    # Enforcement-neutral usage-metering witness claims. When set, the
    # top-level wire fields `attribution: {human, on_behalf_of[]}` and
    # `synthetic: bool` are carried verbatim (server-side consumer contract);
    # they are claims for the receipt chain, never authorization inputs.
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": ["name"],
                "withheld_fields": [],
                "reason_code": "minimum_disclosure",
                "reason_label": "Minimum disclosure",
                "evidence_available": True,
                "evidence": None,
            },
        )

    c = _client_with_transport(handler)
    c.check_boundary(
        "p",
        ["name"],
        attribution={"human": "u-1", "on_behalf_of": ["u-2", "u-3"]},
        synthetic=True,
    )
    body = captured["body"]
    assert body["attribution"] == {"human": "u-1", "on_behalf_of": ["u-2", "u-3"]}
    assert body["synthetic"] is True


def test_check_boundary_synthetic_false_is_an_explicit_claim():
    # `synthetic=False` is SET (an explicit "this is real traffic" claim) and
    # must be sent as false — distinct from omitting the claim entirely.
    body = AegisClient._check_boundary_body(
        "p", ["name"], origin="https://localhost:8443/api/v1", synthetic=False
    )
    assert body["synthetic"] is False
    assert "attribution" not in body


def test_check_boundary_body_omits_unset_witness_claims():
    # Body-builder pin: no claims -> no claim keys (byte-identical body).
    body = AegisClient._check_boundary_body(
        "p", ["name"], origin="https://localhost:8443/api/v1"
    )
    assert "attribution" not in body
    assert "synthetic" not in body


def test_check_boundary_body_destination_resource_id_is_top_level_and_verbatim():
    # A caller-declared label for the concrete resource behind `destination`.
    # Sent verbatim, top-level, and ONLY when set — the SDK does not validate
    # it and does not change its own result on it.
    body = AegisClient._check_boundary_body(
        "p",
        ["name"],
        origin="https://localhost:8443/api/v1",
        destination="system_of_record",
        destination_resource_id="res_123",
    )
    assert body["destination"] == "system_of_record"
    assert body["destination_resource_id"] == "res_123"


def test_check_boundary_body_omits_unset_destination_resource_id():
    # Byte-identical body when the label is not given (None == omitted).
    body = AegisClient._check_boundary_body(
        "p",
        ["name"],
        origin="https://localhost:8443/api/v1",
        destination="system_of_record",
    )
    assert "destination_resource_id" not in body
    body2 = AegisClient._check_boundary_body(
        "p",
        ["name"],
        origin="https://localhost:8443/api/v1",
        destination_resource_id=None,
    )
    assert "destination_resource_id" not in body2


def test_check_boundary_sends_destination_resource_id_on_the_wire():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": ["name"],
                "withheld_fields": [],
                "reason_code": "minimum_disclosure",
                "reason_label": "Minimum disclosure",
                "evidence_available": True,
                "evidence": None,
            },
        )

    c = _client_with_transport(handler)
    c.check_boundary(
        "p", ["name"], destination="system_of_record", destination_resource_id="res_123"
    )
    assert seen.get("destination_resource_id") == "res_123"


def test_check_boundary_raises_on_non_2xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="nope")

    c = _client_with_transport(handler)
    # S022 audit remediation: non-2xx raises the coded envelope (Node parity:
    # `if (!resp.ok) throw httpError("check-boundary", ...)`), not a raw
    # httpx.HTTPStatusError. Doctor still fail-closes via `except Exception`.
    from aegis_trust.errors import AegisHttpError

    with pytest.raises(AegisHttpError) as ei:
        c.check_boundary("p", ["name"])
    assert ei.value.code == "aegis.http.nonOk"
    assert ei.value.status == 503


def test_check_boundary_raises_on_malformed_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"source": "CORE"})  # no outcome

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_partial_body_with_outcome_only():
    # Finding A: a partial-but-valid-JSON body with only outcome present must
    # NOT parse to a trusted view (it would otherwise map PROTECTED -> ALLOW).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"outcome": "PROTECTED"})

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_source():
    # Finding A: source is a required field.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": [],
                "withheld_fields": [],
                "reason_code": "x",
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_reason_code():
    # Finding A: reason_code is a required field.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": [],
                "withheld_fields": [],
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_allowed_fields():
    # Finding A: allowed_fields is now REQUIRED (no default-to-empty).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "withheld_fields": [],
                "reason_code": "x",
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_normalize_base_url_completes_pathless():
    # S015 install friction (P-37): a pathless base URL must be completed to
    # /api/v1 (the gateway serves everything there); explicit paths are kept.
    import aegis_trust.client as cmod

    cmod._base_url_path_completed_warned = False
    assert (
        cmod.normalize_base_url("http://localhost:8443")
        == "http://localhost:8443/api/v1"
    )
    assert cmod.normalize_base_url("https://gw:8443/") == "https://gw:8443/api/v1"
    assert (
        cmod.normalize_base_url("http://localhost:8443/api/v1")
        == "http://localhost:8443/api/v1"
    )
    assert (
        cmod.normalize_base_url("http://localhost:8443/custom")
        == "http://localhost:8443/custom"
    )


def test_client_constructor_normalizes_base_url():
    import aegis_trust.client as cmod

    cmod._base_url_path_completed_warned = False
    c = cmod.AegisClient(base_url="http://localhost:8443")
    assert c._base_url == "http://localhost:8443/api/v1"


# ── declared action (read / write) + lossless response (raw, boundary_receipt) ──

_VIEW_BODY = {
    "source": "CORE",
    "outcome": "PROTECTED",
    "purpose_label": "p",
    "allowed_fields": ["name"],
    "withheld_fields": [],
    "reason_code": "minimum_disclosure",
    "reason_label": "Minimum disclosure",
    "evidence_available": True,
    "evidence": None,
}


def test_check_boundary_body_omits_unset_action():
    # No declaration -> no key: the body stays byte-identical to prior SDKs.
    body = AegisClient._check_boundary_body(
        "p",
        ["name"],
        origin="https://localhost:8443/api/v1",
        destination="https://x.example/a",
    )
    assert "action" not in body


@pytest.mark.parametrize("action", ["read", "write", " read ", "Read", ""])
def test_check_boundary_body_sends_action_verbatim(action):
    # Verbatim, top-level: the server compares byte for byte, so the SDK must
    # not trim or case-fold (a "fixed" value would be a different request than
    # the one the caller wrote).
    body = AegisClient._check_boundary_body(
        "p", ["name"], origin="https://localhost:8443/api/v1", action=action
    )
    assert body["action"] == action


def test_check_boundary_sends_action_on_the_wire():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=_VIEW_BODY)

    c = _client_with_transport(handler)
    c.check_boundary("p", [], destination="https://facts.example/c/1", action="read")
    assert seen["action"] == "read"
    assert seen["destination"] == "https://facts.example/c/1"


def test_check_boundary_view_keeps_the_whole_body_in_raw():
    # Keys the typed view does not surface must survive in `raw`: a Core that
    # issues a receipt signs a digest of this object, so dropping one would
    # make the decision unverifiable downstream.
    extra = {
        **_VIEW_BODY,
        "policy_generation": 7,
        "policy_digest": "sha256:abc",
        "response_policy": {"tone": "formal", "fields": ["name"]},
        "some_future_key": [1, {"nested": "ü\u0001"}],
        "boundary_receipt": {"schema": "aegis-span-crypto.v0", "envelope_id": "e" * 64},
    }

    c = _client_with_transport(lambda req: httpx.Response(200, json=extra))
    view = c.check_boundary("p", ["name"])
    assert view.raw == extra
    assert view.boundary_receipt == extra["boundary_receipt"]
    # A copy, not the transport's object: mutating it cannot change the view.
    view.raw["outcome"] = "BLOCKED"
    assert view.outcome == "PROTECTED"


def test_check_boundary_view_without_receipt():
    c = _client_with_transport(lambda req: httpx.Response(200, json=_VIEW_BODY))
    view = c.check_boundary("p", ["name"])
    assert view.boundary_receipt is None
    assert view.raw == _VIEW_BODY


def test_check_boundary_view_null_receipt_is_none():
    # A configured server that could not commit a receipt answers
    # `boundary_receipt: null` + `boundary_receipt_error`; the view carries
    # no receipt and `raw` keeps the reason.
    body = {
        **_VIEW_BODY,
        "boundary_receipt": None,
        "boundary_receipt_error": "commitment_unavailable",
    }
    c = _client_with_transport(lambda req: httpx.Response(200, json=body))
    view = c.check_boundary("p", ["name"])
    assert view.boundary_receipt is None
    assert view.raw["boundary_receipt_error"] == "commitment_unavailable"


def test_check_boundary_views_compare_on_typed_fields_only():
    a = AegisClient._parse_boundary_view({**_VIEW_BODY, "x": 1})
    b = AegisClient._parse_boundary_view({**_VIEW_BODY, "x": 2})
    # `raw` is excluded from ==: two views of the same decision compare equal
    # whatever extra keys the server sent.
    assert a == b
