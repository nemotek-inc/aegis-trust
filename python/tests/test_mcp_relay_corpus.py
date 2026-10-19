"""MCP relay conformance — Python runner.

Feeds each case of the shared corpus (`conformance/mcp_relay.v0.json`), line by
line, to the shipped `ShieldProxy` and asserts the lines it sends each side and
the events it writes. The Node SDK runs the SAME corpus
(node/tests/mcpRelayCorpus.test.ts), so both classify a server->host line the
same way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegis_trust.canonical import (
    ENFORCEMENT_MCP_PROXY,
    CanonicalEmitter,
    load_canonical_policy,
)
from aegis_trust.mcp_proxy import ShieldProxy

CORPUS = Path(__file__).resolve().parents[2] / "conformance" / "mcp_relay.v0.json"
DOC = json.loads(CORPUS.read_text())
CASES = DOC["cases"]
EVENT_KEYS = (
    "purpose",
    "operation",
    "decision",
    "outcome",
    "reason_code",
    "blocked_fields",
    "allowed_fields",
)


def test_corpus_is_present_and_nonempty() -> None:
    assert DOC["version"] == 0
    assert CASES, "shared MCP relay corpus must define cases"


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
    return None


def _match(expected: Any, actual: Any, handles: dict[str, str], where: str) -> None:
    if isinstance(expected, str) and expected.startswith("$H:"):
        assert isinstance(actual, str) and actual.startswith("aegis-"), (
            f"{where}: want a proxy handle, got {actual!r}"
        )
        bound = handles.setdefault(expected, actual)
        assert bound == actual, (
            f"{where}: handle {expected} was {bound!r}, now {actual!r}"
        )
        return
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{where}: want object, got {actual!r}"
        assert sorted(expected) == sorted(actual), (
            f"{where}: keys {sorted(actual)} != {sorted(expected)}"
        )
        for key in expected:
            _match(expected[key], actual[key], handles, f"{where}.{key}")
        return
    if isinstance(expected, list):
        assert isinstance(actual, list) and len(actual) == len(expected), (
            f"{where}: want {expected!r}, got {actual!r}"
        )
        for i, (e, a) in enumerate(zip(expected, actual)):
            _match(e, a, handles, f"{where}[{i}]")
        return
    if (
        isinstance(expected, str)
        and _as_json(expected) is not None
        and _as_json(actual) is not None
    ):
        _match(_as_json(expected), _as_json(actual), handles, f"{where}(json)")
        return
    assert type(expected) is type(actual) and expected == actual, (
        f"{where}: want {expected!r}, got {actual!r}"
    )


def _substitute(value: Any, handles: dict[str, str]) -> Any:
    if isinstance(value, str) and value.startswith("$H:"):
        return handles[value]
    if isinstance(value, dict):
        return {k: _substitute(v, handles) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, handles) for v in value]
    return value


def _lines(raw: bytes | None) -> list[Any]:
    if not raw:
        return []
    return [json.loads(part) for part in raw.decode().splitlines() if part.strip()]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_mcp_relay_case(case: dict, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(DOC["policies"][case["policy"]]))
    events_path = tmp_path / "events.jsonl"
    policy = load_canonical_policy(policy_path)
    emitter = CanonicalEmitter(
        ENFORCEMENT_MCP_PROXY, "corpus", path=events_path, policy_id=policy.policy_id
    )
    flags = case.get("flags", {})
    proxy = ShieldProxy(
        policy,
        emitter,
        agent_id="corpus-host",
        uninspected=flags.get("uninspected", "withhold"),
        allow_declared_purpose=flags.get("allow_declared_purpose", False),
    )
    handles: dict[str, str] = {}
    host_bound: list[str] = []
    for n, step in enumerate(case["steps"]):
        where = f"{case['id']} step {n} ({step['from']})"
        msg = _substitute(step["msg"], handles)
        if step["from"] == "host":
            forward, reply = proxy.handle_client_line(json.dumps(msg).encode())
            to_server, to_host = _lines(forward), _lines(reply)
        else:
            to_host = _lines(proxy.handle_server_line(json.dumps(msg).encode()))
            to_server = [json.loads(b) for b in proxy.drain_to_server()]
        _match(step["expect_host"], to_host, handles, f"{where} host")
        _match(step["expect_server"], to_server, handles, f"{where} server")
        host_bound.extend(json.dumps(m, ensure_ascii=False) for m in to_host)

    allowed = case.get("host_may_contain", [])
    for line in host_bound:
        rest = line
        for ok in allowed:
            rest = rest.replace(ok, "")
        assert "LEAK-" not in rest, (
            f"{case['id']}: an excluded value reached the host: {line}"
        )

    events = (
        [json.loads(raw) for raw in events_path.read_text().splitlines()]
        if events_path.exists()
        else []
    )
    assert len(events) == len(case["expect_events"]), f"{case['id']}: events {events}"
    for i, (want, got) in enumerate(zip(case["expect_events"], events)):
        for key in EVENT_KEYS:
            if want.get(key) is None:
                assert key not in got, (
                    f"{case['id']} event {i}: {key} should be absent, got {got.get(key)!r}"
                )
            elif key in ("blocked_fields", "allowed_fields"):
                assert sorted(got.get(key) or []) == want[key], (
                    f"{case['id']} event {i}: {key} {got.get(key)}"
                )
            else:
                assert got.get(key) == want[key], (
                    f"{case['id']} event {i}: {key} {got.get(key)!r} != {want[key]!r}"
                )
        assert "LEAK-" not in json.dumps(got), f"{case['id']} event {i} carries a value"
