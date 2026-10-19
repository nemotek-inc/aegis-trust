"""shield-proxy end-to-end tests: real subprocess, real stdio framing.

A fake MCP server returns an over-broad customer record in the result forms an
MCP server can use; the proxy must deliver only the policy's scope to the
"host" (this test), withhold what it cannot inspect, block unknown tools without
forwarding them, refuse server-to-host requests, and emit schema-valid canonical
v0 events. Line-level classification is covered case by case by the shared
corpus (test_mcp_relay_corpus.py); this file proves the stdio pumps carry it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "schemas" / "v0"

FAKE_SERVER = """
import json, sys
log = open(sys.argv[1], "a") if len(sys.argv) > 1 else None
record = {"name": "ACME", "company": "ACME Inc",
          "email": "ceo@acme.test", "ssn": "123-45-6789"}
def send(msg):
    sys.stdout.write(json.dumps(msg) + "\\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if log:
        log.write(line + "\\n")
        log.flush()
    if "id" not in msg or "method" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name == "query_business_data":
            result = {"structuredContent": record,
                      "content": [{"type": "text", "text": json.dumps(record)},
                                  {"type": "text", "text": "plain note ssn=123-45-6789"}]}
        elif name == "query_resource":
            result = {"content": [{"type": "resource", "resource": {
                "uri": "crm://customers/1", "mimeType": "application/json",
                "text": json.dumps(record)}}]}
        elif name == "query_error":
            send({"jsonrpc": "2.0", "id": msg["id"], "error": {
                "code": -32000, "message": "failed for ssn=123-45-6789", "data": record}})
            continue
        elif name == "query_with_sampling":
            send({"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage",
                  "params": {"messages": [{"role": "user", "content": {
                      "type": "text", "text": "ssn=123-45-6789"}}]}})
            send({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "info", "data": record}})
            result = {"structuredContent": record}
        else:
            result = {"structuredContent": record}
    elif method == "resources/read":
        result = {"contents": [{"uri": msg["params"]["uri"], "text": json.dumps(record)}]}
    elif method == "leak/banner":
        sys.stdout.write("RAW BANNER ssn=123-45-6789\\n")
        sys.stdout.flush()
        result = {"ok": True}
    else:
        result = {"ok": True}
    send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
"""

POLICY = {
    "policy_schema_version": 0,
    "policy_id": "proxy-test-policy",
    "purposes": {
        "customer_data": {"scope": ["name", "company"]},
        "everything": {"deny_fields": ["ssn"]},
    },
    "tools": {
        "query_business_data": "customer_data",
        "query_resource": "customer_data",
        "query_error": "customer_data",
        "query_with_sampling": "customer_data",
        "resources/read": "customer_data",
    },
    "defaults": {"unknown_tool": "block"},
}
SECRETS = ("ceo@acme.test", "123-45-6789")


def _start(tmp_path: Path, *extra: str) -> tuple[subprocess.Popen, Path, Path]:
    server_py = tmp_path / "fake_server.py"
    server_py.write_text(FAKE_SERVER)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(POLICY))
    audit_path = tmp_path / "events.jsonl"
    server_log = tmp_path / "server_saw.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(policy_path),
            "--agent-id",
            "claude-code-test",
            "--audit-path",
            str(audit_path),
            *extra,
            "--",
            sys.executable,
            str(server_py),
            str(server_log),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc, audit_path, server_log


@pytest.fixture()
def proxy(tmp_path: Path):
    proc, audit_path, server_log = _start(tmp_path)
    yield proc, audit_path, server_log
    proc.stdin.close()
    proc.wait(timeout=10)


def rpc(proc: subprocess.Popen, msg: dict | list) -> dict:
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def call(
    proc: subprocess.Popen, msg_id: int, tool: str, arguments: dict | None = None
) -> dict:
    return rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}},
        },
    )


def _events(audit_path: Path) -> list[dict]:
    lines = [json.loads(raw) for raw in audit_path.read_text().splitlines()]
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMA_DIR / "aegis-audit-event.v0.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    for event in lines:
        validator.validate(event)
        assert not any(s in json.dumps(event) for s in SECRETS)  # names only
    return lines


def _seen(server_log: Path) -> list[dict]:
    return [json.loads(raw) for raw in server_log.read_text().splitlines()]


def test_proxy_filters_known_tool_and_blocks_unknown(proxy) -> None:
    proc, audit_path, server_log = proxy

    init = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["protocolVersion"] == "2025-06-18"

    # mapped tool: structuredContent and JSON text minimized; free text withheld
    resp = call(proc, 2, "query_business_data")
    assert resp["result"]["structuredContent"] == {
        "name": "ACME",
        "company": "ACME Inc",
    }
    assert set(json.loads(resp["result"]["content"][0]["text"])) == {"name", "company"}
    assert resp["result"]["content"][1]["text"].startswith("[Aegis: withheld")
    assert not any(s in json.dumps(resp) for s in SECRETS)

    # unknown tool: blocked AND never forwarded to the server
    blocked = call(proc, 3, "exfiltrate_everything")
    assert blocked["result"]["isError"] is True
    assert "unknown_tool" in blocked["result"]["content"][0]["text"]

    # a declared purpose broader than the mapping: refused, never forwarded
    refused = call(proc, 4, "query_business_data", {"purpose": "everything"})
    assert "declared_purpose_refused" in refused["result"]["content"][0]["text"]

    rpc(
        proc, {"jsonrpc": "2.0", "id": 5, "method": "ping"}
    )  # barrier: server has logged
    names = [
        m["params"]["name"]
        for m in _seen(server_log)
        if m.get("method") == "tools/call"
    ]
    assert names == ["query_business_data"]

    events = _events(audit_path)
    allow = [e for e in events if e["decision"] == "allow"]
    assert allow[0]["enforcement_point"] == "mcp_proxy"
    assert allow[0]["outcome"] == "access_reduced"
    assert sorted(allow[0]["blocked_fields"]) == [
        "<withheld:content[1].text>",
        "email",
        "ssn",
    ]
    assert allow[0]["principal"]["agent_id"] == "claude-code-test"
    reasons = [e["reason_code"] for e in events if e["decision"] == "deny"]
    assert reasons == ["unknown_tool", "declared_purpose_refused"]


def test_proxy_b5_forms_reach_the_host_without_values(proxy) -> None:
    proc, audit_path, _ = proxy
    rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    resource = call(proc, 2, "query_resource")
    inner = resource["result"]["content"][0]["resource"]
    assert json.loads(inner["text"]) == {"name": "ACME", "company": "ACME Inc"}

    error = call(proc, 3, "query_error")
    assert error["error"] == {
        "code": -32603,
        "message": "upstream error (withheld by Aegis)",
        "data": {"name": "ACME", "company": "ACME Inc"},
    }

    for reply in (resource, error):
        assert not any(s in json.dumps(reply) for s in SECRETS)
    events = _events(audit_path)
    assert [e["outcome"] for e in events] == ["access_reduced", "access_reduced"]
    assert "protected" not in [e.get("outcome") for e in events]


def test_proxy_refuses_server_requests_over_stdio(proxy) -> None:
    proc, audit_path, server_log = proxy
    rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    # the server sends sampling/createMessage and a log before its result: the
    # host sees only the filtered result; the server is told -32601
    resp = call(proc, 2, "query_with_sampling")
    assert resp["id"] == 2
    assert resp["result"]["structuredContent"] == {
        "name": "ACME",
        "company": "ACME Inc",
    }

    rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "ping"})  # barrier
    refusals = [m for m in _seen(server_log) if m.get("id") == "srv-1"]
    assert refusals and refusals[0]["error"]["code"] == -32601

    reasons = [e.get("reason_code") for e in _events(audit_path)]
    assert "server_request_refused" in reasons
    assert "server_log_withheld" in reasons


def test_proxy_gates_sibling_paths_and_rejects_protocol_abuse(proxy) -> None:
    proc, audit_path, server_log = proxy

    # resources/read is a data path on the same boundary: mapped => filtered
    resp = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/read",
            "params": {"uri": "crm://customers/1"},
        },
    )
    assert resp["result"]["contents"][0]["uri"] == "crm://customers/1"
    assert set(json.loads(resp["result"]["contents"][0]["text"])) == {"name", "company"}

    # prompts/get is NOT mapped in the policy => blocked, never forwarded
    blocked = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "prompts/get",
            "params": {"name": "system-prompt"},
        },
    )
    assert blocked["result"]["isError"] is True
    assert "unknown_tool" in blocked["result"]["content"][0]["text"]

    # JSON-RPC batch => rejected outright (would bypass per-id filtering)
    batch_reply = rpc(
        proc,
        [
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "query_business_data", "arguments": {}},
            }
        ],
    )
    assert batch_reply["result"]["isError"] is True
    assert "batch_rejected" in batch_reply["result"]["content"][0]["text"]

    # non-JSON server stdout (raw banner with secrets) is dropped, and the reply
    # to a method the proxy has no projection for is withheld
    banner_resp = rpc(
        proc, {"jsonrpc": "2.0", "id": 13, "method": "leak/banner", "params": {}}
    )
    assert banner_resp["id"] == 13 and banner_resp["error"]["code"] == -32603

    rpc(proc, {"jsonrpc": "2.0", "id": 14, "method": "ping"})  # barrier
    seen_dump = json.dumps(_seen(server_log))
    assert "prompts/get" not in seen_dump
    assert seen_dump.count("query_business_data") == 0  # the batch was never forwarded
    _events(audit_path)


def test_proxy_uninspected_pass_names_what_it_relays(tmp_path: Path) -> None:
    proc, audit_path, _ = _start(tmp_path, "--uninspected", "pass")
    try:
        rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        resp = call(proc, 2, "query_business_data")
        assert resp["result"]["content"][1]["text"] == "plain note ssn=123-45-6789"
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    event = [
        e
        for e in (json.loads(r) for r in audit_path.read_text().splitlines())
        if e["decision"] == "allow"
    ][0]
    assert event["outcome"] == "access_reduced"
    assert event["reason_code"] == "unfiltered_passthrough"
    assert event["allowed_fields"] == ["<unfiltered:content[1].text>"]


def test_proxy_refuses_malformed_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"policy_schema_version": 0, "purposes": {"p": {"deny_fields": []}}})
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(bad),
            "--",
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0  # fail-closed at startup, server never proxied
