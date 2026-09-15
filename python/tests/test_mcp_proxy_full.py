"""shield-proxy FULL-mode gate: real subprocess + real stub gateway over HTTP.

The proxy consults the gateway BEFORE forwarding a gated call (the third PEP
grows teeth): a policy deny means the tool NEVER runs — verified via the fake
server's seen-calls probe — and a gateway outage is a deny, never a
pass-through. Both gate kinds are exercised: `check-access` (@shield-parity,
works on every live gateway) and `tool-call` (AI-native per-tool-call gate,
AI_NATIVE_V1_CONTRACT.md).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_mcp_proxy import FAKE_SERVER, POLICY  # noqa: E402

DECISION_OK = {"outcome": "PROTECTED", "ledgered": True, "decision_id": "d-1"}
DECISION_BLOCKED = {"outcome": "BLOCKED", "ledgered": True, "decision_id": "d-2"}


class _StubGateway(BaseHTTPRequestHandler):
    """Canned aegis gateway: /check-access allows every purpose except
    'denied_purpose'; /tool-call passes only 'query_business_data'."""

    def log_message(self, *args):  # noqa: D102 — silence test noise
        pass

    def do_GET(self):  # /health
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.calls.append((self.path, body))  # type: ignore[attr-defined]
        if self.path.endswith("/check-access"):
            allowed = body.get("purpose") != "denied_purpose"
            payload = {"allowed": allowed}
        elif self.path.endswith("/tool-call"):
            ok = body.get("tool") == "query_business_data"
            payload = {
                "decision": DECISION_OK if ok else DECISION_BLOCKED,
                "enforcement": None,
            }
        else:
            payload = {}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def gateway():
    srv = HTTPServer(("127.0.0.1", 0), _StubGateway)
    srv.calls = []  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _clean_env(**extra: str) -> dict[str, str]:
    """AEGIS の設定を一切持たない子プロセス環境。

    剥がしたいのは **製品の ambient 設定** であって、interpreter が起動できる
    かどうかではない。2026-09-15 に専用 CI host へ移して分かったこと: 環境を
    丸ごと置き換えると、`actions/setup-python` が入れた可搬 build の python は

        error while loading shared libraries: libpython3.10.so.1.0

    で起動すらしない。共有 runner ではたまたま起動できていただけで、この test は
    **その 1 種類の機械でしか成立しない形**になっていた。loader が要るものだけ
    通し、AEGIS_* は通さない。
    """
    env = {"PATH": "/usr/bin:/bin"}
    for key in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "PYTHONHOME"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env.update(extra)
    return env


def _spawn(tmp_path: Path, gateway_url: str, gate: str, policy: dict | None = None):
    server_py = tmp_path / "fake_server.py"
    server_py.write_text(FAKE_SERVER)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy or POLICY))
    audit_path = tmp_path / "events.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(policy_path),
            "--agent-id",
            "full-gate-test",
            "--audit-path",
            str(audit_path),
            "--gate",
            gate,
            "--",
            sys.executable,
            str(server_py),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_clean_env(
            AEGIS_MODE="full",
            AEGIS_URL=gateway_url,
            AEGIS_TOKEN="test-token",
        ),
    )
    return proc, audit_path


def _rpc(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def _tool_call(proc, msg_id, name):
    return _rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        },
    )


def _seen_calls(proc):
    return _rpc(
        proc, {"jsonrpc": "2.0", "id": 99, "method": "tools/seen", "params": {}}
    )["result"]["calls"]


def test_check_access_gate_allows_then_filters(gateway, tmp_path):
    proc, _ = _spawn(
        tmp_path, f"http://127.0.0.1:{gateway.server_port}", "check-access"
    )
    try:
        resp = _tool_call(proc, 1, "query_business_data")
        # allowed by the gateway AND still minimized locally (defense in depth)
        assert resp["result"]["structuredContent"] == {
            "name": "ACME",
            "company": "ACME Inc",
        }
        # the gate consulted /check-access once per scope entry (finding B:
        # one scope per call)
        paths = [p for p, _ in gateway.calls if p.endswith("/check-access")]
        assert len(paths) == len(POLICY["purposes"]["customer_data"]["scope"])
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


def test_check_access_gate_denies_and_tool_never_runs(gateway, tmp_path):
    policy = json.loads(json.dumps(POLICY))
    policy["purposes"]["denied_purpose"] = {"scope": []}
    policy["tools"]["blocked_tool"] = "denied_purpose"
    proc, audit_path = _spawn(
        tmp_path, f"http://127.0.0.1:{gateway.server_port}", "check-access", policy
    )
    try:
        resp = _tool_call(proc, 1, "blocked_tool")
        assert resp["result"]["isError"] is True
        assert "gateway_denied" in resp["result"]["content"][0]["text"]
        # the fake server never saw the blocked tool (pre-call gate)
        assert "blocked_tool" not in _seen_calls(proc)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(ev.get("reason_code") == "gateway_denied" for ev in events)


def test_gateway_outage_is_a_deny_not_a_passthrough(tmp_path):
    # No gateway listening on this port: the gate must fail closed.
    proc, audit_path = _spawn(tmp_path, "http://127.0.0.1:1", "check-access")
    try:
        resp = _tool_call(proc, 1, "query_business_data")
        assert resp["result"]["isError"] is True
        assert "gateway_unavailable" in resp["result"]["content"][0]["text"]
        assert "query_business_data" not in _seen_calls(proc)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(ev.get("reason_code") == "gateway_unavailable" for ev in events)


def test_tool_call_gate_uses_ai_native_endpoint(gateway, tmp_path):
    policy = json.loads(json.dumps(POLICY))
    policy["tools"]["other_tool"] = "customer_data"
    proc, _ = _spawn(
        tmp_path, f"http://127.0.0.1:{gateway.server_port}", "tool-call", policy
    )
    try:
        ok = _tool_call(proc, 1, "query_business_data")
        assert ok["result"]["structuredContent"] == {
            "name": "ACME",
            "company": "ACME Inc",
        }
        denied = _tool_call(proc, 2, "other_tool")
        assert denied["result"]["isError"] is True
        assert "gateway_denied" in denied["result"]["content"][0]["text"]
        assert "other_tool" not in _seen_calls(proc)
        # the AI-native endpoint carried the tool + purpose + owner + fields
        tc = [b for p, b in gateway.calls if p.endswith("/tool-call")]
        assert tc and tc[0]["tool"] == "query_business_data"
        assert tc[0]["purpose"] == "customer_data"
        assert tc[0]["owner"] == "full-gate-test"
        assert tc[0]["fields"] == ["name", "company"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


def test_lite_mode_unchanged_no_gateway_calls(gateway, tmp_path):
    """AEGIS_MODE unset keeps today's LITE proxy: no gateway traffic at all."""
    server_py = tmp_path / "fake_server.py"
    server_py.write_text(FAKE_SERVER)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(POLICY))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(policy_path),
            "--",
            sys.executable,
            str(server_py),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_clean_env(),
    )
    try:
        resp = _tool_call(proc, 1, "query_business_data")
        assert resp["result"]["structuredContent"] == {
            "name": "ACME",
            "company": "ACME Inc",
        }
        assert not [p for p, _ in gateway.calls]
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
