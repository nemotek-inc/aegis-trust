"""The agent on the tool path: aegis-mcp-proxy minimizes tool output before the model sees it.

The primary target is the coding agent itself (Claude Code, Cursor, codex, agy,
any MCP host). You do not change the agent or the MCP server — you point the
agent's MCP config at `aegis-mcp-proxy` instead of the raw server:

    host  <--stdio-->  aegis-mcp-proxy --policy p.json --tool-rules r.json  <--stdio-->  real MCP server

Every tools/call *result* is filtered to the policy's scope before it can enter
the agent's model context, logs, or downstream tool calls — server unmodified,
fail-closed on tools the policy does not map.

This script plays the "host". It runs the SAME tool call twice — once straight
against the server, once through the proxy — and prints what the agent receives
each time. No API key, no network, no Aegis Core.

    pip install aegis-trust
    python examples/mcp_proxy_demo.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# A stand-in MCP server. Its tool returns an over-broad customer record — the
# kind of tool output that, unfiltered, lands whole in your agent's context.
FAKE_SERVER = r"""
import json, sys
RECORD = {"name": "ACME", "company": "ACME Inc",
          "email": "ceo@acme.test", "ssn": "123-45-6789",
          "card_number": "4242-4242-4242-4242"}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg.get("method") == "tools/call":
        result = {"structuredContent": RECORD,
                  "content": [{"type": "text", "text": json.dumps(RECORD)}]}
    else:
        result = {"ok": True}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""

# The policy: for this tool, the agent's purpose only needs name + company.
POLICY = {
    "policy_schema_version": 0,
    "policy_id": "demo",
    "purposes": {"customer_data": {"scope": ["name", "company"]}},
    "tools": {"query_business_data": "customer_data"},
    "defaults": {"unknown_tool": "block"},
}

# The argument rule: this read tool takes no arguments the operator did not list.
RULES = {"query_business_data": {"access": "read", "arguments": {"allow": ["customer_id"]}}}

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "query_business_data", "arguments": {}},
}
BAD_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "exfiltrate_everything", "arguments": {}},
}


def rpc(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        server = d / "server.py"
        server.write_text(FAKE_SERVER)
        policy = d / "policy.json"
        policy.write_text(json.dumps(POLICY))
        rules = d / "rules.json"
        rules.write_text(json.dumps(RULES))
        audit = d / "events.jsonl"

        # 1) WITHOUT the proxy: the agent talks straight to the server.
        raw = subprocess.Popen(
            [sys.executable, str(server)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        got = rpc(raw, CALL)["result"]["structuredContent"]
        raw.stdin.close()
        raw.wait(timeout=10)
        print("WITHOUT proxy — what the agent's model receives:")
        print("  ", got)
        print("   -> ssn/card in agent context:", "ssn" in got or "card_number" in got)

        # 2) WITH aegis-mcp-proxy on the path (server unmodified).
        proxy = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "aegis_trust.mcp_proxy",
                "--policy",
                str(policy),
                "--tool-rules",
                str(rules),
                "--agent-id",
                "demo-host",
                "--audit-path",
                str(audit),
                "--",
                sys.executable,
                str(server),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        through = rpc(proxy, CALL)["result"]["structuredContent"]
        blocked = rpc(proxy, BAD_CALL)["result"]
        proxy.stdin.close()
        proxy.wait(timeout=10)

        print("\nWITH aegis-mcp-proxy — what the agent's model receives:")
        print("  ", through)
        print(
            "   -> ssn/card in agent context:",
            "ssn" in through or "card_number" in through,
            "(stripped at the process boundary)",
        )

        print("\nA tool the policy does not allow never even runs:")
        print(
            "   exfiltrate_everything ->",
            "BLOCKED" if blocked.get("isError") else "forwarded",
            "-",
            blocked["content"][0]["text"],
        )

        # The boundary leaves an audit trail (enforcement_point=mcp_proxy).
        events = [json.loads(x) for x in audit.read_text().splitlines() if x.strip()]
        kinds = [
            (e.get("enforcement_point"), e.get("decision") or e.get("outcome"))
            for e in events
        ]
        print("\nCanonical audit events emitted:", kinds)

    print(
        "\nTakeaway: the agent is on the tool path through the proxy. It cannot "
        "see fields outside the declared scope, and cannot call a tool the "
        "policy does not map — one line of MCP config, server unmodified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
