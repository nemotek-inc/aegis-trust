# shield-proxy host registration (Claude Code / Cursor / codex / agy)

`pip install aegis-trust` installs the `aegis-mcp-proxy` command (equivalently
`python3 -m aegis_trust.mcp_proxy`). The proxy wraps any MCP server command:
replace the server command with
`aegis-mcp-proxy --policy <policy> --tool-rules <rules> --interface-pins <pins> --agent-id <host> -- <original command>`.
The host needs no other change; tool results arrive already minimized and every
call lands in the canonical audit stream (`enforcement_point=mcp_proxy`). This
is how an agent on the tool path sees only policy-permitted fields — host
unmodified, fail-closed on unknown tools. `--tool-rules` lists the arguments each
tool may receive (a tool with no rule is refused) and `--interface-pins` holds the
tool descriptions you approved (see Notes; `--interface-candidates` writes what the
server offered, for you to review).

## Claude Code (`.mcp.json` / `claude mcp add`)

```json
{
  "mcpServers": {
    "crm": {
      "command": "aegis-mcp-proxy",
      "args": [
        "--policy", "/etc/aegis/policy.json",
  "--tool-rules", "/etc/aegis/tool-rules.json",
  "--interface-pins", "/etc/aegis/interface-pins.json",
        "--tool-rules", "/etc/aegis/tool-rules.json",
        "--interface-pins", "/etc/aegis/interface-pins.json",
        "--agent-id", "claude-code",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

CLI equivalent:
`claude mcp add crm -- aegis-mcp-proxy --policy /etc/aegis/policy.json --tool-rules /etc/aegis/tool-rules.json --interface-pins /etc/aegis/interface-pins.json --agent-id claude-code -- node /opt/crm/mcp-server.js`

## Cursor (`.cursor/mcp.json`, same stdio shape)

```json
{
  "mcpServers": {
    "crm": {
      "command": "aegis-mcp-proxy",
      "args": [
        "--policy", "/etc/aegis/policy.json",
  "--tool-rules", "/etc/aegis/tool-rules.json",
  "--interface-pins", "/etc/aegis/interface-pins.json",
        "--tool-rules", "/etc/aegis/tool-rules.json",
        "--interface-pins", "/etc/aegis/interface-pins.json",
        "--agent-id", "cursor",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

## codex (`~/.codex/config.toml`)

```toml
[mcp_servers.crm]
command = "python3"
args = [
  "-m", "aegis_trust.mcp_proxy",
  "--policy", "/etc/aegis/policy.json",
  "--tool-rules", "/etc/aegis/tool-rules.json",
  "--interface-pins", "/etc/aegis/interface-pins.json",
  "--agent-id", "codex",
  "--", "node", "/opt/crm/mcp-server.js",
]
```

## agy (Antigravity MCP settings, same stdio shape)

```json
{
  "mcpServers": {
    "crm": {
      "command": "python3",
      "args": [
        "-m", "aegis_trust.mcp_proxy",
        "--policy", "/etc/aegis/policy.json",
  "--tool-rules", "/etc/aegis/tool-rules.json",
  "--interface-pins", "/etc/aegis/interface-pins.json",
        "--tool-rules", "/etc/aegis/tool-rules.json",
        "--interface-pins", "/etc/aegis/interface-pins.json",
        "--agent-id", "agy",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

## Notes

- `--agent-id` is the advisory `principal.agent_id` in audit events; pick one
  value per host so the stream is attributable.
- `--audit-path` (or `AEGIS_CANONICAL_AUDIT_PATH`) sets the event JSONL;
  default `~/.aegis/canonical_events.jsonl`.
- Same policy file works unchanged in the in-process SDK and (projected) in
  the gateway — that is the upgrade path.
- Gated data paths: `tools/call`, `resources/read`, `prompts/get`,
  `completion/complete`. The last three need an explicit purpose mapping in
  the policy's `tools` map (e.g. `"resources/read": "internal_docs"`) or they
  are blocked. Unmapped tools, JSON-RPC batches, task-augmented calls,
  `tasks/*`, and non-JSON server stdout are all rejected fail-closed.
- No server line is relayed as the server wrote it. Each relayed line is
  rebuilt from a projection fixed for its kind:
  - a gated result: `structuredContent`, a text that is JSON as a whole and an
    embedded resource's JSON text get the purpose's field rule. Everything
    else (free text, image/audio data, resource links, blobs, `_meta`, any
    other key) is *uninspected*;
  - an error reply to a gated call: `data` gets the field rule, the message is
    uninspected, and the code is kept only when it is a standard JSON-RPC code;
  - `initialize` and the listings: spec keys only. `tools/list` shows only the
    tools the policy maps; resource and prompt listings are empty unless
    `resources/read` / `prompts/get` is mapped. Cursors become proxy handles.
    Each entry is then relayed **only as the operator approved it**
    (`--interface-pins`, below);
  - a reply whose id matches no outstanding request (for example a second
    reply with the same id) is dropped;
  - server notifications: cancel, progress, `list_changed` and
    resources-updated are projected; server logs are uninspected; any other
    notification is dropped. A progress notification carries the proxy's own
    count (1, 2, ... per token), never the server's `progress` or `total`;
  - server requests: `ping` and `roots/list` are relayed under a proxy id.
    `sampling/createMessage`, `elicitation/create` and anything else are
    refused: the server gets JSON-RPC error -32601 and the host sees nothing.
- `--uninspected withhold` (the default) replaces an uninspected text with a
  fixed notice and removes the other uninspected carriers; the event says
  `access_reduced` and names each one as `<withheld:path>` in
  `blocked_fields`. `--uninspected pass` relays them; the event then never says
  `protected`: it carries `reason_code: unfiltered_passthrough` and
  `<unfiltered:path>` in `allowed_fields`. `protected` means every carrier was
  inspected and nothing was removed.
- The call's purpose comes from the policy's `tools` map. The host's model
  writes `arguments.purpose`, so a declared purpose that differs from the
  mapping is refused (`declared_purpose_refused`). `--allow-declared-purpose`
  restores the earlier rule (an explicit declaration wins); events then say
  `declared_purpose_override`.
- Interface metadata (tool, resource and prompt names, titles, descriptions
  and schemas, `serverInfo`, `instructions`) is server-written. It reaches the
  host only as the operator pinned it: `--interface-pins <file>` holds
  `{"version": 0, "initialize": {...}, "tools": {name: entry}, "prompts":
  {...}, "resources": {uri: entry}, "resourceTemplates": {...}}`, each value a
  projected entry. An entry the server's projected entry equals is relayed as
  pinned. Any other entry, and every entry when there is no pin file, is
  withheld: a tool is listed by its policy-known name with `inputSchema`
  `{"type": "object"}`, a prompt / resource / template is left out, and
  `initialize` gets `serverInfo` `{"name": "mcp-server", "version": "0"}` and no
  `instructions`; the event says `interface_unapproved` and names the entry (a
  tool by name, anything else by position). `--uninspected pass` relays an
  unpinned entry and names it `unfiltered`. `--interface-candidates <file>`
  (0600) receives the projected entries that were not relayed as pinned: review
  them and copy the approved ones into the pin file.
- A `tools/call`'s arguments (host→server) pass only by the tool's rule:
  `--tool-rules <file>` holds `{tool: {"access": "read" | "write",
  "arguments": {"allow": [path, ...]}}}` (the shape aegis-mcp-relay uses). Every
  argument leaf must be on the tool's `allow` list (a key containing `.` or
  arguments that are not an object are refused too): `argument_not_allowed`,
  with the refused argument names (never values) in `blocked_fields`. A tool
  with no rule, or a rule with no `allow`, is refused (`argument_rule_missing`).
  `--unchecked-arguments pass` forwards a call whose tool has no rule; the
  reply's event names `<unfiltered:arguments>` and never says `protected`.
  `query` and `fields` rules are judged by aegis-mcp-relay only; a rules file
  that has them is refused at start (`aegis.mcp_proxy.tool_rules_relay_only`).
- Named limits (stated, not closed): the presence and timing of lines are
  low-bandwidth channels a server can use on purpose; a relay cannot close
  them. A `prompts/get` or `completion/complete` argument reaches the server as
  the host wrote it (the call itself is gated by the `tools` map). Egress
  `destinations` policy is enforced by the SDK/gateway forms in v0.

## FULL mode on the proxy path (gateway-backed per-call gate)

By default the proxy is LITE: local canonical-policy filtering only, no
network. Setting `AEGIS_MODE=full` (or `auto` with FULL intent — `AEGIS_TOKEN`
or a non-dev `AEGIS_URL`) arms the gateway gate: the proxy consults the
gateway BEFORE forwarding every gated call, so a policy deny means the tool
NEVER runs (side effects prevented, not just output filtered), and a gateway
outage is a deny (`gateway_unavailable`), never a pass-through. Local
filtering still applies on the way back (defense in depth).

The gate primitive is explicit — never auto-probed:

| `--gate` / `AEGIS_MCP_GATE` | primitive | works against |
|---|---|---|
| `check-access` (default) | `@shield`-parity purpose gate (`POST /check-access`) | every live gateway today |
| `tool-call` | AI-native per-tool-call gate (`POST /tool-call`, role-keyed tool whitelist, chain-witnessed decision — `AI_NATIVE_V1_CONTRACT.md`) | boundaries serving the AI-native family |

Extra env/flags: `AEGIS_URL` + `AEGIS_TOKEN` (the gateway), `--owner` /
`AEGIS_OWNER` (principal.owner for the tool-call gate; defaults to
`--agent-id`). Audit reason codes added by the gate: `gateway_denied`,
`gateway_unavailable`.
