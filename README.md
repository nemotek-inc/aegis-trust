# aegis-trust

**The trust layer for AI agents.** Put it on your agent's tool path (MCP proxy) or wrap a data accessor in-process (SDK) — declare *purpose* + *scope*, and only the data that purpose allows reaches the agent. Local-first, fail-closed.

- **Python**: [`pip install aegis-trust`](https://pypi.org/project/aegis-trust/) — `0.10.2` — source in [`python/`](python/)
- **TypeScript / Node**: [`npm install aegis-trust`](https://www.npmjs.com/package/aegis-trust) — `0.10.2` — source in [`node/`](node/)

## Put aegis-trust on your agent's tool path (Claude Code / Cursor / any MCP host)

Point your MCP host at `aegis-mcp-proxy` instead of the raw server — **no change
to the agent or the server.** Every tool result is minimized to your policy
before it can enter the model's context, logs, or downstream tool calls; tools
the policy does not map are blocked fail-closed; every call lands in a canonical
audit stream.

```json
// .mcp.json — wrap any MCP server with the proxy
{
  "mcpServers": {
    "crm": {
      "command": "aegis-mcp-proxy",
      "args": ["--policy", "policy.json", "--agent-id", "claude-code",
               "--", "node", "/opt/crm/mcp-server.js"]
    }
  }
}
```

See it in 30 seconds — the same tool call, with and without the proxy on the path:

```bash
pip install aegis-trust
python python/examples/mcp_proxy_demo.py
# WITHOUT proxy: {name, company, email, ssn, card_number}   ← secrets in the agent's context
# WITH proxy:    {name, company}                            ← stripped at the process boundary
# unmapped tool: BLOCKED (fail-closed) — never even runs
```

Host registration for Cursor / codex / agy: [`schemas/v0/mcp-hosts.md`](schemas/v0/mcp-hosts.md).

## Or shield a data accessor in-process (SDK)

Both snippets are **self-contained and run as written** (LITE mode, no gateway, no token):

```python
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    # your real DB/API call goes here; this literal stands in for a 30-field row
    return {"name": "Tanaka Taro", "issue": "Login problem",
            "email": "t@example.com", "ssn": "123-45-6789"}

print(get_customer(1))
# → {'name': 'Tanaka Taro', 'issue': 'Login problem'} — email/ssn stripped before the agent sees it
```

```typescript
import { shield } from "aegis-trust";

const getCustomer = shield({ purpose: "customer_support", scope: ["name", "issue"] })(
  (_id: string) => ({
    name: "Tanaka Taro", issue: "Login problem",
    email: "t@example.com", ssn: "123-45-6789", // your real fetch goes here
  }),
);

console.log(getCustomer("C-001"));
// → { name: "Tanaka Taro", issue: "Login problem" } — email/ssn stripped before the agent sees it
```

`wrap()` reports what was filtered; [`python/examples/llm_context_leak.py`](python/examples/llm_context_leak.py)
shows why a hand-rolled 5-line allowlist leaks on nested data and this does not.

## What this is — and what it is not

The proxy and the SDK run **in your own infrastructure** and minimize what an
agent receives. That is a **data-minimization / blast-radius layer for agents
you operate** — not a sandbox against a hostile in-process attacker (in-process
code can always bypass an in-process filter; LITE never claims otherwise). The
threat it removes is the common one: sensitive fields *accidentally* riding into
the model, its logs, and downstream tool calls.

Enforcement against an **untrusted** caller — cryptographic identity, a real
trust boundary, tamper-evident audit — is **FULL mode** (the aegis-core
gateway). The same `purpose`/`scope` policy drives all three forms (proxy, SDK,
gateway): you raise the enforcement strength **without rewriting policy**. The
claim ceiling and never-claims live in
[`docs/productization/LITE_CLAIMS.md`](docs/productization/LITE_CLAIMS.md).

## For AI agents

Machine-readable product surface, generated from live registry facts (never
hand-edited; a CI guard rejects any drift from the generated content):

- Manifest: <https://aegisagentcontrol.com/aegis.json>
- Site guide: <https://aegisagentcontrol.com/llms.txt>
- Quickstart with expected output: <https://aegisagentcontrol.com/quickstart>

Package-level guides: [`python/llms.txt`](python/llms.txt) · [`node/llms.txt`](node/llms.txt).

## Release & supply chain

> **Release `0.10.2`** — published to both npm (`npm install aegis-trust`) and
> PyPI (`pip install aegis-trust`); the two SDKs are version-locked at the same
> number. This is a **pre-1.0 (0.x) release**: the public API may still change
> before v1.0 — see [Alpha limitations](#alpha-limitations-read-before-adopting)
> for what does not work yet. Release artifacts (npm tarball, Python wheel +
> sdist) are cosign-signed (keyless Sigstore, Rekor public log), carry npm
> provenance + PyPI PEP 740 attestations, and are attached to the GitHub Release
> `v0.10.2`. The prior `0.9.0-rc3` (withdrawn: the published artifact did not
> match this repo's source) remains npm-deprecated and version-scoped.
>
> **0.10.1 / 0.10.2 note.** The repository moved to the `nemotek-inc`
> organization on 2026-09-01. `0.10.1` reached PyPI only, uploaded with a
> maintainer API token from the cosign-signed artifacts (Sigstore signatures
> and SBOMs unchanged) **without PEP 740 attestations**, and never reached npm:
> the package metadata still named the previous owner, which the npm registry
> rejects against the build provenance. `0.10.2` is `0.10.1` with the package
> URLs corrected and is published on both registries on the token-free,
> attested path (npm provenance + PEP 740) after both Trusted Publisher
> bindings were re-registered under `nemotek-inc` on 2026-09-05. Releases now
> start from a version-bump merge to `main` (see [RELEASING.md](RELEASING.md)).

## Status

- **Python**: `aegis-trust==0.10.2` on PyPI — `pip install aegis-trust`. v1.0.0 GA pending 5-oracle readability review + verifier coverage uplift.
- **TypeScript**: `aegis-trust` `0.10.2` on npm — `npm install aegis-trust`. Version-locked with the Python SDK at the same number.
- **License**: MIT (see [`LICENSE`](LICENSE); `python/LICENSE` is identical, byte-for-byte).
- **API versioning**: `Aegis-Api-Version: 2026-05-18` (dated header).
- **Not production-ready, not GA, not enterprise-ready.** This is an Alpha preview. SLA: none. Production use is at your own risk.

## Alpha limitations (read before adopting)

Honest list of what does NOT work in `0.10.2`. We list these here so a real evaluator does not have to discover them from code:

- **Token-level LLM response streaming is not field-filtered; record-boundary streaming ships (LITE).** `shield()` filters a single, complete return value, and a *partial* SSE / chunked token stream cannot be field-filtered safely — you cannot strip `ssn` from a half-parsed record. For handlers that yield **whole records** incrementally (DB cursor, paginated fetch, an upstream LLM emitting one JSON object per step), `shieldedStreamTool()` / `shielded_stream_tool()` filter each record at its boundary as it arrives — shipped in **both** SDKs, **LITE only** (see the [Runnable integrations](#runnable-integrations-today) table). The two remaining gaps: token-level partial-chunk filtering of an Anthropic / OpenAI / Vercel AI SDK response stream (not possible by design), and FULL-mode streaming with the pre-execution `/check-access` gate (a tracked follow-up — use the non-streaming `shieldedTool()` / `shielded_tool()` for FULL today).
- **First-party adapters: LangChain + CrewAI + LlamaIndex on both SDKs, Vercel AI SDK on Node.** Dedicated adapters ship for **LangChain**, **CrewAI**, and **LlamaIndex** on **both** SDKs — Node (`aegis-trust/adapters`: `shieldedTool` + `toLangChainTool` / `toCrewaiTool` / `toLlamaIndexTool`) and Python (`aegis_trust.adapters`: `shielded_tool` + `to_langchain_tool` / `to_crewai_tool` / `to_llamaindex_tool`) — plus **Vercel AI SDK** on Node (`toVercelTool`), each with a runnable example and unit tests. There are **no** dedicated adapters for Anthropic / OpenAI SDKs (no tool-registry abstraction — the drop-in one-liner is the whole integration), Mastra, Bedrock, or AutoGen. Treat anything not in the [Runnable integrations](#runnable-integrations-today) table as **compatible-by-pattern**, not **integrated** — use the [Drop-in wrapper pattern](#drop-in-wrapper-pattern).
- **Python and Node ingest-failure semantics are now aligned (fail-closed) as of 0.9.2.** Both SDKs return a type-shaped empty on a gateway ingest exception in FULL mode — the filtered data is released only after the audit record is durably accepted (AO-003 audit completeness). rc7 and earlier Node returned the filtered data anyway (fail-open on audit); that divergence was reconciled in 0.9.2 (see `node/CHANGELOG.md`).
- **Local audit logs are append-only, NOT hash-chained or tamper-evident in the SDK.** Python writes SQLite (`~/.aegis/history.db`); Node writes JSONL (`~/.aegis/history.jsonl`). These are plain append-only local records (no `prev_hash` chaining); editing or deleting an entry leaves no cryptographic trace. Tamper-evidence is a property of the **aegis-core gateway's** server-side audit log in FULL mode (`/audit/verify` → `chain_valid`), not of these local files. Inspecting the local logs currently requires separate tooling per language.
- **Install resolves to `0.10.2` on both registries.** `pip install aegis-trust` and `npm install aegis-trust` both fetch `0.10.2` (the two SDKs are version-locked at the same number). The deprecated `0.9.0-rc3` (withdrawn: the published artifact did not match this repo's source) is version-scoped and never the default.
- **Error-code reference page is hosted, not in-repo.** Error envelopes carry `docs_url: https://aegis-trust.dev/errors/<code>` (per [`python/src/aegis_trust/errors.py`](python/src/aegis_trust/errors.py) + [`node/src/errors.ts`](node/src/errors.ts)). The hosted page is the authoritative registry; the in-repo file [`node/docs/errors/README.md`](node/docs/errors/README.md) is a partial mirror. Use the `code` field on `AegisError` as the stable identifier; the Web URL may be empty for some codes during preview.

If any of the above is a blocker for your use case, wait for v1.0 GA rather than adopting 0.10.2.

## Procurement & Compliance posture (Alpha)

Honest disclosure for procurement teams, security review, and compliance officers. None of the below is a marketing claim — it is the literal state of this preview. If your evaluation requires anything beyond what is listed, the answer for `0.10.2` is "not yet".

**Commercial / procurement**

- **License**: MIT (see [`LICENSE`](LICENSE); `python/LICENSE` is identical byte-for-byte). No contribution under any other license is solicited or accepted.
- **SLA**: **none**. There is no uptime, support response, or remediation timeline commitment in this preview release.
- **Support channel**: GitHub issues at this repo + email `contact@aegisagentcontrol.com`. No paid tier. No 24/7 channel.
- **Vendor of record**: NemoTek (contact@aegisagentcontrol.com). Single-maintainer project at preview stage. Procurement teams that require multi-engineer bus-factor evidence should treat this as a risk factor for 0.10.2.
- **Enterprise agreement / DPA / MSA**: not offered for 0.10.2. The MIT license is the only legal instrument.
- **Pricing**: open-source SDK is free. No commercial SKU is available.

**Audit / compliance attestation**

- **SOC 2 Type II / ISO 27001 / PCI-DSS / HIPAA**: **no certification or attestation exists** for `aegis-trust` or its aegis-core gateway dependency in the preview release. Compliance evaluation is the operator's responsibility.
- **GDPR**: the SDK is a *data-minimization tool by design* (declared `purpose` × `scope` enforces field-level reduction before data leaves the function boundary), but no Data Processing Agreement is offered, no controller / processor split is contractually defined, and no DSR (data subject request) tooling is provided. Operators integrating into a GDPR-regulated pipeline must perform their own DPIA.
- **CCPA / CPRA**: same posture as GDPR — minimization helps, no contractual instruments provided.
- **Data residency**: the SDK in `LITE` mode does not transmit data; in `FULL` mode it calls an `aegis-core` gateway whose deployment topology is operator-controlled. There is no managed-service control over residency.
- **Audit log retention**: written locally (`~/.aegis/history.jsonl` for Node, `~/.aegis/history.db` for Python). The SDK does not manage retention, encryption-at-rest, or transport to a SIEM — that is the operator's responsibility.
- **Breach notification**: best-effort via the security disclosure process documented in [`python/SECURITY.md`](python/SECURITY.md) / [`node/SECURITY.md`](node/SECURITY.md) (48h acknowledgment, 7-day triage, 30-day fix for CVSS ≥ 7.0). No track record exists for the preview release.
- **Right to be forgotten / data deletion**: the SDK is stateless except for the local audit log. Deletion of audit entries is the operator's responsibility.
- **SBOM / SLSA / supply-chain attestation**: CycloneDX SBOMs (node + python) and Sigstore cosign-signed SDK artifacts (npm tarball, Python wheel, sdist) are attached to the GitHub Release at `v0.10.2` (`Block B Phase 2` in `release-attestation.yml`, keyless OIDC signing, Sigstore Rekor public log). Both registries publish via Block C Trusted Publisher OIDC (token-free, OTP-free) on the same workflow run — npm to the `latest` dist-tag (non-prerelease) and PyPI via its Trusted Publisher. npm provenance (`--provenance`) is **enabled** in the release workflow (the repo is public), so `npm audit signatures` verifies the npm-side attestation; `cosign verify-blob` against the GitHub Release `.tgz` / `.whl` / `.tar.gz` remains available as the registry-independent verification path (byte-identical to the npm-published tarball — same artifact handoff).

**What this section is not**: a compliance certification, a legal commitment, a roadmap commitment, or an invitation to negotiate. It is an honest static snapshot of preview-state posture so a procurement or compliance review can make a `proceed / wait for GA / decline` call without a back-and-forth with the maintainer.

## Runnable integrations today

The table below lists what has a working example file in this repo and what is exercised by the test suite. If an integration is **not** in this table, it does not have a dedicated example or test yet — use the generic [Drop-in wrapper pattern](#drop-in-wrapper-pattern) instead.

**Dedicated adapters** ship a `shieldedTool()` / `shielded_tool()` primitive plus per-framework binders that produce each framework's native tool shape with shield filtering baked in — Node under the `aegis-trust/adapters` subpath (`toLangChainTool`, `toVercelTool`, `toCrewaiTool`) and Python under `aegis_trust.adapters` (`to_langchain_tool`, `to_crewai_tool`). The binders take no runtime dependency on the frameworks (factory / base-class injection), so they are version-tolerant and unit-tested without any framework installed. The shield filters the tool's **return value**, not its arguments — validate and authorize tool-call arguments in your handler or the framework's schema layer.

| Integration | Language | Adapter | Example file(s) | Test |
|---|---|---|---|---|
| Model Context Protocol (MCP) | Node | drop-in `shield()` | [`node/examples/mcpTool.ts`](node/examples/mcpTool.ts), [`node/examples/mcpEndToEnd.ts`](node/examples/mcpEndToEnd.ts) | [`node/tests/mcp/run_end_to_end.mjs`](node/tests/mcp/run_end_to_end.mjs) |
| LangChain.js | Node | `toLangChainTool` | [`node/examples/langchainExample.ts`](node/examples/langchainExample.ts) | [`node/tests/adapters.test.ts`](node/tests/adapters.test.ts) (+ example falls back when `@langchain/openai` is not installed) |
| LangChain (Python) | Python | `to_langchain_tool` | [`python/examples/langchain_example.py`](python/examples/langchain_example.py) | [`python/tests/test_adapters.py`](python/tests/test_adapters.py) (+ example falls back when `langchain-core` is not installed) |
| Vercel AI SDK | Node | `toVercelTool` | [`node/examples/vercelAiExample.ts`](node/examples/vercelAiExample.ts) | [`node/tests/adapters.test.ts`](node/tests/adapters.test.ts) (+ example falls back when `ai` is not installed) |
| CrewAI (Node port) | Node | `toCrewaiTool` | [`node/examples/crewaiExample.ts`](node/examples/crewaiExample.ts) | [`node/tests/adapters.test.ts`](node/tests/adapters.test.ts) (+ example falls back when `crewai` is not installed) |
| CrewAI (Python) | Python | `to_crewai_tool` | [`python/examples/crewai_example.py`](python/examples/crewai_example.py) | [`python/tests/test_adapters.py`](python/tests/test_adapters.py) (+ example falls back when `crewai` is not installed) |
| LlamaIndex.TS | Node | `toLlamaIndexTool` | [`node/examples/llamaindexExample.ts`](node/examples/llamaindexExample.ts) | [`node/tests/adapters.test.ts`](node/tests/adapters.test.ts) (+ example falls back when `llamaindex` is not installed) |
| LlamaIndex (Python) | Python | `to_llamaindex_tool` | [`python/examples/llamaindex_example.py`](python/examples/llamaindex_example.py) | [`python/tests/test_adapters.py`](python/tests/test_adapters.py) (+ example falls back when `llama-index-core` is not installed) |
| Streaming (record-boundary, **LITE only**) | Node | `shieldedStreamTool` | [`node/examples/streamExample.ts`](node/examples/streamExample.ts) | [`node/tests/adaptersStream.test.ts`](node/tests/adaptersStream.test.ts) |
| Streaming (record-boundary, **LITE only**) | Python | `shielded_stream_tool` | [`python/examples/stream_example.py`](python/examples/stream_example.py) | [`python/tests/test_adapters_stream.py`](python/tests/test_adapters_stream.py) |
| FastAPI / FastMCP | Python | drop-in `shield()` | recipes in [`python/README.md`](python/README.md) | underlying `shield()` covered by `python/tests/`; no dedicated FastAPI / FastMCP integration test yet |
| Generic async / deny-fields / multi-purpose / dot-notation / sandbox / crypto-wallet | Node | drop-in `shield()` | [`node/examples/`](node/examples/) | per-example |

Integrations that are **not yet runnable as dedicated adapters in this repo** (use the drop-in wrapper instead):

- Anthropic SDK (`anthropic`, `@anthropic-ai/sdk`) — no tool-registry abstraction; the [drop-in one-liner](#drop-in-wrapper-pattern) is the whole integration (filter the data you put in the `messages` payload).
- OpenAI SDK (`openai`) — same: filter the tool-result data fed back to the model.
- Mastra (`@mastra/core`)
- Bedrock, AutoGen.js

These are compatible-by-pattern. Purpose-built adapters/example files for them are planned but not present in 0.10.2.

## Drop-in wrapper pattern

For any framework or SDK that is not in the table above, wrap the **data-access function** (not the LLM client). The wrapped function keeps the same signature and can be passed into any tool registry, message-building step, or callback the framework already accepts.

```python
# Python — wrap your data accessor, then hand it to your agent framework / LLM SDK
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    return db.fetch(id)

# Now use get_customer wherever you would have used the raw accessor:
#   - Anthropic / OpenAI / Bedrock: include get_customer(id) in your messages payload
#   - Vercel AI SDK: register get_customer as the execute callback of a tool
#   - LangChain / LlamaIndex / CrewAI / AutoGen: same — pass the wrapped function in
```

```typescript
// Node — same pattern. shield returns a function with the same signature as db.fetch
import { shield } from "aegis-trust";

const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "issue"],
})(db.fetch);

// Now hand getCustomer to your framework's tool registry.
// Working examples in this repo: node/examples/langchainExample.ts, node/examples/mcpTool.ts,
// node/examples/crewaiExample.ts.
```

These snippets are **not adapters**. They are the same generic `shield()` wrapper applied at the data-access boundary. They work in `0.10.2` today, but they require you to wire them into your framework yourself; the framework integration code is not in this repo.

## Repository layout

```
aegis-trust/
├── python/        # Python SDK (pip install aegis-trust)
│   ├── src/
│   │   ├── aegis_trust/         # canonical module (v0.9.1+)
│   │   └── aegis/               # back-compat shim (DeprecationWarning, removal v2.0.0)
│   ├── tests/
│   ├── pyproject.toml
│   └── README.md
└── node/          # TypeScript / Node SDK (npm install aegis-trust)
    ├── src/
    ├── tests/
    ├── examples/                # MCP, LangChain.js, CrewAI, async, deny-fields, multi-purpose,
    │                            # dot-notation, sandbox, crypto-wallet, docker. (See the
    │                            # Runnable integrations table above for the authoritative list.)
    ├── package.json
    └── README.md
```

## Origin

This repository is the single home for both the Python and TypeScript `aegis-trust`
SDKs, consolidated from earlier separate codebases. Pre-consolidation development
history remains in the original repositories.
