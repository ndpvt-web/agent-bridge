# AgentBridge Protocol v2

Transport: HTTPS via the tunnel. One authenticated endpoint: `POST /mcp`.
Framing: JSON-RPC 2.0, MCP-style methods (`initialize`, `tools/list`,
`tools/call`, `notifications/*` accepted and ignored).

## Pairing

```
POST /pair
Content-Type: application/json
X-Bridge-Request: 1

{ "pairing_code": "ABCD-EFGH-JK", "agent_name": "claude-desktop",
  "public_key": "<base64url 32-byte Ed25519 public key>" }
```

`X-Bridge-Request: 1` and the exact content type are required (same CSRF
hardening as `/mcp`). `agent_name` is printable characters only, <= 80 chars.

200 → `{ "agent_id": "agt_...", "profile": "developer", ... }`.
The code comes from `agent-bridge pair` on the Mac (10 min TTL, single-use).
The agent generates and keeps its own Ed25519 keypair; the private key
never crosses the wire.

## Tunnel URL self-healing (discovery inbox)

Quick tunnels get a NEW random address every time cloudflared restarts.
So you never have to ask the user to re-paste: `agent-bridge pair` also
prints a **self-heal link** (a free webhook.site inbox, no account). A
watcher on the Mac posts ONLY the current tunnel URL there on every
rotation. The inbox never carries keys, codes, or request content - the
tunnel URL alone grants nothing; every call still needs your paired key.

If your stored tunnel URL stops answering:

```
GET <self-heal link>            # .../requests?sorting=newest&per_page=1
-> { "data": [ { "content": "{\"tunnel_url\":\"https://...\",\"ts\":\"...\"}" } ] }
```

Parse `data[0].content` as JSON, take `tunnel_url`, verify it matches
`https://*.trycloudflare.com`, and reconnect. Keep using your existing
keypair - pairing survives restarts.

## Signed requests

Every `POST /mcp` carries:

- `X-Bridge-Request: 1` (required; CSRF hardening)
- `Content-Type: application/json` (exact)
- `X-Bridge-Agent: <agent_id>`
- `X-Bridge-Ts: <unix milliseconds>`
- `X-Bridge-Nonce: <16..128 chars, single use>`
- `X-Bridge-Sign: <base64url Ed25519 signature>`

Canonical string (UTF-8, `\n`-joined):

```
agentId "\n" ts "\n" nonce "\n" METHOD "\n" path "\n" sha256hex(rawBody)
```

Validation order: custom header → content type → agent known & not revoked
→ timestamp within ±120 s → nonce shape → nonce unused → signature valid →
nonce recorded. A nonce is burned only after the signature verifies, so
junk-signed requests cannot poison the replay cache. Authentication
failures are rate-limited (30/min/source → 429) and audited in bounded form.

## Methods

- `initialize` → protocol version + server info.
- `tools/list` → tool catalog with JSON Schemas.
- `tools/call` `{name, arguments}` → result in `structuredContent`.

Tools: `system.info`, `fs.list`, `fs.read`, `fs.write`, `fs.delete`,
`process.run`, `shell.exec` (opt-in), `approval.status`.

## Approvals

When a call needs on-device approval, `tools/call` returns 200 with:

```json
{ "status": "pending_approval", "approval_id": "apr_...",
  "expires_at": "...", "how_to_approve": "agent-bridge approve apr_..." }
```

Poll `approval.status` with the `approval_id`. States: `pending`,
`expired`, `denied`, `executed`, `execution_failed`, `already_executed`,
`forbidden`. An approved action executes exactly once, on the first poll
after approval, and only for the agent that requested it. A failed
execution is consumed (`execution_failed`) - request a fresh approval
rather than retrying. For `process.run`, every workspace file named in the
argv is frozen at request time and the run executes the frozen copies.

## Errors

JSON-RPC codes: -32700 parse, -32601 unknown method, -32602 invalid params,
-32000 tool error (`forbidden:`, `disabled:`, …), -32029 rate limited.
HTTP: 400 missing headers, 401 auth failure, 413 body too large,
415 wrong content type, 421 disallowed Host, 429 pair throttling.
