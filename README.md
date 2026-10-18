# AgentBridge — Connect Your Mac to Any Cloud AI Agent in One Command

**AgentBridge turns your Mac into a secure, remote-controlled workstation for any cloud AI agent** — Claude, ChatGPT, Cursor, Instinct, HappyCapy, or your own agent — with one terminal command. Run builds on your Mac's Xcode, read and write local files, and let your agent work on your machine 24/7, without giving away the keys to your Mac.

- **Zero dependencies** — pure Node.js built-ins, no `npm install`, no Homebrew required
- **Secure by design** — Ed25519-signed requests, capability-based tools, filesystem jail, on-device human approvals, tamper-evident audit log
- **Agent-agnostic** — speaks MCP-style JSON-RPC (`initialize`, `tools/list`, `tools/call`). If your agent can call tools, it can use AgentBridge
- **One command** — installs Node (pinned + checksum-verified), cloudflared, the bridge, and 24/7 auto-start via launchd

```
curl -fsSL https://github.com/<you>/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash
agent-bridge pair
```

(Or clone the repo and build the installer locally: `bash scripts/build-installer.sh`.)

Paste the one-time pairing code and tunnel URL into your cloud agent. Done.

---

## Why not just expose a shell over a tunnel?

Because that is how you lose a Mac. The common pattern — a local HTTP server with a bearer token and a `/exec` endpoint — collapses the moment a token leaks into a log, a screenshot, or a chat message. And even with a perfect token, the *agent itself* can be prompt-injected into running something destructive.

AgentBridge is built on a different set of assumptions:

| Assumption | Consequence |
|---|---|
| The tunnel URL is public knowledge | Authentication must survive a public endpoint |
| Any single credential can leak | No bearer tokens; per-request Ed25519 signatures |
| The agent can be manipulated | Capabilities, not a shell; human approval for anything irreversible |
| The laptop is on hostile networks | Loopback-only bind, no CORS, Host-header checks |
| You will want to know what happened | Hash-chained, HMAC-authenticated audit log |

## Architecture

```
┌──────────────┐   HTTPS (Cloudflare Tunnel)   ┌─────────────────────────────┐
│  Cloud agent │ ────────────────────────────▶ │  cloudflared (quick tunnel) │
│ (Claude,     │   Ed25519-signed requests     │         │                   │
│  Instinct, …)│                               │         ▼                   │
└──────────────┘                               │  AgentBridge (127.0.0.1)    │
                                               │   ├─ pairing (one-time code)│
                                               │   ├─ signature + replay chk │
                                               │   ├─ capability tools       │
                                               │   ├─ fs jail (workspace)    │
                                               │   ├─ approval gate ──▶ YOU  │
                                               │   └─ audit log (chained)    │
                                               └─────────────────────────────┘
```

**The Mac never listens on the network.** The server binds `127.0.0.1` only; cloudflared dials out. There is no inbound port, no LAN exposure, no router config.

## The security model in five rules

1. **No bearer tokens.** Agents pair with a one-time code (10-minute TTL, single-use) and register an Ed25519 public key. The bridge stores *only public keys* — a full read of its secrets directory yields nothing that can authenticate. Every request is signed over `(agent, timestamp, nonce, method, path, body-hash)` with a 120-second window and a nonce replay cache.

2. **Capabilities, not a shell.** The API is a small tool catalog: `system.info`, `fs.list`, `fs.read`, `fs.write`, `fs.delete`, `process.run`, `approval.status`. Raw `shell.exec` exists only if you opt in at install time (`--enable-shell`) — and *every* call still requires your on-device approval.

3. **The allowlist is honest.** Auto-approved programs are inspection-only (`ls`, `cat`, `grep`, `jq`, …). Interpreters and build tools (`node`, `python3`, `git`, `make`, `xcodebuild`, `npm`) are shells in disguise, so they require approval — or a per-agent grant *you* set from the Mac: `agent-bridge allow <agent> xcodebuild`. The API can never expand its own permissions.

4. **The filesystem is jailed.** Writes and deletes stay inside `~/agent-bridge/workspace` (symlinks resolved before the check, `O_NOFOLLOW` against races). Deletes move to a local trash; overwrites keep 20 versions. Reads can extend to your home directory but never escape configured roots.

5. **You are the root of trust.** Destructive or elevated actions create a pending approval; you run `agent-bridge approve <id>` on the Mac (a macOS notification tells you when something is waiting). Default deny, 120-second expiry, single-use, race-safe.

See [docs/threat-model.md](docs/threat-model.md) for the full analysis and [SECURITY.md](SECURITY.md) for reporting.

## The one-time setup

```bash
# 1. Install (macOS, Apple Silicon or Intel)
curl -fsSL https://github.com/<you>/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash

# 2. Pair an agent (prints a one-time code, valid 10 minutes)
agent-bridge pair                    # default: workspace profile
agent-bridge pair --profile readonly    # read-only agent
agent-bridge pair --profile developer   # + process execution (approval-gated)

# 3. Give your cloud agent: the tunnel URL + the pairing code.
#    It registers its public key and starts making signed calls.
```

## Profiles

| Profile | fs.read / fs.list | fs.write / fs.delete | process.run | shell.exec |
|---|---|---|---|---|
| `readonly` | ✅ | — | — | — |
| `workspace` (default) | ✅ | ✅ (workspace, approval for delete) | — | — |
| `developer` | ✅ | ✅ | allowlist or approval | opt-in + always approval |

## Day-to-day commands

```bash
agent-bridge status            # config summary, no secrets
agent-bridge pair              # new pairing code
agent-bridge agents            # who is connected
agent-bridge revoke <agent>    # cut an agent off instantly
agent-bridge pending           # what is waiting on you
agent-bridge approve <id>      # allow one pending action
agent-bridge allow <agent> git # trust this agent with one program
agent-bridge audit --verify    # prove the audit log is intact
~/agent-bridge/uninstall.sh    # remove everything
```

## For agent developers

AgentBridge exposes MCP-style JSON-RPC over a single `POST /mcp` endpoint:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "fs.read", "arguments": { "path": "notes/todo.md" } } }
```

Headers: `X-Bridge-Agent`, `X-Bridge-Ts`, `X-Bridge-Nonce`, `X-Bridge-Sign` (Ed25519 over the canonical string), `X-Bridge-Request: 1`, `Content-Type: application/json`. Full spec: [docs/protocol.md](docs/protocol.md). A reference client lives in [test/client.mjs](test/client.mjs).

## What this is not

- Not a sandbox against software already running as you on your Mac.
- Not a replacement for locking your screen — approvals are CLI-based.
- Not affiliated with Cloudflare; quick tunnels are used for transport only. For production use, switch to a named tunnel with Cloudflare Access for an additional identity layer.

## FAQ

**Does this work with Claude Code / Cursor / Instinct / my own agent?**
Yes — anything that can make HTTPS POSTs. The protocol is ~100 lines to implement; see docs/protocol.md.

**What happens if my tunnel URL leaks?**
Nothing, by itself. Requests still need a paired agent's private key, fresh timestamps, and unused nonces.

**What happens if the agent goes rogue?**
It can read and write the workspace (that's the job), but deletes need your approval, interpreters need your approval, and raw shell is off unless you opted in. `agent-bridge revoke` cuts it off instantly, and `agent-bridge audit` shows you everything it did.

**Linux support?**
The server is platform-neutral and is developed/tested on Linux; the installer, launchd integration, and desktop notifications are macOS-only today. Linux installers (systemd) are on the roadmap.

## License

MIT. See [LICENSE](LICENSE).
