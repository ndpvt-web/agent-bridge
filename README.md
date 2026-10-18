# AgentBridge

**Let an AI agent work on your Mac - safely. One command to install, one command to connect.**

## Install

```bash
curl -fsSL https://github.com/ndpvt-web/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash
```

Then connect your agent (Claude, ChatGPT, Cursor, Instinct, or your own):

```bash
agent-bridge pair
```

Paste the tunnel URL and one-time code into your agent. Done.

## Two modes

| | What the agent can do |
| --- | --- |
| **SAFE** (default) | Work inside one folder you choose. Safe commands run freely; anything risky waits for your approval on the Mac. What you approve is exactly what runs. |
| **FULL** | Anything, as you. No jail, no approvals. Only if you trust the agent completely. |

SAFE is the default - the one-command install above gives you SAFE.
To install straight into FULL instead:

```bash
curl -fsSL https://github.com/ndpvt-web/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash -s -- --mode full
```

Switch anytime (FULL always asks you to confirm, and every switch is logged):

```bash
agent-bridge mode full
agent-bridge mode safe
```

## Everyday commands

```bash
agent-bridge status     # is it running, in which mode, who is connected
agent-bridge pending    # requests waiting for you
agent-bridge approve    # say yes     agent-bridge deny   # say no
agent-bridge agents     # who is connected      agent-bridge revoke <name>   # cut one off
agent-bridge audit      # tamper-evident log of everything
~/agent-bridge/uninstall.sh   # remove the bridge (keeps your files)
```

## Works with your agent

- **Instinct** - paste the tunnel URL and pairing code into your chat. It connects itself; you approve on the Mac.
- **Claude, ChatGPT / Codex, Cursor, Meta Muse, or your own agent** - if it can make HTTPS requests, it can pair: the handshake is two calls, written up in [docs/protocol.md](docs/protocol.md). Give your agent the tunnel URL, the pairing code, and that doc.

AgentBridge speaks MCP-style JSON-RPC (`initialize`, `tools/list`, `tools/call`) over signed HTTPS. A small adapter for native MCP client configs (`mcp.json`) is not built yet.

## How it stays safe

Every call is cryptographically signed by a paired agent key. Files live in a realpath-checked jail. When you approve a command, the bridge freezes a private copy of every file it names and runs the copy - nothing can be swapped after you say yes. Approvals work once. Everything lands in a tamper-evident audit log. The installer's downloads are version-pinned and hash-verified.

Details: [SECURITY.md](SECURITY.md) · [threat model](docs/threat-model.md) · [protocol](docs/protocol.md)

Zero dependencies, macOS, MIT license. v2.1.0 - 306 automated security tests (`npm test`).
