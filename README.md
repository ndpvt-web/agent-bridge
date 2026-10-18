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

## How it stays safe

Every call is cryptographically signed by a paired agent key. Files live in a realpath-checked jail. When you approve a command, the bridge freezes a private copy of every file it names and runs the copy - nothing can be swapped after you say yes. Approvals work once. Everything lands in a tamper-evident audit log. The installer's downloads are version-pinned and hash-verified.

Details: [SECURITY.md](SECURITY.md) · [threat model](docs/threat-model.md) · [protocol](docs/protocol.md)

Zero dependencies, macOS, MIT license. v2.1.0 - 306 automated security tests (`npm test`).
