<div align="center">

# AgentBridge

**Let any AI agent work on your Mac - safely.**

One command to install. One command to connect. You approve what matters.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey)]()
[![Version: 2.1.0](https://img.shields.io/badge/version-2.1.0-green)]()
[![Tests: 306 passing](https://img.shields.io/badge/tests-306%20passing-brightgreen)]()

[Works With](#works-with-your-agent) · [Quick Start](#quick-start) · [Two Modes](#two-modes) · [Security](#how-it-stays-safe) · [Docs](docs)

</div>

---

Your Mac, remote-controlled by an AI agent - without handing over the keys.

AgentBridge runs a tiny, zero-dependency server on your Mac. Point your cloud agent at it, and the agent can do real work on your machine: run builds, read and write files, execute commands - inside limits you choose. Anything risky waits for your approval, and **what you approve is exactly what runs**.

## Works with your agent

<p>
<a href="#works-with-your-agent"><img alt="Instinct" src="https://img.shields.io/badge/Instinct-7c3aed"></a>
<a href="#works-with-your-agent"><img alt="ChatGPT / Codex" src="https://img.shields.io/badge/ChatGPT%20%2F%20Codex-74aa9c?logo=openai&logoColor=white"></a>
<a href="#works-with-your-agent"><img alt="Claude" src="https://img.shields.io/badge/Claude-191919?logo=anthropic&logoColor=white"></a>
<a href="#works-with-your-agent"><img alt="Cursor" src="https://img.shields.io/badge/Cursor-000000?logo=cursor&logoColor=white"></a>
<a href="#works-with-your-agent"><img alt="Meta Muse" src="https://img.shields.io/badge/Meta%20Muse-0668E1?logo=meta&logoColor=white"></a>
</p>


- **Instinct** - paste the tunnel URL and pairing code into your chat. It connects itself; you approve on the Mac.
- **Claude, ChatGPT / Codex, Cursor, Meta Muse, or your own agent** - if it can make HTTPS requests, it can pair: the handshake is two calls, written up in [docs/protocol.md](docs/protocol.md). Give your agent the tunnel URL, the pairing code, and that doc.

AgentBridge speaks MCP-style JSON-RPC (`initialize`, `tools/list`, `tools/call`) over signed HTTPS. A small adapter for native MCP client configs (`mcp.json`) is not built yet.

## Quick start

No technical knowledge needed. Four steps, about two minutes.

**Step 1 - open Terminal.**
On your Mac, press the **Command (⌘) and Space** keys together. A search box appears. Type `Terminal` and press **Return**. A plain window with a blinking cursor opens.

**Step 2 - paste one line.**
Copy the line below (select it, then Command+C), click inside the Terminal window, paste it (Command+V), and press **Return**:

```bash
curl -fsSL https://github.com/ndpvt-web/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash
```

You'll see it download and check a few things - that's normal. If it asks which mode you want, just press **Return** (that picks SAFE, the recommended one). When you see **AGENTBRIDGE INSTALLED**, you're done with this step. About a minute.

**Step 3 - connect your agent.**
In the same Terminal window, paste this and press **Return**:

```bash
agent-bridge pair
```

It prints a **tunnel URL** and a short **one-time code** (good for 10 minutes). Send both to your AI agent - for example, paste them into your chat with it. The agent connects itself.

> If Terminal says `command not found`, paste this line first and try again:
> `export PATH="$HOME/.local/bin:$PATH"`

**Step 4 - approve what it does.**
When your agent wants to do something risky, it waits for you. In Terminal, run `agent-bridge pending` to see what's asking, then `agent-bridge approve` or `agent-bridge deny`. Everyday safe commands don't bother you.

That's it. The bridge keeps running in the background - you never have to open Terminal again unless you want to approve something or change a setting.

## Two modes

| | What the agent can do |
| --- | --- |
| **SAFE** (default) | Work inside one folder you choose. Everyday commands run freely; anything risky waits for your approval on the Mac. |
| **FULL** | Anything, as you. No jail, no approvals. Only if you trust the agent completely. |

SAFE is the default and never changes silently. To install straight into FULL:

```bash
curl -fsSL https://github.com/ndpvt-web/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash -s -- --mode full
```

Switch anytime - FULL always shows one clear warning, asks you to confirm, and logs the switch:

```bash
agent-bridge mode full
agent-bridge mode safe
```

## How it works

```
 your agent (cloud)                    your Mac
 -----------------                    --------
      |     1. pair with one-time code      |
      |-----------------------------------> |  agent-bridge pair
      |                                     |
      |     2. signed request (Ed25519)     |
      |-----------------------------------> |  checked against your rules
      |                                     |
      |     3. risky? you get a yes/no      |
      |                                     |  on the Mac - your call
      |                                     |
      |     4. approved bytes run, logged   |
      | <-----------------------------------|
```

## Everyday commands

```bash
agent-bridge status     # is it running, in which mode, who is connected
agent-bridge pending    # requests waiting for you
agent-bridge approve    # say yes          agent-bridge deny      # say no
agent-bridge agents     # who is connected agent-bridge revoke <name>  # cut one off
agent-bridge audit      # tamper-evident log of everything (--verify checks integrity)
agent-bridge trash      # browse and restore deleted files
~/agent-bridge/uninstall.sh   # remove the bridge (keeps your files)
```

## How it stays safe

1. **Signed requests** - every call is Ed25519-signed by a paired agent key. No key, no access. Captured requests can't be replayed.
2. **Strict allowlist** - 21 read-only programs with per-program argument rules. Everything else needs your approval.
3. **Filesystem jail** - realpath-checked; symlink escapes and writes through links are refused.
4. **Frozen approvals** - named files are copied into a private snapshot at request time, and the run executes the copies. Approvals work once, expire in 120 seconds, and default to deny.
5. **Tamper-evident audit log** - hash-chained; edits to history show up as tampering.

Install downloads are version-pinned and SHA-256-verified, fail-closed, with no unverified system-binary fallback.

## Why AgentBridge

- **You stay in charge** - risky commands, deletions, and shell access wait for your yes on the Mac itself
- **No bait-and-switch** - approving a command freezes a private copy of every file it names, and the run executes the copies
- **Your files stay in a jail** - the agent sees only the folder you choose; writes are versioned, deletes go to a trash folder
- **Every action is logged** - a tamper-evident audit trail of who did what, when
- **Zero dependencies** - no Homebrew, no npm install; the installer sets up a pinned, hash-verified Node for you

## Docs

[Security policy](SECURITY.md) · [Threat model](docs/threat-model.md) · [Protocol for agent developers](docs/protocol.md)

## License

MIT
