# AgentBridge — Let any AI agent work on your Mac, safely

**One terminal command connects your Mac to any cloud AI agent. The agent can build, read files, and run commands on your Mac — and every risky action needs your approval first.**

[Quickstart](#install-in-one-command) · [How it stays safe](#how-it-stays-safe) · [SECURITY.md](SECURITY.md) · [Issues](https://github.com/ndpvt-web/agent-bridge/issues)

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey)

> [!NOTE]
> **Status (Oct 2026):** Two full rounds of independent security review are done — every finding fixed at the root, with 223 adversarial test cases, 10 end-to-end tests, and 21 installer end-to-end checks passing. Treat this as release-candidate software.

## What it is

Your Mac, remote-controlled by an AI agent — without handing over the keys.

AgentBridge runs a small, secure server on your Mac. Point your cloud agent (Claude, ChatGPT, Cursor, Instinct, HappyCapy, or your own) at it, and the agent can do real work on your machine: run Xcode builds, read and write files, execute commands — all inside strict limits you control.

- **One command to install** — no Homebrew, no npm install, zero dependencies beyond Node (which the installer sets up for you)
- **You approve the risky stuff** — commands outside a strict allowlist and all deletions wait for your yes on the Mac itself, bound to the exact action you approved
- **Files stay in a jail** — the agent only sees the folder you choose, never your whole disk. Writes are versioned and deletes go to a trash folder, so mistakes are recoverable
- **Every action is logged** — a tamper-evident audit trail of who did what, when
- **Works with any agent** — speaks MCP-style JSON-RPC (`initialize`, `tools/list`, `tools/call`). If your agent can call tools, it can use AgentBridge

## Install in one command

```bash
curl -fsSL https://github.com/ndpvt-web/agent-bridge/releases/latest/download/install-agent-bridge.sh | bash
```

Then pair your agent:

```bash
agent-bridge pair
```

This prints a tunnel URL and a one-time pairing code (valid 10 minutes). Paste both into your cloud agent. Done — the bridge now runs 24/7 in the background via launchd.

Prefer to build from source? `bash scripts/build-installer.sh` builds the installer locally.

## What your agent can do

- Read, write, and list files inside your chosen folder
- Run approved commands — builds, tests, and a curated set of safe dev tools without asking
- Work while you're away — the bridge stays up, you stay in control
- Get its own identity — each agent pairs with its own Ed25519 key, so you can see and revoke each one separately

## How it stays safe

1. **Signed requests** — every call is Ed25519-signed by a paired agent key. No key, no access. Captured requests can't be replayed.
2. **Strict command allowlist** — per-program argument rules, not patterns an agent can talk its way around.
3. **Filesystem jail** — realpath-checked; symlink escapes and writes through links are refused.
4. **Human approval gate** — anything outside the allowlist pings your Mac for a yes/no, and what runs is exactly what you approved, down to the file contents.
5. **Tamper-evident audit log** — hash-chained; edits to history show up as tampering.

The installer's downloads are version-pinned and SHA-256-verified against hashes embedded in the script, fail-closed on mismatch. Full details in [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).

## Day-to-day

| Command | What it does |
| --- | --- |
| `agent-bridge pair` | Pair a new agent (prints one-time code) |
| `agent-bridge status` | Is the bridge running, and who's connected |
| `agent-bridge revoke <agent>` | Cut off an agent |
| `agent-bridge audit` | Review the audit log |
| `agent-bridge uninstall` | Remove the bridge (keeps your workspace unless `--purge`) |

## For agent developers

AgentBridge speaks MCP-style JSON-RPC over the tunnel. Call `initialize`, list tools with `tools/list`, and invoke them with `tools/call`. See the [docs](docs) for the tool catalogue and pairing handshake.

## License

MIT
