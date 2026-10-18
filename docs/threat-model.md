# AgentBridge Threat Model

## Assets

1. The Mac itself: arbitrary code execution as the user.
2. User files: home directory, documents, SSH keys, browser state.
3. Credentials: pairing codes, agent public keys, audit key.
4. Availability: the bridge and the Mac staying usable.

## Actors

- **Remote stranger** — has the tunnel URL (public or leaked), no keys.
- **Rogue agent** — a legitimately paired cloud agent that is compromised,
  prompt-injected, or buggy. Has a working private key.
- **LAN attacker** — shares a network with the Mac (café WiFi).
- **Local process** — runs as the user on the Mac. (Out of scope: if the
  user account is compromised, no userspace bridge can help. We only avoid
  making it worse: secrets are 0600/0700 and public keys are useless to steal.)

## Attacks and fundamental defenses

### 1. Credential replay / theft (remote stranger)
- **v1 failure:** one static bearer token in a header = full shell. Token
  appeared in `CONNECTION_INFO.txt`, callback payloads, logs, chat.
- **v2 defense:** Ed25519 challenge-response-free signatures. The bridge
  stores only public keys; there is no shared secret to steal from disk,
  logs, or the pairing response. Requests bind method + path + body hash +
  timestamp (±120 s) + single-use nonce, so captured requests cannot be
  replayed, retargeted, or tampered with.

### 2. Prompt injection → destructive command (rogue agent)
- **v1 failure:** `POST /terminal/exec` ran any string through `zsh -l -c`.
  A five-line regex blocklist pretended to contain this; it cannot
  (`rm -rf "$HOME"`, base64, variable indirection, …).
- **v2 defense:** no shell in the API. Capabilities only. Irreversible or
  elevated operations (delete, non-allowlisted programs, opt-in shell)
  require a human approval on the Mac, bound to the exact planned action,
  single-use, 120 s TTL, default deny. The agent cannot approve anything
  itself and cannot widen its own permissions: per-agent program grants are
  set exclusively by the CLI on the Mac.

### 3. Interpreters as an allowlist bypass (rogue agent)
- **v1-style failure:** allowlisting `node`, `python3`, `git`, `make`, `find`,
  `tar`, `curl` etc. is equivalent to allowing a shell.
- **v2 defense:** the auto-allowlist contains only programs that cannot
  execute attacker-controlled code and cannot write outside their arguments.
  Everything else → approval or an explicit human grant.

### 4. Planted binary (rogue agent)
- **Attack:** agent writes an executable named `ls` into the workspace and
  invokes it (relative or absolute path) — allowlist bypass.
- **v2 defense:** auto-allow applies only to bare names resolved through the
  scrubbed system `PATH`. Any `argv[0]` containing a slash requires
  approval. Spawned environments never inherit the caller's env.

### 5. Filesystem escape (rogue agent)
- **v1 failure:** `path.resolve` prefix check, no symlink resolution, and
  `/var` was explicitly allowed.
- **v2 defense:** the deepest existing ancestor is `realpath`-resolved
  (symlinks die here) before the prefix check; the non-existent tail is
  re-appended lexically. Writes/deletes are confined to the workspace root
  regardless of read roots. Reads use `O_NOFOLLOW`; writes open with
  `O_NOFOLLOW` so a symlink swapped in after the check cannot redirect them.
  Final-component symlinks are rejected outright.
- **Residual:** a symlink swapped in between `realpath` and `open` on a
  *parent directory* is a known race; the window is microseconds and
  requires local code execution to exploit reliably, which is already out
  of scope.

### 6. Browser drive-by / DNS rebinding (remote stranger → local user)
- **v1 failure:** `Access-Control-Allow-Origin: *` with `Authorization` in
  allowed headers invited cross-origin browser calls to the bridge.
- **v2 defense:** no CORS headers at all; requests must carry a custom
  header (`X-Bridge-Request: 1`) and an exact `Content-Type:
  application/json`, neither of which a cross-origin browser form/fetch can
  produce without a preflight we never answer. Host header must be
  loopback or a configured tunnel hostname.

### 7. LAN exposure
- **v1 failure:** bound `0.0.0.0`; anyone on the WiFi could reach the API.
- **v2 defense:** `127.0.0.1` only. Remote access exists solely through the
  tunnel. (A `bind` config override exists for exotic setups and prints a
  loud warning; it is never set by the installer.)

### 8. Pairing endpoint abuse
- **Defense:** codes are 50-bit, 10-minute TTL, single-use, max 5 active;
  failed attempts are rate-limited (6 per 10 min per source IP). Failures
  are audited.

### 9. Silent tampering / repudiation
- **v2 defense:** every decision (pair, reject, rate-limit, execute,
  approve, deny) is appended to a hash-chained, HMAC-authenticated JSONL
  audit log. `agent-bridge audit --verify` proves integrity. The HMAC key
  never leaves the device.

### 10. Supply chain
- **v1 failure:** unpinned downloads; `kill -9` of whatever held the port;
  token printed to terminal and written to a plaintext info file.
- **v2 defense:** Node.js and cloudflared are version-pinned and SHA-256
  verified against upstream checksum files at install time. No sudo. No
  secrets in terminal output or info files. Uninstaller removes everything.

## Known limitations (honest list)

- The tunnel URL is unguessable but not secret-proof; treat it as public.
  Security must not and does not depend on it.
- Quick tunnels move: on reconnect the URL changes. Re-pairing is NOT
  required (keys are URL-independent), but the agent needs the new URL.
- Approvals are CLI/notification-based; a user who approves everything
  reflexively defeats rule 5. The UI names the exact action for this reason.
- The bridge does not defend against a compromised user account, a
  malicious kernel, or physical access.
