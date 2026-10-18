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
  replayed, retargeted, or tampered with. A nonce is burned only AFTER its
  signature verifies: junk-signed floods can neither pre-burn a victim's
  nonce nor evict it from the bounded cache to enable a replay.
  Authentication failures are rate-limited (30/min/source → 429) and
  audited in bounded form (floods cannot fill the disk).

### 2. Prompt injection → destructive command (rogue agent)
- **v1 failure:** `POST /terminal/exec` ran any string through `zsh -l -c`.
  A five-line regex blocklist pretended to contain this; it cannot
  (`rm -rf "$HOME"`, base64, variable indirection, …).
- **v2 defense:** no shell in the API. Capabilities only. Irreversible or
  elevated operations (delete, non-allowlisted programs, opt-in shell)
  require a human approval on the Mac, bound to the exact planned action:
  the argv plus the SHA-256 of every workspace file named in it (which must
  exist at approval time; a plan naming a missing, symlinked, or >64 MB file
  is refused rather than approved unbound), single-use, 120 s TTL, default
  deny. Interpreters and build tools read files beyond the named argv
  (imports, Makefiles); those contents cannot be bound, and the approval
  line says so explicitly. Auto-allowed commands are additionally bounded by
  a 300 s execution timeout and per-agent rate limits. The agent cannot approve anything
  itself and cannot widen its own permissions: per-agent program grants are
  set exclusively by the CLI on the Mac.

### 3. Interpreters and flag-attached paths as allowlist bypass (rogue agent)
- **v1-style failure:** allowlisting `node`, `python3`, `git`, `make`, `find`,
  `tar`, `curl` etc. is equivalent to allowing a shell. Allowlisting by
  program name alone is *also* broken: `sort --output=~/.zshrc`,
  `rg --pre=sh`, `grep --file=/etc/passwd`.
- **v2 defense:** the auto-allowlist is a set of per-program argument
  grammars. Flags are deny-by-default; joined `--opt=value` forms are never
  auto-allowed; every positional path must resolve inside the workspace
  jail; programs that can execute code (interpreters, build tools, package
  managers, anything with an exec/pre/output option) are not in the list at
  all. Everything else → approval or an explicit human grant via the CLI,
  which warns loudly when the granted program can run code.

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
  regardless of read roots, and reads default to the workspace only - the
  bridge's own install dir is denied even when a parent is a read root.
  Writes refuse a symlink at the lexical final component, refuse hardlinked
  files, and go through race-checked opens (`O_NOFOLLOW` plus an inode
  comparison between lstat and the opened fd) with temp-file + rename
  atomicity. Deletes re-validate everything at execution time.
- **Residual:** a parent-directory swap timed between the realpath check and
  the open is narrowed to a same-inode race window; reliably winning it
  needs local code execution, which is out of scope.

### 6. Browser drive-by / DNS rebinding (remote stranger → local user)
- **v1 failure:** `Access-Control-Allow-Origin: *` with `Authorization` in
  allowed headers invited cross-origin browser calls to the bridge.
- **v2 defense:** no CORS headers at all; BOTH `/mcp` and `/pair` require
  a custom header (`X-Bridge-Request: 1`) and an exact `Content-Type:
  application/json`, neither of which a cross-origin browser form/fetch can
  produce without a preflight we never answer. Host header must be
  loopback or a configured tunnel hostname.

### 7. LAN exposure
- **v1 failure:** bound `0.0.0.0`; anyone on the WiFi could reach the API.
- **v2 defense:** `127.0.0.1` only. Remote access exists solely through the
  tunnel. `loadConfig` refuses a non-loopback `bind` outright - config can
  no longer widen the bind at all.

### 8. Pairing endpoint abuse
- **Defense:** codes are 50-bit, 10-minute TTL, single-use, max 5 active;
  failed attempts are rate-limited (6 per 10 min per source AND 60 per
  10 min globally; behind the tunnel the source is keyed on
  `CF-Connecting-IP` trusted only from a loopback peer - and the global
  bucket means spoofing that header cannot reset the budget).
  Failures are audited. Pairing requires a code the human generates on the
  Mac, so throttling can never lock out the human - worst case it slows
  adding a *new* agent while an attack is ongoing.

### 9. Silent tampering / repudiation
- **v2 defense:** every decision (pair, reject, rate-limit, execute, jail
  denial, capability denial, CLI approve/deny/grant) is appended to a
  hash-chained, HMAC-authenticated JSONL audit log. Appends are serialized
  across processes under a lockfile with the chain head re-read under the
  lock, so server and CLI entries interleave without forking the chain (an
  honest log never reports as "tampered"). `agent-bridge audit
  --verify` proves integrity. The HMAC key is not agent-readable (the
  install dir is denied). Honest limit: verification detects edits and gaps,
  not truncation of the newest entries.

### 10. Supply chain
- **v1 failure:** unpinned downloads; `kill -9` of whatever held the port;
  token printed to terminal and written to a plaintext info file.
- **v2 defense:** Node.js and cloudflared are version-pinned and SHA-256
  verified against hashes embedded in the installer (fail-closed on
  mismatch). A node/cloudflared already on PATH is used WITHOUT
  verification, with a loud warning - remove it from PATH to force the
  verified download. No sudo. No secrets in terminal output or info files.
  The uninstaller keeps workspace/trash/versions unless `--purge`.

## Known limitations (honest list)

- The tunnel URL is unguessable but not secret-proof; treat it as public.
  Security must not and does not depend on it.
- Quick tunnels move: on reconnect the URL changes. Re-pairing is NOT
  required (keys are URL-independent), but the agent needs the new URL.
- Approvals are CLI/notification-based; a user who approves everything
  reflexively defeats rule 5. The CLI shows the exact action - argv as a
  JSON array, control characters escaped - and asks for confirmation.
  Approved actions go stale after 10 minutes.
- The bridge does not defend against a compromised user account, a
  malicious kernel, or physical access.
