# Security Policy

## Reporting a vulnerability

Do NOT open a public issue for security reports. Use GitHub's private
"Report a vulnerability" flow on the repository's Security tab.

Include: affected version, impact, reproduction steps, and whether the
attack requires (a) the tunnel URL, (b) a paired agent's private key,
(c) local access to the Mac, or (d) physical access.

## Scope notes

AgentBridge's security boundary assumes:
- The tunnel URL may be public. (Defended: signature auth, replay protection.)
- A paired agent may be compromised or prompt-injected. (Defended: capability
  scoping, filesystem jail, on-device approvals, revocation.)
- The Mac's user account is NOT compromised. A local process running as you
  can read the bridge's state directory; that is out of scope by design.

## Hardening recommendations

- Keep `enable_shell: false` (the default) unless you truly need it.
- Prefer the `workspace` profile; grant `developer` only to agents that build.
- Reads default to the workspace only. Adding your home directory as a read
  root (config.json) exposes everything in it to every paired agent - except
  the bridge's own state, which stays denied.
- Use `agent-bridge audit --verify` periodically to check log integrity.
- For a second identity layer, put a named Cloudflare Tunnel with Access
  (JWT verification) in front of the bridge.
