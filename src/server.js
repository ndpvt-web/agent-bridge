'use strict';
/*
 * AgentBridge server v2.1.0
 * Zero npm dependencies. Node.js built-ins only.
 *
 * Security model (see docs/threat-model.md):
 *  - Loopback-only bind; the tunnel carries remote traffic.
 *  - Pairing with one-time codes; Ed25519 public-key auth; every request is
 *    a signature over (agent, ts, nonce, method, path, body hash) with a
 *    timestamp window and nonce replay protection. No shared secrets
 *    stored anywhere: the bridge keeps only public keys.
 *  - Capability tools (MCP-style JSON-RPC), not a raw shell. Shell access is
 *    a separate install-time opt-in and every call needs on-device approval.
 *  - Filesystem jail with realpath symlink resolution; writes workspace-only.
 *  - On-device approval gate for irreversible or elevated operations; an
 *    approved command runs FROZEN COPIES of the workspace files it named.
 *  - Hash-chained, HMAC-authenticated audit log.
 *  - No CORS. Custom-header + exact content-type requirement defeats
 *    browser drive-by and DNS-rebinding requests.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { KeyStore } = require('./lib/keystore');
const { NonceCache, canonicalString, bodyHashHex, verifySignature } = require('./lib/auth');
const { RateLimiter } = require('./lib/ratelimit');
const { AuditLog } = require('./lib/audit');
const { Approvals } = require('./lib/approvals');
const { loadConfig, PROFILES } = require('./lib/config');
const { tools, ToolError, pendingResult } = require('./tools');

const VERSION = '2.1.0';
const PROTOCOL_VERSION = '2025-06-18';

function startServer(installDir, opts = {}) {
  const cfg = loadConfig(installDir);
  const keystore = new KeyStore(path.join(installDir, 'secrets'));
  const approvals = new Approvals(path.join(installDir, 'approvals'));
  const audit = new AuditLog(path.join(installDir, 'logs', 'audit.jsonl'), keystore.auditKey(), { maxBytes: cfg.audit_max_bytes });
  fs.mkdirSync(path.join(installDir, 'logs'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(cfg.workspace_root, { recursive: true, mode: 0o700 });
  const nonces = new NonceCache();
  const limiter = new RateLimiter();
  const bootTime = Date.now(); // timestamps older than boot are always rejected (nonce cache is in-memory)

  // One policy object, built at startup: no per-tool fullMode branches.
  const fullMode = cfg.mode === 'full';
  const denyBridgeState = { installDir: cfg.install_dir, workspaceRoot: cfg.workspace_root };
  const policy = fullMode
    ? { fullMode: true, readRoots: ['/'], readOpts: denyBridgeState, writeRoots: ['/'], writeOpts: denyBridgeState }
    : {
        fullMode: false,
        readRoots: [cfg.workspace_root, ...(cfg.read_roots_extra || [])],
        readOpts: denyBridgeState,
        writeRoots: [cfg.workspace_root],
        writeOpts: denyBridgeState,
      };
  if (fullMode) {
    console.warn('[agent-bridge] *** FULL PERMISSION MODE: no jail, no approvals, shell enabled. Every paired agent with process rights has full control of this account (bridge state stays denied). Switch back: agent-bridge mode limited ***');
  }
  audit.record({ agent: null, tool: 'server', decision: 'started', detail: 'mode=' + cfg.mode });
  // The running mode, for the CLI to show (config edits need a restart).
  try {
    fs.mkdirSync(path.join(installDir, 'run'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(installDir, 'run', 'server-info.json'),
      JSON.stringify({ pid: process.pid, mode: cfg.mode, version: VERSION, started_at: new Date().toISOString() }), { mode: 0o600 });
  } catch {}

  function json(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      // Deliberately NO Access-Control-Allow-Origin: browsers get nothing.
    });
    res.end(body);
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0, over = false;
      req.on('data', c => {
        if (over) return; // draining
        size += c.length;
        if (size > limit) {
          over = true;
          reject(new ToolError('too_large', 'body too large'));
          return; // keep consuming to drain the socket cleanly
        }
        chunks.push(c);
      });
      req.on('end', () => { if (!over) resolve(Buffer.concat(chunks).toString('utf8')); });
      req.on('error', (e) => { if (!over) reject(e); });
    });
  }

  function hostAllowed(req) {
    let host = (req.headers.host || '').toLowerCase();
    // '[::1]:7899' -> '[::1]'; 'example.com:7899' -> 'example.com'.
    // Strict: after ']', only :port may follow - '[::1]evil.example' is junk.
    if (host.startsWith('[')) {
      const close = host.indexOf(']');
      if (close === -1) return false;
      const rest = host.slice(close + 1);
      if (rest !== '' && !/^:\d+$/.test(rest)) return false;
      host = host.slice(0, close + 1);
    } else {
      host = host.split(':')[0];
    }
    if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return true;
    return (cfg.tunnel_host_suffixes || []).some(s => host.endsWith(s));
  }

  // Real client key for rate limiting. Behind cloudflared everything arrives
  // from loopback and the true source is CF-Connecting-IP (Cloudflare's edge
  // overwrites it). Trusted ONLY from a loopback peer - and even then it only
  // refines the bucket; a GLOBAL bucket bounds total failures, so a direct
  // local client spoofing the header cannot reset its attempt budget.
  function clientIp(req) {
    const ra = req.socket.remoteAddress || 'unknown';
    const loop = ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
    const cf = loop ? req.headers['cf-connecting-ip'] : null;
    return Array.isArray(cf) ? String(cf[0]) : (cf ? String(cf) : ra);
  }

  function noteAuthFailure(req, reason) {
    // Throttle authentication failures: 30/min/source AND 300/min
    // global (a loopback client rotating CF-Connecting-IP cannot reset
    // its budget). Returns true when the caller should answer 429.
    const ip = clientIp(req);
    const n = limiter.count('authfail:' + ip, 60000);
    const g = limiter.count('authfail:*', 60000);
    limiter.record('authfail:' + ip, 60000);
    limiter.record('authfail:*', 60000);
    // Bounded forensics keyed GLOBALLY: an unauthenticated flood must
    // not fill the disk no matter how source headers rotate. First 10
    // failures per minute are logged in full, then every 100th, always
    // with the running count.
    if (g < 10 || g % 100 === 0) {
      audit.record({ agent: req.headers['x-bridge-agent'] || null, tool: 'auth', decision: 'rejected',
        detail: String(reason).slice(0, 120) + ' [failures this minute: ' + (g + 1) + ']' });
    }
    return n >= 30 || g >= 300;
  }

  // --- /pair ---
  async function handlePair(req, res, ip) {
    // Same drive-by hardening as /mcp: a cross-origin browser POST cannot
    // send a custom header or an exact JSON content-type without a
    // preflight, and no preflight is ever answered.
    if (req.headers['x-bridge-request'] !== '1') return json(res, 400, { error: 'missing X-Bridge-Request header' });
    if ((req.headers['content-type'] || '') !== 'application/json') return json(res, 415, { error: 'Content-Type must be exactly application/json' });
    // Rate limit FAILED attempts only, in TWO buckets: per-source AND
    // global. The per-source key can be refined by a loopback-trusted
    // CF-Connecting-IP header; the global bucket cannot be spoofed, so the
    // total attempt budget holds no matter what headers arrive.
    const perSource = limiter.count('pairfail:' + ip, cfg.pair_rate_limit.window_ms);
    const globalN = limiter.count('pairfail:*', cfg.pair_rate_limit.window_ms);
    if (perSource >= cfg.pair_rate_limit.attempts || globalN >= cfg.pair_rate_limit.attempts * 10) {
      // Log only the first rate-limited attempt per window: a flood must not
      // convert throttled RESPONSES into unbounded audit WRITES.
      if (globalN === cfg.pair_rate_limit.attempts * 10) {
        audit.record({ agent: null, tool: 'pair', decision: 'rate_limited', detail: 'global threshold hit' });
      }
      return json(res, 429, { error: 'too many failed pairing attempts', retry_after_ms: cfg.pair_rate_limit.window_ms });
    }
    let body;
    try {
      body = JSON.parse(await readBody(req, 4096));
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('bad body');
    }
    catch { return json(res, 400, { error: 'invalid JSON body' }); }
    const code = body.pairing_code;
    const name = body.agent_name;
    const publicKey = body.public_key;
    // Names reach the human's terminal. Block control chars AND Unicode
    // format characters (bidi overrides, zero-width, U+2028/9): a name that
    // visually reorders or hides text is a social attack on the approver.
    if (typeof code !== 'string' || typeof name !== 'string' || !name.trim() ||
        name.length > 80 || !/^[\x20-\x7E\u00A0-\uFFFF]+$/.test(name) ||
        /[\p{Cf}\u2028\u2029]/u.test(name)) {
      return json(res, 400, { error: 'pairing_code and agent_name required (printable name, <= 80 chars, no format characters)' });
    }
    if (typeof publicKey !== 'string' || Buffer.from(publicKey, 'base64url').length !== 32) {
      return json(res, 400, { error: 'public_key must be a base64url 32-byte Ed25519 public key' });
    }
    const consumed = keystore.consumePairingCode(code);
    if (!consumed) {
      limiter.record('pairfail:' + ip, cfg.pair_rate_limit.window_ms);
      const g = limiter.count('pairfail:*', cfg.pair_rate_limit.window_ms);
      limiter.record('pairfail:*', cfg.pair_rate_limit.window_ms);
      // Bounded forensics: first 10 failures per window in full, then every 100th.
      if (g < 10 || g % 100 === 0) {
        audit.record({ agent: null, tool: 'pair', decision: 'rejected', detail: 'bad or expired code from ' + ip + ' [failures this window: ' + (g + 1) + ']' });
      }
      return json(res, 403, { error: 'invalid, used, or expired pairing code' });
    }
    if (!PROFILES[consumed.profile]) consumed.profile = 'workspace';
    const agent = keystore.addAgent(name, consumed.profile, publicKey);
    audit.record({ agent: agent.id, tool: 'pair', decision: 'paired', detail: name + ' (' + consumed.profile + ')' });
    return json(res, 200, {
      agent_id: agent.id,
      profile: agent.profile,
      protocol: { transport: 'POST /mcp', jsonrpc: '2.0', mcp_version: PROTOCOL_VERSION },
      signing: 'X-Bridge-Sign = base64url Ed25519 signature of: agentId\\n unixMs\\n nonce\\n METHOD\\n path\\n sha256hex(body)',
    });
  }

  // --- authenticated request pipeline ---
  // Header-only checks run BEFORE the body is read, so junk requests do not
  // get to buffer megabytes first. The signature itself needs the body.
  function authenticateHeaders(req) {
    const h = req.headers;
    if (h['x-bridge-request'] !== '1') return [400, 'missing X-Bridge-Request header'];
    if ((h['content-type'] || '') !== 'application/json') return [415, 'Content-Type must be exactly application/json'];
    const agentId = h['x-bridge-agent'];
    const ts = h['x-bridge-ts'];
    const nonce = h['x-bridge-nonce'];
    const sig = h['x-bridge-sign'];
    if (!agentId || !ts || !nonce || !sig) return [401, 'missing auth headers'];
    if (typeof sig !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(sig)) return [401, 'bad signature shape'];
    const agent = keystore.getAgent(agentId);
    if (!agent) return [401, 'unknown agent'];
    if (agent.revoked) return [401, 'agent revoked'];
    const tsNum = Number(ts);
    // Strict: nothing signed before this process booted. The nonce cache is
    // in-memory, so accepting pre-boot timestamps re-opens replay across a
    // restart.
    if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 120000 || tsNum < bootTime) {
      return [401, 'timestamp outside +/-120s window'];
    }
    if (typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 128) {
      return [401, 'bad nonce'];
    }
    // Replay check WITHOUT recording: the nonce is burned only after the
    // signature verifies (see below). Otherwise junk-signed requests could
    // pre-burn a victim's nonce (selective DoS) or flood the cache to evict
    // a captured nonce and replay the captured request.
    if (nonces.has(agentId, nonce)) return [401, 'replay detected'];
    return null; // headers OK
  }

  function authenticateBody(req, rawBody, pathName, agentId, ts, nonce, sig, agent) {
    // Replay check again: the earlier header check raced ahead of an awaited
    // body read, so the check and the record must happen HERE, with no await
    // between them (atomic on the event loop).
    if (nonces.has(agentId, nonce)) return [401, 'replay detected'];
    const bodyHash = bodyHashHex(rawBody);
    const canonical = canonicalString({ agentId, ts, nonce, method: req.method, path: pathName, bodyHash });
    if (!verifySignature(agent.public_key, canonical, sig)) return [401, 'bad signature'];
    nonces.record(agentId, nonce);
    return null;
  }

  // --- JSON-RPC / MCP dispatch ---
  async function handleMcp(req, res, agent, rawBody) {
    let rpc;
    try { rpc = JSON.parse(rawBody); }
    catch { return json(res, 200, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
    const id = rpc.id === undefined ? null : rpc.id;
    const reply = (result) => json(res, 200, { jsonrpc: '2.0', id, result });
    const fail = (code, message, data) => json(res, 200, { jsonrpc: '2.0', id, error: { code, message, data } });

    const rl = limiter.check('mcp:' + agent.id, cfg.rate_limit_per_minute, 60000);
    if (!rl.allowed) return fail(-32029, 'rate limited', { retry_after_ms: rl.retryAfterMs });

    const method = rpc.method;
    const ctx = { cfg, agent, approvals, audit, keystore, version: VERSION, policy };

    if (method === 'initialize') {
      return reply({
        // Always the server's real version: echoing the client's claim is
        // how version-confusion downgrades start.
        protocolVersion: PROTOCOL_VERSION,
        serverInfo: { name: 'agent-bridge', version: VERSION },
        capabilities: { tools: {} },
      });
    }
    if (method === 'tools/list') {
      const caps = Object.entries(tools).map(([name, t]) => ({
        name, description: t.description, inputSchema: t.schema,
      }));
      return reply({ tools: caps });
    }
    if (method === 'tools/call') {
      const params = rpc.params || {};
      const name = params.name;
      const args = params.arguments || {};
      const tool = (typeof name === 'string' && Object.hasOwn(tools, name)) ? tools[name] : undefined;
      if (!tool) return fail(-32602, 'unknown tool: ' + name);
      if (typeof args !== 'object' || args === null || Array.isArray(args)) {
        return fail(-32602, 'arguments must be an object');
      }
      try {
        if (tool.approval === false) {
          const result = await tool.run(ctx, args);
          audit.record({ agent: agent.id, tool: name, decision: 'executed' });
          return reply({ content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], structuredContent: result });
        }
        const plan = await tool.plan(ctx, args);
        const always = tool.approval !== 'conditional';
        if (!policy.fullMode && (always || plan.needsApproval)) {
          const kind = tool.approval === 'conditional' ? 'process' : tool.approval;
          const result = pendingResult(ctx, kind, name, plan.summary, plan.payload);
          return reply({ content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], structuredContent: result });
        }
        const result = await tool.execute(ctx, plan.payload);
        return reply({ content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], structuredContent: result });
      } catch (e) {
        if (e instanceof ToolError) {
          audit.record({ agent: agent.id, tool: name, decision: 'rejected', detail: (e.code + ': ' + e.message).slice(0, 200) });
          return fail(-32000, e.code + ': ' + e.message);
        }
        if (e && e.code === 'EJAIL') {
          audit.record({ agent: agent.id, tool: name, decision: 'jail_denied', detail: String(e.message).slice(0, 200) });
          return fail(-32000, 'forbidden: ' + e.message);
        }
        audit.record({ agent: agent.id, tool: name, decision: 'internal_error', detail: String(e && e.message).slice(0, 120) });
        return fail(-32603, 'internal error');
      }
    }
    if (typeof method === 'string' && method.startsWith('notifications/')) {
      res.writeHead(202, { 'Content-Type': 'application/json' });
      return res.end('{}');
    }
    return fail(-32601, 'method not found: ' + method);
  }

  const server = http.createServer(async (req, res) => {
    const pathName = req.url.split('?')[0];
    try {
      if (!hostAllowed(req)) return json(res, 421, { error: 'host not allowed' });

      if (req.method === 'GET' && pathName === '/health') {
        return json(res, 200, { status: 'ok' }); // minimal by design
      }
      if (req.method === 'POST' && pathName === '/pair') {
        return await handlePair(req, res, clientIp(req));
      }
      if (req.method === 'POST' && pathName === '/mcp') {
        // Cheap header checks BEFORE buffering the body.
        const hdrErr = authenticateHeaders(req);
        if (hdrErr) {
          if (noteAuthFailure(req, hdrErr[1])) return json(res, 429, { error: 'too many failed authentication attempts', retry_after_ms: 60000 });
          return json(res, hdrErr[0], { error: hdrErr[1] });
        }
        const rawBody = await readBody(req, cfg.max_body_bytes);
        const h = req.headers;
        const agent = keystore.getAgent(h['x-bridge-agent']);
        const sigErr = authenticateBody(req, rawBody, pathName, h['x-bridge-agent'], h['x-bridge-ts'], h['x-bridge-nonce'], h['x-bridge-sign'], agent);
        if (sigErr) {
          if (noteAuthFailure(req, sigErr[1])) return json(res, 429, { error: 'too many failed authentication attempts', retry_after_ms: 60000 });
          return json(res, sigErr[0], { error: sigErr[1] });
        }
        keystore.touchAgent(agent.id);
        return await handleMcp(req, res, agent, rawBody);
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      if (e instanceof ToolError && e.code === 'too_large') return json(res, 413, { error: 'body too large' });
      return json(res, 500, { error: 'internal error' });
    }
  });
  // Bound concurrent connections: buffered request bodies cost memory each.
  server.maxConnections = 64;

  const bind = opts.bind || cfg.bind || '127.0.0.1';
  const port = opts.port || cfg.port;
  return new Promise((resolve) => {
    server.listen(port, bind, () => {
      const addr = server.address();
      resolve({ server, cfg, keystore, approvals, audit, port: addr.port, bind: addr.address, version: VERSION });
    });
  });
}

module.exports = { startServer, VERSION };

if (require.main === module) {
  const installDir = process.env.AGENT_BRIDGE_HOME || path.join(require('os').homedir(), 'agent-bridge');
  startServer(installDir).then(({ port, bind }) => {
    console.log(`[agent-bridge] v${VERSION} listening on http://${bind}:${port} (loopback only)`);
    console.log('[agent-bridge] pair an agent: agent-bridge pair');
  });
}
