'use strict';
/*
 * AgentBridge server v2.0.0
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
 *  - On-device approval gate for irreversible or elevated operations.
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

const VERSION = '2.0.0';
const PROTOCOL_VERSION = '2025-06-18';

function startServer(installDir, opts = {}) {
  const cfg = loadConfig(installDir);
  const keystore = new KeyStore(path.join(installDir, 'secrets'));
  const approvals = new Approvals(path.join(installDir, 'approvals'));
  const audit = new AuditLog(path.join(installDir, 'logs', 'audit.jsonl'), keystore.auditKey());
  fs.mkdirSync(path.join(installDir, 'logs'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(cfg.workspace_root, { recursive: true, mode: 0o700 });
  const nonces = new NonceCache();
  const limiter = new RateLimiter();
  const bootTime = Date.now(); // timestamps older than boot are always rejected (nonce cache is in-memory)

  const readRoots = [cfg.workspace_root, ...(cfg.read_roots_extra || [])];

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
    // '[::1]:7899' -> '[::1]'; 'example.com:7899' -> 'example.com'
    host = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
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
      audit.record({ agent: null, tool: 'pair', decision: 'rate_limited', detail: ip });
      return json(res, 429, { error: 'too many failed pairing attempts', retry_after_ms: cfg.pair_rate_limit.window_ms });
    }
    let body;
    try { body = JSON.parse(await readBody(req, 4096)); }
    catch { return json(res, 400, { error: 'invalid JSON' }); }
    const code = body.pairing_code;
    const name = body.agent_name;
    const publicKey = body.public_key;
    // Names reach the human's terminal (CLI lists them): printable only, no
    // control characters - a forged "screen clear" is a social attack on
    // the approver.
    if (typeof code !== 'string' || typeof name !== 'string' || !name.trim() ||
        name.length > 80 || !/^[\x20-\x7E\u00A0-\uFFFF]+$/.test(name)) {
      return json(res, 400, { error: 'pairing_code and agent_name required (printable name, <= 80 chars)' });
    }
    if (typeof publicKey !== 'string' || Buffer.from(publicKey, 'base64url').length !== 32) {
      return json(res, 400, { error: 'public_key must be a base64url 32-byte Ed25519 public key' });
    }
    const consumed = keystore.consumePairingCode(code);
    if (!consumed) {
      limiter.check('pairfail:' + ip, 1000000, cfg.pair_rate_limit.window_ms); // record one failure (per-source)
      limiter.check('pairfail:*', 1000000, cfg.pair_rate_limit.window_ms);    // and one globally
      audit.record({ agent: null, tool: 'pair', decision: 'rejected', detail: 'bad or expired code from ' + ip });
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
  async function authenticate(req, rawBody, pathName) {
    const h = req.headers;
    if (h['x-bridge-request'] !== '1') return { error: [400, 'missing X-Bridge-Request header'] };
    if ((h['content-type'] || '') !== 'application/json') return { error: [415, 'Content-Type must be exactly application/json'] };
    const agentId = h['x-bridge-agent'];
    const ts = h['x-bridge-ts'];
    const nonce = h['x-bridge-nonce'];
    const sig = h['x-bridge-sign'];
    if (!agentId || !ts || !nonce || !sig) return { error: [401, 'missing auth headers'] };

    const agent = keystore.getAgent(agentId);
    if (!agent) return { error: [401, 'unknown agent'] };
    if (agent.revoked) return { error: [401, 'agent revoked'] };

    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 120000 || tsNum < bootTime - 120000) {
      return { error: [401, 'timestamp outside +/-120s window'] };
    }
    if (typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 128) {
      return { error: [401, 'bad nonce'] };
    }
    // Replay check WITHOUT recording: the nonce is burned only after the
    // signature verifies. Otherwise junk-signed requests could pre-burn a
    // victim's nonce (selective DoS) or flood the cache to evict a captured
    // nonce and replay the captured request. No await happens between the
    // check and the record, so check+set is atomic on the event loop.
    if (nonces.has(agentId, nonce)) return { error: [401, 'replay detected'] };

    const bodyHash = bodyHashHex(rawBody);
    const canonical = canonicalString({ agentId, ts, nonce, method: req.method, path: pathName, bodyHash });
    if (!verifySignature(agent.public_key, canonical, sig)) return { error: [401, 'bad signature'] };
    nonces.record(agentId, nonce);
    return { agent };
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
    const ctx = { cfg, agent, approvals, audit, keystore, readRoots, version: VERSION };

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
        const plan = tool.plan(ctx, args);
        const always = tool.approval !== 'conditional';
        if (always || plan.needsApproval) {
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
        const rawBody = await readBody(req, cfg.max_body_bytes);
        const auth = await authenticate(req, rawBody, pathName);
        if (auth.error) {
          // Throttle authentication failures: 30/min/source -> 429.
          const ip = clientIp(req);
          const n = limiter.count('authfail:' + ip, 60000);
          limiter.check('authfail:' + ip, 1000000, 60000); // record this failure
          if (n >= 30) return json(res, 429, { error: 'too many failed authentication attempts', retry_after_ms: 60000 });
          // Bounded forensics: an unauthenticated flood must not fill the
          // disk. First 10 failures per source per minute are logged in
          // full, then every 100th, always with the running count.
          if (n < 10 || n % 100 === 0) {
            audit.record({ agent: req.headers['x-bridge-agent'] || null, tool: 'auth', decision: 'rejected',
              detail: String(auth.error[1]).slice(0, 120) + ' [failures this minute: ' + (n + 1) + ']' });
          }
          return json(res, auth.error[0], { error: auth.error[1] });
        }
        keystore.touchAgent(auth.agent.id);
        return await handleMcp(req, res, auth.agent, rawBody);
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      if (e instanceof ToolError && e.code === 'too_large') return json(res, 413, { error: 'body too large' });
      return json(res, 500, { error: 'internal error' });
    }
  });

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
