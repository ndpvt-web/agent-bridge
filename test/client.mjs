// Test/attack client for AgentBridge: pairing + signed MCP calls.
import crypto from 'node:crypto';

export function generateAgentKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return {
    publicKeyB64Url: spki.subarray(spki.length - 32).toString('base64url'),
    privateSeedB64Url: pkcs8.subarray(pkcs8.length - 32).toString('base64url'),
  };
}

function signSeed(seedB64Url, msg) {
  const seed = Buffer.from(seedB64Url, 'base64url');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const key = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(msg, 'utf8'), key).toString('base64url');
}

export function canonical({ agentId, ts, nonce, method, path, bodyHash }) {
  return [agentId, ts, nonce, method.toUpperCase(), path, bodyHash].join('\n');
}

export class BridgeClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.keys = generateAgentKeypair();
    this.agentId = null;
  }

  async pair(code, name = 'test-agent', publicKeyOverride) {
    const res = await fetch(this.baseUrl + '/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Connection': 'close' },
      body: JSON.stringify({ pairing_code: code, agent_name: name, public_key: publicKeyOverride ?? this.keys.publicKeyB64Url }),
    });
    const data = await res.json();
    if (res.status === 200) this.agentId = data.agent_id;
    return { status: res.status, data };
  }

  signedHeaders(method, path, body, overrides = {}) {
    const ts = overrides.ts || String(Date.now());
    const nonce = overrides.nonce || crypto.randomBytes(16).toString('hex');
    const bodyHash = crypto.createHash('sha256').update(body || '').digest('hex');
    const canon = canonical({ agentId: this.agentId, ts, nonce, method, path, bodyHash });
    const seed = overrides.seed || this.keys.privateSeedB64Url;
    const sig = overrides.sig || signSeed(seed, canon);
    return {
      'Content-Type': 'application/json',
      'Connection': 'close',
      'X-Bridge-Request': '1',
      'X-Bridge-Agent': this.agentId,
      'X-Bridge-Ts': ts,
      'X-Bridge-Nonce': nonce,
      'X-Bridge-Sign': sig,
      ...overrides.extraHeaders,
    };
  }

  // Raw signed POST for tamper tests.
  async rawPost(path, body, overrides = {}) {
    const res = await fetch(this.baseUrl + path, {
      method: 'POST',
      headers: this.signedHeaders('POST', path, body, overrides),
      body,
    });
    return { status: res.status, data: await res.json().catch(() => null) };
  }

  async call(toolName, args = {}, overrides = {}) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: toolName, arguments: args } });
    const { status, data } = await this.rawPost('/mcp', body, overrides);
    return { status, rpc: data };
  }

  async rpc(method, params = {}, overrides = {}) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    return this.rawPost('/mcp', body, overrides);
  }
}
