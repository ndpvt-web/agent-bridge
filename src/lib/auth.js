'use strict';
// Request authentication: Ed25519 signatures. The agent's private key never
// leaves the agent; the bridge stores only public keys. A read of the
// secrets directory yields nothing that can authenticate.
// Canonical string: agentId \n ts \n nonce \n method \n path \n sha256hex(body)
const crypto = require('crypto');

const TS_WINDOW_MS = 120 * 1000;
const NONCE_TTL_MS = 10 * 60 * 1000;
const NONCE_CACHE_MAX = 20000;

class NonceCache {
  constructor() { this.map = new Map(); }
  seen(agentId, nonce) {
    const now = Date.now();
    let m = this.map.get(agentId);
    if (!m) { m = new Map(); this.map.set(agentId, m); }
    for (const [n, exp] of m) { if (exp <= now) m.delete(n); }
    if (m.has(nonce)) return true;
    if (m.size >= NONCE_CACHE_MAX) {
      const oldest = m.keys().next();
      if (!oldest.done) m.delete(oldest.value);
    }
    m.set(nonce, now + NONCE_TTL_MS);
    return false;
  }
}

function canonicalString({ agentId, ts, nonce, method, path, bodyHash }) {
  return [agentId, ts, nonce, String(method).toUpperCase(), path, bodyHash].join('\n');
}

function bodyHashHex(rawBody) {
  return crypto.createHash('sha256').update(rawBody || '').digest('hex');
}

// publicKeyB64Url: raw 32-byte Ed25519 public key, base64url
function verifySignature(publicKeyB64Url, canonical, signatureB64Url) {
  try {
    const rawPub = Buffer.from(publicKeyB64Url, 'base64url');
    if (rawPub.length !== 32) return false;
    // Wrap raw key into SPKI DER for Ed25519 (fixed 12-byte prefix).
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const keyObject = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, rawPub]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(canonical, 'utf8'), keyObject, Buffer.from(signatureB64Url, 'base64url'));
  } catch { return false; }
}

// Helpers for clients/tests: sign the same canonical string with a raw 32-byte
// Ed25519 private seed.
function signCanonical(privateSeedB64Url, canonical) {
  const seed = Buffer.from(privateSeedB64Url, 'base64url');
  if (seed.length !== 32) throw new Error('bad seed length');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const keyObject = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), keyObject).toString('base64url');
}

function generateAgentKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return {
    publicKeyB64Url: spki.subarray(spki.length - 32).toString('base64url'),
    privateSeedB64Url: pkcs8.subarray(pkcs8.length - 32).toString('base64url'),
  };
}

module.exports = { NonceCache, canonicalString, bodyHashHex, verifySignature, signCanonical, generateAgentKeypair, TS_WINDOW_MS };
