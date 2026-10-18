'use strict';
// Credential store: pairing codes and paired agents.
// Only SHA-256 hashes of secrets are persisted. Secrets cross the wire once,
// during pairing, over the TLS tunnel.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { withLock } = require('./lockfile');

const PAIR_CODE_TTL_MS = 10 * 60 * 1000;   // pairing code valid 10 minutes
const MAX_PAIRING_CODES = 5;

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

class KeyStore {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dir, 0o700); } catch {}
    this.agentsPath = path.join(dir, 'agents.json');
    this.codesPath = path.join(dir, 'pairing-codes.json');
    this.auditKeyPath = path.join(dir, 'audit.key');
    this.lockPath = path.join(dir, '.lock');
  }

  // Cross-process mutex (shared lockfile helper, pid-liveness stale break):
  // server and CLI both mutate these files; an unlocked read-modify-write
  // can silently lose a revocation.
  _locked(fn) { return withLock(this.lockPath, fn); }

  _readJson(p, fallback) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
  }
  _writeJson(p, obj) {
    const tmp = p + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex');
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, p);
    try { fs.chmodSync(p, 0o600); } catch {}
  }

  // --- audit key (local only, never leaves the device) ---
  auditKey() {
    // Under the lock: a first concurrent start of CLI and server must not
    // generate two keys (the loser's entries would fail verification).
    return this._locked(() => {
      let k = null;
      try { k = fs.readFileSync(this.auditKeyPath, 'utf8').trim(); } catch {}
      if (!k || k.length < 32) {
        k = crypto.randomBytes(32).toString('hex');
        fs.writeFileSync(this.auditKeyPath, k, { mode: 0o600 });
      }
      return k;
    });
  }

  // --- pairing codes ---
  createPairingCode(profile) {
    return this._locked(() => this._createPairingCode(profile));
  }
  _createPairingCode(profile) {
    const codes = this._readJson(this.codesPath, []).filter(c => Date.now() < c.expires_at && !c.used);
    if (codes.length >= MAX_PAIRING_CODES) throw new Error('too many active pairing codes; revoke one first');
    // Human-transcribable: 4 groups of 4 base32 chars, Crockford-ish alphabet
    const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    // Rejection sampling: 248 = 8 * 31, so every alphabet char is exactly
    // equally likely (plain b % 31 would over-weight the first 8 chars).
    let raw = '';
    while (raw.length < 10) {
      const b = crypto.randomBytes(1)[0];
      if (b >= 248) continue;
      raw += alphabet[b % 31];
    }
    const code = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8);
    codes.push({
      code_sha256: sha256(code),
      profile: profile || 'workspace',
      created_at: new Date().toISOString(),
      expires_at: Date.now() + PAIR_CODE_TTL_MS,
      used: false,
    });
    this._writeJson(this.codesPath, codes);
    return code;
  }

  // Consume a pairing code. Returns {profile} or null.
  consumePairingCode(code) {
    return this._locked(() => this._consumePairingCode(code));
  }
  _consumePairingCode(code) {
    const norm = String(code || '').toUpperCase().trim();
    const codes = this._readJson(this.codesPath, []);
    const h = sha256(norm);
    const idx = codes.findIndex(c => {
      const a = Buffer.from(c.code_sha256, 'utf8'), b = Buffer.from(h, 'utf8');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    });
    if (idx === -1) return null;
    const c = codes[idx];
    if (c.used || Date.now() > c.expires_at) return null;
    c.used = true;
    this._writeJson(this.codesPath, codes);
    return { profile: c.profile || 'workspace' };
  }

  // --- agents ---
  listAgents() {
    return this._readJson(this.agentsPath, []).map(a => ({
      id: a.id, name: a.name, profile: a.profile, created_at: a.created_at,
      last_seen_at: a.last_seen_at || null, revoked: !!a.revoked,
    }));
  }

  addAgent(name, profile, publicKeyB64Url) {
    return this._locked(() => this._addAgent(name, profile, publicKeyB64Url));
  }
  _addAgent(name, profile, publicKeyB64Url) {
    const agents = this._readJson(this.agentsPath, []);
    const id = 'agt_' + crypto.randomBytes(9).toString('base64url');
    agents.push({
      id, name: String(name || 'agent').slice(0, 80), profile,
      public_key: publicKeyB64Url,
      allowed_programs: [],
      created_at: new Date().toISOString(), revoked: false,
    });
    this._writeJson(this.agentsPath, agents);
    return { id, profile };
  }

  getAgent(id) {
    return this._readJson(this.agentsPath, []).find(a => a.id === id) || null;
  }

  touchAgent(id) {
    // Throttled: at most one disk write per agent per 30 s.
    this._lastTouch = this._lastTouch || {};
    const now = Date.now();
    if (this._lastTouch[id] && now - this._lastTouch[id] < 30000) return;
    this._lastTouch[id] = now;
    this._locked(() => {
      const agents = this._readJson(this.agentsPath, []);
      const a = agents.find(x => x.id === id);
      if (a) { a.last_seen_at = new Date().toISOString(); this._writeJson(this.agentsPath, agents); }
    });
  }

  setProgramAllowed(id, program, allowed) {
    return this._locked(() => this._setProgramAllowed(id, program, allowed));
  }
  _setProgramAllowed(id, program, allowed) {
    const agents = this._readJson(this.agentsPath, []);
    const a = agents.find(x => x.id === id);
    if (!a) return false;
    a.allowed_programs = a.allowed_programs || [];
    const i = a.allowed_programs.indexOf(program);
    if (allowed && i === -1) a.allowed_programs.push(program);
    if (!allowed && i !== -1) a.allowed_programs.splice(i, 1);
    this._writeJson(this.agentsPath, agents);
    return true;
  }

  revokeAgent(id) {
    return this._locked(() => this._revokeAgent(id));
  }
  _revokeAgent(id) {
    const agents = this._readJson(this.agentsPath, []);
    const a = agents.find(x => x.id === id);
    if (!a) return false;
    a.revoked = true;
    this._writeJson(this.agentsPath, agents);
    return true;
  }
}

module.exports = { KeyStore, sha256 };
