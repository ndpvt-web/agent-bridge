'use strict';
// Append-only, hash-chained, HMAC-authenticated audit log.
// Every request decision is recorded. Tampering with any entry breaks the chain.
const fs = require('fs');
const crypto = require('crypto');

class AuditLog {
  constructor(filePath, hmacKey) {
    this.path = filePath;
    this.key = hmacKey;
    this.seq = 0;
    this.prev = '0'.repeat(64);
    // Resume from existing log
    try {
      const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
      if (lines.length) {
        const last = JSON.parse(lines[lines.length - 1]);
        this.seq = last.seq;
        this.prev = last.mac;
      }
    } catch {}
  }

  record(entry) {
    const e = {
      seq: this.seq + 1,
      ts: new Date().toISOString(),
      ...entry,
      prev: this.prev,
    };
    const mac = crypto.createHmac('sha256', this.key)
      .update(JSON.stringify(e)).digest('hex');
    e.mac = mac;
    fs.appendFileSync(this.path, JSON.stringify(e) + '\n', { mode: 0o600 });
    this.seq = e.seq;
    this.prev = mac;
    return e;
  }

  static verify(filePath, hmacKey) {
    const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
    let prev = '0'.repeat(64);
    for (let i = 0; i < lines.length; i++) {
      const e = JSON.parse(lines[i]);
      if (e.seq !== i + 1) return { ok: false, at: i, reason: 'sequence gap' };
      if (e.prev !== prev) return { ok: false, at: i, reason: 'chain break' };
      const { mac, ...rest } = e;
      const expect = crypto.createHmac('sha256', hmacKey).update(JSON.stringify(rest)).digest('hex');
      if (mac !== expect) return { ok: false, at: i, reason: 'hmac mismatch' };
      prev = mac;
    }
    return { ok: true, entries: lines.length };
  }
}
module.exports = { AuditLog };
