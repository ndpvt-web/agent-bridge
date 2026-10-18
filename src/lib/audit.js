'use strict';
// Append-only, hash-chained, HMAC-authenticated audit log.
// Every request decision is recorded. Tampering with any entry breaks the chain.
//
// Appends are serialized across processes with a lockfile, and the chain head
// is re-read from disk UNDER the lock: the server and every CLI invocation
// are separate processes, and interleaved appends from two in-memory chain
// heads would fork the chain (duplicate seq) and make an honest log verify
// as "tampered".
const fs = require('fs');
const crypto = require('crypto');
const { withLock } = require('./lockfile');

class AuditLog {
  constructor(filePath, hmacKey) {
    this.path = filePath;
    this.lockPath = filePath + '.lock';
    this.key = hmacKey;
    this.seq = 0;
    this.prev = '0'.repeat(64);
    this._readTail();
  }

  // Re-read the chain head (last entry) from disk. Only the tail is read:
  // entry size is bounded (summaries are capped), so 32KB always covers the
  // final complete line.
  _readTail() {
    try {
      const st = fs.statSync(this.path);
      if (st.size === 0) return;
      const fd = fs.openSync(this.path, 'r');
      try {
        const size = Math.min(st.size, 32768);
        const buf = Buffer.alloc(size);
        fs.readSync(fd, buf, 0, size, st.size - size);
        const s = buf.toString('utf8').replace(/\n+$/, '');
        const line = s.slice(s.lastIndexOf('\n') + 1);
        if (!line) return;
        const last = JSON.parse(line);
        if (Number.isInteger(last.seq) && typeof last.mac === 'string') {
          this.seq = last.seq;
          this.prev = last.mac;
        }
      } finally { fs.closeSync(fd); }
    } catch {}
  }

  record(entry) {
    return withLock(this.lockPath, () => {
      this._readTail(); // another process may have appended since our last write
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
    });
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
