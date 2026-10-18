'use strict';
// In-memory sliding-window rate limiter, memory-bounded: empty windows are
// dropped and the keyspace is capped (an attacker rotating spoofed source
// headers cannot grow the map without bound).
const MAX_KEYS = 10000;

class RateLimiter {
  constructor() { this.hits = new Map(); } // key -> array of timestamps (insertion order)

  _prune(now, windowMs) {
    for (const [k, arr] of this.hits) {
      while (arr.length && arr[0] <= now - windowMs) arr.shift();
      if (!arr.length) this.hits.delete(k);
    }
    // Hard cap regardless of window: evict oldest-touched keys.
    while (this.hits.size > MAX_KEYS) this.hits.delete(this.hits.keys().next().value);
  }

  // Record one hit and tell whether it is within the limit.
  // Returns { allowed, retryAfterMs }
  check(key, limit, windowMs) {
    const now = Date.now();
    if ((this._n = (this._n || 0) + 1) % 64 === 0) this._prune(now, windowMs);
    let arr = this.hits.get(key);
    if (!arr) { arr = []; this.hits.set(key, arr); }
    const cutoff = now - windowMs;
    while (arr.length && arr[0] <= cutoff) arr.shift();
    if (arr.length >= limit) {
      return { allowed: false, retryAfterMs: arr[0] + windowMs - now };
    }
    arr.push(now);
    return { allowed: true, retryAfterMs: 0 };
  }

  // Record an event without a limit (for "count failures" bookkeeping).
  record(key, windowMs) { this.check(key, Number.MAX_SAFE_INTEGER, windowMs); }

  count(key, windowMs) {
    const arr = this.hits.get(key);
    if (!arr) return 0;
    const cutoff = Date.now() - windowMs;
    return arr.filter(t => t > cutoff).length;
  }
}
module.exports = { RateLimiter };
