'use strict';
// Simple in-memory sliding-window rate limiter.
class RateLimiter {
  constructor() { this.hits = new Map(); } // key -> array of timestamps
  // Returns { allowed, retryAfterMs }
  check(key, limit, windowMs) {
    const now = Date.now();
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
  count(key, windowMs) {
    const arr = this.hits.get(key) || [];
    const cutoff = Date.now() - windowMs;
    return arr.filter(t => t > cutoff).length;
  }
}
module.exports = { RateLimiter };
