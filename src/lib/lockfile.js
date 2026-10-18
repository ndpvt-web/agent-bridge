'use strict';
// Cross-process mutex via exclusive lockfile create, with pid-liveness:
// a lock whose holder process no longer exists is reclaimed immediately,
// so a crashed CLI never stalls the server for the full stale timeout.
const fs = require('fs');

function holderAlive(lockPath) {
  let pid;
  try { pid = Number(fs.readFileSync(lockPath, 'utf8').trim()); } catch { return null; }
  if (!Number.isInteger(pid) || pid <= 0) return null; // empty/unreadable: unknown, fall back to mtime
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code === 'EPERM'; } // exists, owned by someone else
}

function withLock(lockPath, fn, { timeoutMs = 5000, staleMs = 30000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let fd;
    try {
      fd = fs.openSync(lockPath, 'wx', 0o600);
      try { fs.writeSync(fd, String(process.pid)); } catch {}
    } catch (e) {
      if (e.code === 'EEXIST') {
        if (holderAlive(lockPath) === false) { try { fs.unlinkSync(lockPath); } catch {} continue; }
        try {
          const st = fs.statSync(lockPath);
          if (Date.now() - st.mtimeMs > staleMs) { try { fs.unlinkSync(lockPath); } catch {} continue; }
        } catch {}
        if (Date.now() > deadline) throw new Error('lock timeout: ' + lockPath);
        const until = Date.now() + 25;
        while (Date.now() < until) {} // brief spin; critical sections are tiny
        continue;
      }
      throw e;
    }
    try { return fn(); }
    finally { try { fs.closeSync(fd); } catch {} try { fs.unlinkSync(lockPath); } catch {} }
  }
}
module.exports = { withLock };
