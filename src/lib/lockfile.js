'use strict';
// Cross-process mutex via exclusive lockfile create, with pid-liveness:
// a lock whose holder process no longer exists is reclaimed immediately,
// so a crashed CLI never stalls the server for the full stale timeout.
const fs = require('fs');

function lockPid(lockPath) {
  const pid = Number(fs.readFileSync(lockPath, 'utf8').trim());
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

function holderAlive(lockPath) {
  let pid;
  try { pid = lockPid(lockPath); } catch { return null; }
  if (pid === null) return null; // empty/unreadable: unknown, fall back to mtime
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
        // Break a stale lock only after re-reading it: if the pid we saw is
        // gone from the file, someone already reclaimed it - leave theirs.
        try {
          const pid = lockPid(lockPath);
          if (holderAlive(lockPath) === false) {
            try { if (lockPid(lockPath) === pid) fs.unlinkSync(lockPath); } catch {}
            continue;
          }
        } catch { continue; } // lock vanished between checks: retry
        try {
          const st = fs.statSync(lockPath);
          if (Date.now() - st.mtimeMs > staleMs) {
            // Re-confirm the same stale file is still there before unlinking.
            const st2 = fs.statSync(lockPath);
            if (st2.ino === st.ino && st2.mtimeMs === st.mtimeMs) fs.unlinkSync(lockPath);
          }
        } catch {}
        continue;
        if (Date.now() > deadline) throw new Error('lock timeout: ' + lockPath);
        const until = Date.now() + 25;
        while (Date.now() < until) {} // brief spin; critical sections are tiny
        continue;
      }
      throw e;
    }
    try { return fn(); }
    finally {
      try { fs.closeSync(fd); } catch {}
      // Only unlink OUR lock: if it was stale-broken and re-taken, the file
      // now belongs to another holder.
      try { if (lockPid(lockPath) === process.pid) fs.unlinkSync(lockPath); } catch {}
    }
  }
}
module.exports = { withLock };
