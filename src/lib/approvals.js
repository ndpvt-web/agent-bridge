'use strict';
// On-device approval gate. Dangerous operations produce a pending approval;
// the human at the Mac approves or denies with the CLI. Default deny, TTL,
// single-use. State lives in a JSON file so the CLI process and the server
// process share it (atomic tmp+rename writes; server re-reads on each poll).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const APPROVAL_TTL_MS = 120 * 1000;

class Approvals {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.path = path.join(dir, 'approvals.json');
    this.lockPath = path.join(dir, '.lock');
  }

  // Cross-process mutex via exclusive lockfile create. Server and CLI run in
  // different processes; without this, two pollers could both consume the
  // same approval.
  _withLock(fn) {
    const deadline = Date.now() + 5000;
    for (;;) {
      let fd;
      try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
      catch (e) {
        if (e.code === 'EEXIST') {
          // Break stale locks older than 30s.
          try {
            const st = fs.statSync(this.lockPath);
            if (Date.now() - st.mtimeMs > 30000) { fs.unlinkSync(this.lockPath); continue; }
          } catch {}
          if (Date.now() > deadline) throw new Error('approval store locked');
          const until = Date.now() + 25;
          while (Date.now() < until) {} // brief spin; operations are tiny
          continue;
        }
        throw e;
      }
      try { return fn(); }
      finally { fs.closeSync(fd); try { fs.unlinkSync(this.lockPath); } catch {} }
    }
  }

  _read() { try { return JSON.parse(fs.readFileSync(this.path, 'utf8')); } catch { return []; } }
  _write(list) {
    const tmp = this.path + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.path);
    try { fs.chmodSync(this.path, 0o600); } catch {}
  }

  // kind: 'shell' | 'process' | 'delete' | 'write'
  create({ kind, agentId, summary, payload, toolName }) {
    const list = this._read().filter(a => a.status === 'pending' && Date.now() < a.expires_at);
    const a = {
      id: 'apr_' + crypto.randomBytes(9).toString('base64url'),
      kind, agent_id: agentId,
      summary: String(summary).slice(0, 500),
      payload, // planned action, executed only after approval
      tool_name: toolName || null,
      status: 'pending',
      created_at: new Date().toISOString(),
      expires_at: Date.now() + APPROVAL_TTL_MS,
    };
    list.push(a);
    this._write(list);
    this._notifyDesktop(a);
    return { id: a.id, expires_at: a.expires_at };
  }

  _notifyDesktop(a) {
    // Best-effort GUI notification on macOS; silently skipped headless/Linux.
    if (process.platform !== 'darwin') return;
    const script = `display notification "${a.kind} requested by ${a.agent_id} (approve in Terminal: agent-bridge approve ${a.id})" with title "AgentBridge approval needed"`;
    execFile('/usr/bin/osascript', ['-e', script], { timeout: 3000 }, () => {});
  }

  // Server-side poll. Returns 'pending' | 'approved' | 'denied' | 'expired' | 'unknown'
  status(id) {
    const a = this._read().find(x => x.id === id);
    if (!a) return { state: 'unknown' };
    if (a.status === 'pending' && Date.now() > a.expires_at) return { state: 'expired' };
    return { state: a.status, approval: a };
  }

  decide(id, decision) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a) return { ok: false, reason: 'unknown approval id' };
      if (a.status !== 'pending') return { ok: false, reason: 'already ' + a.status };
      if (Date.now() > a.expires_at) return { ok: false, reason: 'expired' };
      a.status = decision === 'approve' ? 'approved' : 'denied';
      a.decided_at = new Date().toISOString();
      this._write(list);
      return { ok: true };
    });
  }

  // Mark an approved approval as consumed so it can never be replayed.
  consume(id) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a || a.status !== 'approved') return false;
      a.status = 'consumed';
      a.consumed_at = new Date().toISOString();
      this._write(list);
      return true;
    });
  }
}
module.exports = { Approvals, APPROVAL_TTL_MS };
