'use strict';
// On-device approval gate. Dangerous operations produce a pending approval;
// the human at the Mac approves or denies with the CLI. Default deny, TTL,
// single-use. State lives in a JSON file so the CLI process and the server
// process share it (atomic tmp+rename writes; server re-reads on each poll).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { withLock } = require('./lockfile');

const APPROVAL_TTL_MS = 120 * 1000;
const MAX_PENDING = 100;   // backlog cap: an agent cannot flood the human
const TERMINAL_KEPT = 200; // forensic retention for decided records

class Approvals {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.path = path.join(dir, 'approvals.json');
    this.lockPath = path.join(dir, '.lock');
  }

  // Cross-process mutex (shared lockfile helper, pid-liveness stale break).
  // Server and CLI run in different processes; without this, two pollers
  // could both consume the same approval.
  _withLock(fn) { return withLock(this.lockPath, fn); }

  _read() { try { return JSON.parse(fs.readFileSync(this.path, 'utf8')); } catch { return []; } }
  _write(list) {
    const tmp = this.path + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.path);
    try { fs.chmodSync(this.path, 0o600); } catch {}
  }

  // kind: 'shell' | 'process' | 'delete' | 'write'
  // Locked like decide/consume: a create racing a human decision must never
  // overwrite it.
  create({ kind, agentId, summary, payload, toolName }) {
    const a = {
      id: 'apr_' + crypto.randomBytes(9).toString('base64url'),
      kind, agent_id: agentId,
      // The human sees the summary; keep it faithful and complete enough to
      // decide on (bounded so the store stays small).
      summary: String(summary).slice(0, 4000),
      payload, // planned action, executed only after approval
      tool_name: toolName || null,
      status: 'pending',
      created_at: new Date().toISOString(),
      expires_at: Date.now() + APPROVAL_TTL_MS,
    };
    this._withLock(() => {
      const all = this._read();
      const now = Date.now();
      const isLivePending = x => x.status === 'pending' && now < x.expires_at;
      // NEVER drop an open record: live pendings, approved-but-unpolled, or
      // in-flight executions survive no matter how many later decisions land.
      // Only terminal records (denied, expired, consumed) are pruned, keeping
      // the most recent TERMINAL_KEPT for forensics.
      const isOpen = x => isLivePending(x) || x.status === 'approved' || x.status === 'executing';
      const open = all.filter(isOpen);
      if (open.filter(isLivePending).length >= MAX_PENDING) {
        const err = new Error('too many pending approvals (' + MAX_PENDING + ') - the human must decide some first');
        err.code = 'too_many_pending';
        throw err;
      }
      const terminal = all.filter(x => !isOpen(x)).slice(-TERMINAL_KEPT);
      this._write([...terminal, ...open, a]);
    });
    this._notifyDesktop(a);
    return { id: a.id, expires_at: a.expires_at };
  }

  _notifyDesktop(a) {
    // Best-effort GUI notification on macOS; silently skipped headless/Linux.
    // Text goes through osascript ARGV, never interpolated into the script,
    // so an agent-controlled summary cannot inject AppleScript.
    if (process.platform !== 'darwin') return;
    // Coalesce: at most one desktop notification per minute. The pending
    // list (`agent-bridge pending`) is the real review surface; a flood of
    // notifications is an approval-fatigue attack on the human gate.
    try {
      const sentinel = path.join(this.dir, '.last-notify');
      try { if (Date.now() - fs.statSync(sentinel).mtimeMs < 60000) return; } catch {}
      fs.writeFileSync(sentinel, String(Date.now()), { mode: 0o600 });
    } catch {}
    execFile('/usr/bin/osascript', [
      '-e', 'on run argv',
      '-e', 'display notification (item 1 of argv) with title (item 2 of argv)',
      '-e', 'end run',
      '--',
      `${a.kind} requested by ${a.agent_id}. Details: agent-bridge pending`,
      'AgentBridge approval needed',
    ], { timeout: 3000 }, () => {});
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

  // Two-phase execution lifecycle: approved -> executing -> consumed.
  // A failed execution returns to 'approved' so the agent can retry.
  beginExecution(id) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a || a.status !== 'approved') return false;
      a.status = 'executing';
      a.execution_started_at = new Date().toISOString();
      this._write(list);
      return true;
    });
  }

  finishExecution(id) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a || a.status !== 'executing') return false;
      a.status = 'consumed';
      a.consumed_at = new Date().toISOString();
      this._write(list);
      return true;
    });
  }

  failExecution(id) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a || a.status !== 'executing') return false;
      a.status = 'approved'; // retryable
      this._write(list);
      return true;
    });
  }

  expire(id) {
    return this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a) return false;
      a.status = 'expired';
      this._write(list);
      return true;
    });
  }

  // Backwards-compatible single-shot consume (kept for older call sites).
  consume(id) { return this.beginExecution(id) && this.finishExecution(id); }
}
module.exports = { Approvals, APPROVAL_TTL_MS };
