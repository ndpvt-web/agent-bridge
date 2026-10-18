'use strict';
// On-device approval gate. Dangerous operations produce a pending approval;
// the human at the Mac approves or denies with the CLI. Default deny, TTL,
// single-use. State lives in a JSON file so the CLI process and the server
// process share it (atomic tmp+rename writes; server re-reads on each poll).
//
// Single-use is strict: once execution starts, the approval can never run
// again - a failed execution is 'consumed' with an error, not retryable
// (a retryable failure let an agent poll a content check repeatedly until
// it won a race).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { withLock } = require('./lockfile');

const APPROVAL_TTL_MS = 120 * 1000;
const MAX_PENDING = 100;   // backlog cap: an agent cannot flood the human
const MAX_PENDING_PER_AGENT = 25; // and one agent cannot starve the others
const TERMINAL_KEPT = 200; // forensic retention for decided records
const MAX_SUMMARY = 4000;  // the human reads the summary; never truncate it

class Approvals {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.path = path.join(dir, 'approvals.json');
    this.lockPath = path.join(dir, '.lock');
    this.snapshotsDir = path.join(dir, 'snapshots');
    this._pruneSnapshots();
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

  // Approval payloads may reference a frozen-file snapshot directory. Any
  // snapshot not referenced by an open record is garbage (its approval was
  // decided, expired, or pruned) and is removed.
  _pruneSnapshots() {
    let dirs;
    try { dirs = fs.readdirSync(this.snapshotsDir); } catch { return; }
    if (!dirs.length) return;
    const live = new Set();
    for (const a of this._read()) {
      if (['pending', 'approved', 'executing'].includes(a.status) && a.payload && a.payload.snapshot_id) {
        live.add(a.payload.snapshot_id);
      }
    }
    for (const d of dirs) {
      if (!live.has(d)) {
        try { fs.rmSync(path.join(this.snapshotsDir, d), { recursive: true, force: true }); } catch {}
      }
    }
  }

  // kind: 'shell' | 'process' | 'delete'
  // Locked like decide: a create racing a human decision must never
  // overwrite it.
  create({ kind, agentId, summary, payload, toolName }) {
    summary = String(summary);
    if (summary.length > MAX_SUMMARY) {
      // NEVER decide on a truncated description: refuse instead.
      const err = new Error('approval summary too long to show faithfully - shorten the command/argv');
      err.code = 'summary_too_long';
      throw err;
    }
    const a = {
      id: 'apr_' + crypto.randomBytes(9).toString('base64url'),
      kind, agent_id: agentId,
      summary,
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
      if (open.filter(x => isLivePending(x) && x.agent_id === agentId).length >= MAX_PENDING_PER_AGENT) {
        const err = new Error('too many pending approvals from this agent (' + MAX_PENDING_PER_AGENT + ') - let the human decide some first');
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

  // Server-side poll. Returns 'pending' | 'approved' | 'denied' | 'expired' |
  // 'executing' | 'consumed' | 'unknown'.
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
      if (a.status === 'denied') this._pruneSnapshots();
      return { ok: true };
    });
  }

  // Two-phase execution lifecycle: approved -> executing -> consumed.
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

  // error (optional): the execution failed; the record is still consumed.
  // Either way the approval can never execute again.
  finishExecution(id, error) {
    const r = this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a || a.status !== 'executing') return false;
      a.status = 'consumed';
      a.consumed_at = new Date().toISOString();
      if (error) a.execution_error = String(error).slice(0, 300);
      this._write(list);
      return true;
    });
    this._pruneSnapshots();
    return r;
  }

  expire(id) {
    const r = this._withLock(() => {
      const list = this._read();
      const a = list.find(x => x.id === id);
      if (!a) return false;
      a.status = 'expired';
      this._write(list);
      return true;
    });
    this._pruneSnapshots();
    return r;
  }
}
module.exports = { Approvals, APPROVAL_TTL_MS };
