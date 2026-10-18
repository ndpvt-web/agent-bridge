'use strict';
// Tool implementations. Every tool receives a context { cfg, agent, approvals,
// audit, keystore, policy, version } and a validated argument object. Tools
// return plain data or throw ToolError { code, message }.
//
// policy is built ONCE at server start:
//   { fullMode, readRoots, readOpts, writeRoots, writeOpts }
// FULL mode: roots collapse to '/', but the bridge's own install dir stays
// denied and profiles still apply. LIMITED: workspace jail + install-dir deny.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { JailError, resolveInRoots, assertRegularFileOrDir, safeOpen, realpathOrSelf, insideRoot } = require('../lib/jail');
const { PROFILES, PROGRAM_GRAMMARS, scrubbedEnv } = require('../lib/config');

class ToolError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const MAX_LIST_ENTRIES = 5000;
const MAX_OUTPUT_BYTES = 1024 * 1024;

// --- per-program argument grammar engine (deny by default) ---
// Any flag not explicitly listed, any joined long form, any path outside the
// workspace jail => not auto-allowed => on-device approval required.
// Returns a REWRITTEN argv (jailed positionals replaced by their real paths,
// so a `dirlink/../x` trick resolves the way the kernel resolves it), or null.
function validateValue(type, v) {
  if (typeof v !== 'string') return false;
  switch (type) {
    case 'int': return /^[0-9]{1,10}$/.test(v);
    case 'text': return v.length <= 512 && !v.includes('\0');
    default: return false;
  }
}

function grammarRun(argv, grammar, cwd, workspaceRoot) {
  const flags = new Set(grammar.flags || []);
  const valueFlags = grammar.valueFlags || {};
  const longFlags = new Set(grammar.longFlags || []);
  const patternFlags = new Set(grammar.patternFlags || []);
  const maxArgs = grammar.maxArgs === undefined ? 16 : grammar.maxArgs;
  if (argv.length - 1 > maxArgs) return null;
  let endOfFlags = false;
  let patternSeen = false;
  const positionals = []; // { tok, idx }
  let i = 1;
  // PASS 1: parse flags, collect positionals. Whether the pattern came from
  // a flag (grep -e) decides what the positionals ARE, so classification
  // happens in pass 2 with the full picture - a pattern flag appearing
  // after a positional still turns that positional into a file operand.
  while (i < argv.length) {
    const tok = argv[i];
    if (!endOfFlags && tok === '--') { endOfFlags = true; i++; continue; }
    if (!endOfFlags && grammar.plusArgs && tok.startsWith('+') && tok.length > 1 && tok.length <= 512) { i++; continue; }
    if (!endOfFlags && tok.startsWith('--')) {
      if (tok.includes('=')) return null; // joined long values are never auto-allowed
      if (longFlags.has(tok)) { i++; continue; }
      if (patternFlags.has(tok)) patternSeen = true;
      const vt = valueFlags[tok];
      if (vt) {
        const v = argv[i + 1];
        if (v === undefined || !validateValue(vt, v)) return null;
        i += 2; continue;
      }
      return null;
    }
    if (!endOfFlags && tok.startsWith('-') && tok !== '-') {
      const chars = tok.slice(1);
      if (chars.length === 0) return null;
      let j = 0;
      while (j < chars.length) {
        const f = '-' + chars[j];
        if (patternFlags.has(f)) patternSeen = true;
        if (flags.has(f)) { j++; continue; }
        const vt = valueFlags[f];
        if (vt) {
          const joined = chars.slice(j + 1);
          if (joined) { if (!validateValue(vt, joined)) return null; }
          else {
            const v = argv[i + 1];
            if (v === undefined || !validateValue(vt, v)) return null;
            i++;
          }
          j = chars.length;
          break;
        }
        return null;
      }
      i++; continue;
    }
    positionals.push({ tok, idx: i });
    i++;
  }
  // PASS 2: classify positionals and rewrite file operands to real paths.
  const out = argv.slice();
  for (let n = 0; n < positionals.length; n++) {
    const { tok, idx } = positionals[n];
    let kind;
    if (patternSeen) kind = 'jailed';
    else if (n === 0 && grammar.firstPositional === 'any') kind = 'any';
    else if (grammar.pathArgs === 'any') kind = 'any';
    else if (grammar.pathArgs === 'none') kind = 'none';
    else kind = 'jailed';
    if (kind === 'none') return null;
    if (kind === 'jailed') {
      // Resolve the way the KERNEL will: realpath of the raw operand (must
      // exist - read tools are useless on a missing file anyway, so a
      // missing operand simply falls through to on-device approval).
      let real;
      try { real = fs.realpathSync.native(path.resolve(cwd, tok)); } catch { return null; }
      if (!insideRoot(real, realpathOrSelf(workspaceRoot))) return null;
      if (grammar.filesOnly) {
        const st = fs.lstatSync(real);
        if (!st.isFile() || st.isSymbolicLink()) return null;
      }
      out[idx] = real;
    }
  }
  return out;
}

// --- frozen snapshots (approval content binding, done right) ---
// Approving a process.run copies every named workspace file into a private
// dir under the install dir (invisible to agents), plus the sibling files of
// each named file so script-relative imports still resolve. The EXECUTION
// runs the copies: the approved content is exactly what runs, with no
// re-check to race and no post-approval rewrite window at all.
const MAX_FREEZE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_FREEZE_TOTAL_BYTES = 128 * 1024 * 1024;
const MAX_CONTEXT_FILES = 256;
const MAX_CONTEXT_BYTES = 32 * 1024 * 1024;
const CONTEXT_SKIP_DIRS = new Set(['node_modules', '.git']);

function freezeContext(dir, ws, snapshotDir, budget) {
  const walk = (d) => {
    if (budget.files >= MAX_CONTEXT_FILES || budget.bytes >= MAX_CONTEXT_BYTES) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (budget.files >= MAX_CONTEXT_FILES || budget.bytes >= MAX_CONTEXT_BYTES) return;
      const full = path.join(d, e.name);
      if (e.isDirectory()) { if (!CONTEXT_SKIP_DIRS.has(e.name)) walk(full); continue; }
      if (!e.isFile() || e.isSymbolicLink()) continue;
      const rel = path.relative(ws, full);
      if (rel.startsWith('..') || path.isAbsolute(rel)) continue;
      const dest = path.join(snapshotDir, rel);
      if (fs.existsSync(dest)) continue; // a named file already froze this path
      try {
        const st = fs.lstatSync(full);
        if (st.size > 4 * 1024 * 1024) continue;
        fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
        fs.copyFileSync(full, dest);
        fs.chmodSync(dest, st.mode & 0o777);
        budget.files++; budget.bytes += st.size;
      } catch {}
    }
  };
  walk(dir);
}

// Classify every argv operand; freeze named workspace files into a snapshot.
// Returns { rewrite, frozen, contextCount, snapshotId, snapshotDir }.
// Throws ToolError when the plan must be refused.
function freezeArgvFiles(argv, cwd, cfg) {
  const ws = realpathOrSelf(cfg.workspace_root);
  const named = []; // { idx, real, rel, size }
  for (let k = 0; k < argv.length; k++) {
    const a = argv[k];
    if (a.startsWith('-')) continue; // flag: approved as text
    if (k === 0 && !a.includes('/')) continue; // bare program name: resolved via the scrubbed PATH
    if (a.startsWith('~')) {
      throw new ToolError('invalid_params', "'~' is not expanded for process operands - use an absolute or workspace-relative path: " + a.slice(0, 80));
    }
    // The operand right after a '-'-flag is that flag's VALUE (code for
    // -e/-c, a pattern, a name) - its text is already fully visible in the
    // approval summary, so it is never a missing path to bind. (An existing
    // workspace file in that slot is still frozen below.)
    const flagValue = k > 0 && argv[k - 1].startsWith('-');
    // A component over NAME_MAX (255) can never exist as a file, so it is
    // never a legit path operand - refuse it cleanly instead of walking.
    if (!flagValue && a.split('/').some(seg => seg.length > 255)) {
      throw new ToolError('unbindable', 'cannot approve: path component longer than 255 chars');
    }
    let real;
    try { real = resolveInRoots(a, [ws], cwd).real; } catch { continue; } // not a workspace operand: approved as text
    let st;
    try { st = fs.lstatSync(real); } catch (e) {
      if (e && e.code === 'ENOENT') {
        // A path-intended operand that does not exist yet must NOT be
        // approved: the human would approve content they never saw (the
        // agent writes it after approval). Path-intended = contains '/', or
        // carries a plausible file extension (so `node -e 'code...'`,
        // subcommands and make targets stay plain text).
        if (!flagValue && (a.includes('/') || /^\.[A-Za-z0-9]{1,10}$/.test(path.extname(a)))) {
          throw new ToolError('unbindable', 'cannot approve: ' + a + ' does not exist yet inside the workspace - create it first, then request approval');
        }
        continue; // bare word (subcommand, make target or flag value): approved as text
      }
      throw new ToolError('unbindable', 'cannot approve: ' + a.slice(0, 120) + ' is not a readable file (' + (e && e.code || 'error') + ')');
    }
    if (st.isSymbolicLink()) throw new ToolError('unbindable', 'cannot approve a symlinked program/input: ' + a);
    if (!st.isFile()) continue; // directory operand (e.g. `ls .`): approved as text
    if (st.size > MAX_FREEZE_FILE_BYTES) throw new ToolError('unbindable', 'file too large to freeze: ' + a);
    named.push({ idx: k, real, rel: path.relative(ws, real), size: st.size });
  }
  if (!named.length) return { rewrite: {}, frozen: [], contextCount: 0, snapshotId: null, snapshotDir: null };
  if (named.reduce((n, f) => n + f.size, 0) > MAX_FREEZE_TOTAL_BYTES) {
    throw new ToolError('unbindable', 'named files too large to freeze in total - request approval for fewer/smaller files');
  }
  const snapshotId = 'snap_' + crypto.randomBytes(9).toString('base64url');
  const snapshotDir = path.join(cfg.install_dir, 'approvals', 'snapshots', snapshotId);
  const rewrite = {};
  const frozen = [];
  const budget = { files: 0, bytes: 0 }; // sibling-context copy budget
  try {
    for (const f of named) {
      const dest = path.join(snapshotDir, f.rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
      fs.copyFileSync(f.real, dest);
      fs.chmodSync(dest, fs.lstatSync(f.real).mode & 0o777);
      rewrite[f.idx] = dest;
      frozen.push({ operand: argv[f.idx], real: f.real, size: f.size });
    }
    // Sibling files of each named file (bounded, symlinks skipped), so a
    // frozen script's relative imports resolve inside the frozen tree.
    const dirs = new Set(named.map(f => path.dirname(f.real)));
    for (const d of dirs) freezeContext(d, ws, snapshotDir, budget);
    // Tear check for the NAMED files: the copy must match the source as
    // re-read now; a mid-copy write means the content was in flux.
    for (const f of named) {
      const dest = path.join(snapshotDir, f.rel);
      const srcHash = crypto.createHash('sha256').update(fs.readFileSync(f.real)).digest('hex');
      const dstHash = crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex');
      if (srcHash !== dstHash) {
        throw new ToolError('changed', argv[f.idx] + ' was being written while planning - try again');
      }
    }
  } catch (e) {
    try { fs.rmSync(snapshotDir, { recursive: true, force: true }); } catch {}
    throw e;
  }
  return { rewrite, frozen, contextCount: budget.files, snapshotId, snapshotDir };
}

// --- process spawn with output capture ---
// Resolves on 'exit' (process death), not 'close' (stdio drained): a
// backgrounded grandchild holding the pipe cannot stall the request.
// The timeout kills the whole process GROUP (detached spawn), not just the
// direct child.
function spawnCaptured({ argv0, args, cwd, env, timeout }) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(argv0, args, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    } catch (e) { resolve({ started: false, error: e.message }); return; }
    let out = Buffer.alloc(0), err = Buffer.alloc(0), timedOut = false, settled = false;
    const killGroup = (sig) => {
      try { process.kill(-child.pid, sig); } catch { try { child.kill(sig); } catch {} }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup('SIGTERM');
      setTimeout(() => killGroup('SIGKILL'), 2000).unref();
    }, timeout);
    const cap = (acc, chunk) => acc.length < MAX_OUTPUT_BYTES ? Buffer.concat([acc, chunk]) : acc;
    child.stdout.on('data', d => { out = cap(out, d); });
    child.stderr.on('data', d => { err = cap(err, d); });
    child.on('error', e => {
      if (settled) return; settled = true; clearTimeout(timer);
      resolve({ started: false, error: e.message });
    });
    child.on('exit', code => {
      if (settled) return; settled = true; clearTimeout(timer);
      // Brief grace for stdio already in flight when the process died.
      setTimeout(() => resolve({
        started: true, exit_code: code, timed_out: timedOut,
        stdout: out.toString('utf8').slice(0, MAX_OUTPUT_BYTES),
        stderr: err.toString('utf8').slice(0, MAX_OUTPUT_BYTES),
      }), 250).unref();
    });
  });
}

// --- disk quotas (best-effort, cached) ---
const sizeCache = new Map(); // dir -> { ts, bytes }
function dirSizeCached(dir, bailBytes) {
  const c = sizeCache.get(dir);
  if (c && Date.now() - c.ts < 30000) return c.bytes;
  let bytes = 0;
  const walk = (d) => {
    if (bytes > bailBytes) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (bytes > bailBytes) return;
      const full = path.join(d, e.name);
      try {
        if (e.isDirectory()) walk(full);
        else if (e.isFile()) bytes += fs.lstatSync(full).size;
      } catch {}
    }
  };
  walk(dir);
  sizeCache.set(dir, { ts: Date.now(), bytes });
  return bytes;
}

function pruneVersions(versionsDir, maxBytes) {
  if (dirSizeCached(versionsDir, maxBytes * 2) <= maxBytes) return;
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      try {
        if (e.isDirectory()) walk(full);
        else if (e.isFile()) { const st = fs.lstatSync(full); files.push({ p: full, mtimeMs: st.mtimeMs, size: st.size }); }
      } catch {}
    }
  };
  try { walk(versionsDir); } catch { return; }
  files.sort((a, b) => a.mtimeMs - b.mtimeMs); // oldest first
  let total = files.reduce((n, f) => n + f.size, 0);
  for (const f of files) {
    if (total <= maxBytes) break;
    try { fs.unlinkSync(f.p); total -= f.size; } catch {}
  }
  sizeCache.delete(versionsDir);
}

// Move a file to trash. rename(2) is atomic but fails with EXDEV across
// filesystems (workspace and install dir on different volumes) - fall back
// to a race-checked stream copy + fsync + inode-checked unlink.
function moveToTrash(real, dest, mode) {
  try { fs.renameSync(real, dest); return; }
  catch (e) { if (e.code !== 'EXDEV') throw e; }
  const srcFd = safeOpen(real, fs.constants.O_RDONLY);
  try {
    const srcStat = fs.fstatSync(srcFd);
    const dstFd = safeOpen(dest, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, mode || 0o600);
    try {
      const buf = Buffer.alloc(64 * 1024);
      let n;
      while ((n = fs.readSync(srcFd, buf, 0, buf.length, null)) > 0) fs.writeSync(dstFd, buf, 0, n);
      fs.fsyncSync(dstFd);
    } finally { fs.closeSync(dstFd); }
    // Unlink by path only if it is still the same file we copied.
    const now = fs.lstatSync(real);
    if (now.dev !== srcStat.dev || now.ino !== srcStat.ino) {
      throw new JailError('file changed during trash copy - copied but not removed');
    }
  } finally { fs.closeSync(srcFd); }
  fs.unlinkSync(real);
}

function profileCaps(agent) {
  return PROFILES[agent.profile] || PROFILES.readonly;
}

function requireCap(agent, cap) {
  if (!profileCaps(agent)[cap]) {
    throw new ToolError('forbidden', `profile '${agent.profile}' does not allow '${cap}'`);
  }
}

// --- argument validation helpers ---
function needStr(v, name, maxLen = 4096) {
  if (typeof v !== 'string' || v.length === 0 || v.length > maxLen) {
    throw new ToolError('invalid_params', `${name} must be a non-empty string (<= ${maxLen} chars)`);
  }
  return v;
}
function optStr(v, name, maxLen = 4096) {
  if (v === undefined || v === null) return undefined;
  return needStr(v, name, maxLen);
}
function optInt(v, name, min, max, dflt) {
  if (v === undefined || v === null) return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new ToolError('invalid_params', `${name} out of range`);
  return n;
}

// --- pending-approval result wrapper ---
function pendingResult(ctx, kind, toolName, summary, payload) {
  let created;
  try {
    created = ctx.approvals.create({ kind, agentId: ctx.agent.id, summary, payload, toolName });
  } catch (e) {
    if (e && e.code === 'too_many_pending') throw new ToolError('busy', e.message);
    if (e && e.code === 'summary_too_long') throw new ToolError('invalid_params', e.message);
    throw e;
  }
  const { id, expires_at } = created;
  ctx.audit.record({ agent: ctx.agent.id, tool: kind + ':request', decision: 'approval_requested', detail: summary });
  return {
    status: 'pending_approval',
    approval_id: id,
    expires_at: new Date(expires_at).toISOString(),
    how_to_approve: `On the Mac, run: agent-bridge approve ${id}`,
    note: 'Poll the approval.status tool with this approval_id.',
  };
}

const tools = {};

tools['system.info'] = {
  description: 'Summary of the Mac: hostname, OS, CPU, memory, uptime, bridge version and permission mode.',
  schema: { type: 'object', properties: {}, additionalProperties: false },
  approval: false,
  run(ctx) {
    return {
      hostname: os.hostname(), platform: os.platform(), arch: os.arch(),
      release: os.release(), cpus: os.cpus().length,
      memory: { total: os.totalmem(), free: os.freemem() },
      uptime_s: Math.floor(os.uptime()), user: os.userInfo().username,
      bridge: {
        version: ctx.version, profile: ctx.agent.profile,
        mode: ctx.policy.fullMode ? 'full' : 'limited',
        shell_enabled: !!ctx.cfg.enable_shell,
      },
    };
  },
};

tools['fs.list'] = {
  description: 'List a directory inside the allowed roots.',
  schema: {
    type: 'object',
    properties: {
      path: { type: 'string' },
      details: { type: 'boolean' },
    },
    required: ['path'], additionalProperties: false,
  },
  approval: false,
  run(ctx, args) {
    requireCap(ctx.agent, 'fs_read');
    const p = needStr(args.path, 'path');
    const { real } = resolveInRoots(p, ctx.policy.readRoots, ctx.cfg.workspace_root, ctx.policy.readOpts);
    const lst = assertRegularFileOrDir(real);
    if (!lst.isDirectory()) throw new ToolError('not_directory', 'path is a file - use fs.read');
    const entries = fs.readdirSync(real, { withFileTypes: true }).slice(0, MAX_LIST_ENTRIES);
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.list', decision: 'executed', detail: real });
    return {
      path: real,
      items: entries.map(e => {
        const item = { name: e.name, type: e.isDirectory() ? 'directory' : e.isSymbolicLink() ? 'symlink' : 'file' };
        if (args.details) {
          try {
            const s = fs.lstatSync(path.join(real, e.name));
            item.size = s.size; item.modified = s.mtime.toISOString();
          } catch {}
        }
        return item;
      }),
    };
  },
};

tools['fs.read'] = {
  description: 'Read a file inside the allowed roots (utf8 or base64).',
  schema: {
    type: 'object',
    properties: {
      path: { type: 'string' },
      encoding: { type: 'string', enum: ['utf8', 'base64'] },
      max_bytes: { type: 'integer' },
    },
    required: ['path'], additionalProperties: false,
  },
  approval: false,
  run(ctx, args) {
    requireCap(ctx.agent, 'fs_read');
    const p = needStr(args.path, 'path');
    const { real } = resolveInRoots(p, ctx.policy.readRoots, ctx.cfg.workspace_root, ctx.policy.readOpts);
    const st0 = assertRegularFileOrDir(real);
    if (st0.isDirectory()) throw new ToolError('is_directory', 'path is a directory - use fs.list');
    const maxBytes = Math.min(optInt(args.max_bytes, 'max_bytes', 1, ctx.cfg.max_read_bytes, ctx.cfg.max_read_bytes), ctx.cfg.max_read_bytes);
    const st = fs.statSync(real);
    const fd = safeOpen(real, fs.constants.O_RDONLY);
    try {
      const size = Math.min(st.size, maxBytes);
      const buf = Buffer.alloc(size);
      let off = 0;
      while (off < size) {
        const n = fs.readSync(fd, buf, off, size - off, off);
        if (n === 0) break; // truncated mid-read: return what we have
        off += n;
      }
      const truncated = st.size > maxBytes;
      // Read access is the sensitive unapproved op: the path is on the record.
      ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.read', decision: 'executed', detail: real + (truncated ? ' (truncated)' : '') });
      return {
        path: real, size: st.size, returned_bytes: off, truncated: truncated || off < size,
        modified: st.mtime.toISOString(),
        content: args.encoding === 'base64' ? buf.toString('base64') : buf.toString('utf8'),
      };
    } finally { fs.closeSync(fd); }
  },
};

tools['fs.write'] = {
  description: 'Write a file inside the workspace root. Previous content is versioned. base64 content.',
  schema: {
    type: 'object',
    properties: {
      path: { type: 'string' },
      content_base64: { type: 'string' },
      mode: { type: 'string', enum: ['create', 'overwrite', 'append'] },
    },
    required: ['path', 'content_base64'], additionalProperties: false,
  },
  approval: false,
  run(ctx, args) {
    requireCap(ctx.agent, 'fs_write');
    const p = needStr(args.path, 'path');
    const mode = args.mode || 'overwrite';
    if (typeof args.content_base64 !== 'string' || args.content_base64.length > ctx.cfg.max_body_bytes) {
      throw new ToolError('invalid_params', 'content_base64 required (string, size-capped)');
    }
    // Strict base64: no smuggled junk bytes.
    if (args.content_base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(args.content_base64)) {
      throw new ToolError('invalid_params', 'content_base64 is not valid base64');
    }
    const buf = Buffer.from(args.content_base64, 'base64');
    if (buf.length > ctx.cfg.max_body_bytes) throw new ToolError('too_large', 'content exceeds limit');
    // Writes are confined to the workspace root. Never the read-only extra roots.
    const { real } = resolveInRoots(p, ctx.policy.writeRoots, ctx.cfg.workspace_root, ctx.policy.writeOpts);

    // Reject a symlink at the lexical final component (the resolved target may
    // be inside the workspace, but silent write-through is never what you want).
    const lexAbs = path.isAbsolute(p) ? p : path.resolve(ctx.cfg.workspace_root, p.replace(/^~(?=$|\/)/, os.homedir()));
    try { if (fs.lstatSync(lexAbs).isSymbolicLink()) throw new JailError('refusing to write through symlink'); } catch (e) { if (e.code !== 'ENOENT') throw e; }

    // Total quota: the workspace (plus kept versions) cannot grow without bound.
    if (!ctx.policy.fullMode &&
        dirSizeCached(ctx.cfg.workspace_root, ctx.cfg.max_workspace_bytes * 2) + buf.length > ctx.cfg.max_workspace_bytes) {
      throw new ToolError('quota_exceeded', 'workspace disk quota exceeded - delete files or raise max_workspace_bytes');
    }

    const existed = fs.existsSync(real);
    if (mode === 'create' && existed) throw new ToolError('exists', 'file exists (mode=create)');
    let prevMode = null;
    if (existed) {
      const st = fs.lstatSync(real);
      prevMode = st.mode & 0o777;
      if (st.isDirectory()) throw new ToolError('is_directory', 'path is a directory');
      if (st.isSymbolicLink()) throw new JailError('refusing to write through symlink');
      if (!st.isFile()) throw new ToolError('invalid_params', 'not a regular file');
      if (st.nlink > 1) throw new JailError('hardlinked file - refusing to write through it');
      // Version the previous content (overwrites only; appends are additive).
      // Source is read through the race-checked safeOpen.
      if (mode !== 'append') {
        const vdir = path.join(ctx.cfg.install_dir, 'versions');
        const key = crypto.createHash('sha256').update(real).digest('hex').slice(0, 24);
        const fdir = path.join(vdir, key);
        fs.mkdirSync(fdir, { recursive: true, mode: 0o700 });
        const srcFd = safeOpen(real, fs.constants.O_RDONLY);
        let vfd;
        try {
          const vname = Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '-' + path.basename(real);
          vfd = fs.openSync(path.join(fdir, vname), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
          const chunk = Buffer.alloc(1024 * 1024);
          let n;
          while ((n = fs.readSync(srcFd, chunk, 0, chunk.length, null)) > 0) fs.writeSync(vfd, chunk, 0, n);
        } finally {
          fs.closeSync(srcFd);
          if (vfd !== undefined) fs.closeSync(vfd);
        }
        const versions = fs.readdirSync(fdir).sort();
        while (versions.length > 20) fs.unlinkSync(path.join(fdir, versions.shift()));
        pruneVersions(vdir, ctx.cfg.max_versions_bytes);
      }
    }
    fs.mkdirSync(path.dirname(real), { recursive: true, mode: 0o700 });
    if (mode === 'append') {
      // Appends are additive; write directly under the race-checked open.
      const dst = safeOpen(real, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND, 0o600);
      try { fs.writeSync(dst, buf, 0, buf.length, null); }
      finally { fs.closeSync(dst); }
    } else {
      // Atomic write: temp sibling + rename. A crash never leaves a
      // half-written file; the versioned copy stays recoverable. The temp
      // file is always cleaned up, even on a write error.
      const tmpName = real + '.abtmp-' + process.pid + '-' + crypto.randomBytes(6).toString('hex');
      let fd;
      try {
        fd = safeOpen(tmpName, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        try { fs.writeSync(fd, buf, 0, buf.length, 0); }
        finally { fs.closeSync(fd); }
        if (mode === 'create' && fs.existsSync(real)) {
          throw new ToolError('exists', 'file exists (mode=create)');
        }
        fs.renameSync(tmpName, real);
        // The temp file was 0600; restore the previous permission bits so an
        // overwrite never silently strips e.g. the exec bit.
        if (prevMode !== null) { try { fs.chmodSync(real, prevMode); } catch {} }
      } catch (e) {
        try { fs.unlinkSync(tmpName); } catch {}
        throw e;
      }
    }
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.write', decision: 'executed', detail: real + ' (' + buf.length + ' bytes, ' + mode + ')' });
    return { path: real, bytes: buf.length, mode, versioned: existed && mode !== 'append' };
  },
};

tools['fs.delete'] = {
  description: 'Move a workspace file to the local trash area. Requires on-device approval.',
  schema: {
    type: 'object',
    properties: { path: { type: 'string' } },
    required: ['path'], additionalProperties: false,
  },
  approval: 'delete',
  plan(ctx, args) {
    requireCap(ctx.agent, 'fs_delete');
    const p = needStr(args.path, 'path');
    const { real } = resolveInRoots(p, ctx.policy.writeRoots, ctx.cfg.workspace_root, ctx.policy.writeOpts);
    if (real === realpathOrSelf(ctx.cfg.workspace_root)) {
      throw new ToolError('forbidden', 'refusing to delete the workspace root itself');
    }
    const st = assertRegularFileOrDir(real);
    if (st.isDirectory()) throw new ToolError('is_directory', 'fs.delete removes files only, not directories');
    return { summary: 'delete file: ' + real, payload: { real, dev: st.dev, ino: st.ino, size: st.size, mtime_ms: st.mtimeMs } };
  },
  execute(ctx, payload) {
    // Re-validate at execution time: the world may have changed since approval.
    const { real } = resolveInRoots(payload.real, ctx.policy.writeRoots, ctx.cfg.workspace_root, ctx.policy.writeOpts);
    if (real !== payload.real) throw new JailError('path changed since approval - refusing');
    const st = assertRegularFileOrDir(real);
    if (st.isDirectory()) throw new JailError('target became a directory since approval - refusing');
    // The human approved deleting THIS file, not whatever now sits at the
    // path. Bind to inode + size + mtime (inode alone can be recycled after
    // an unlink+recreate); a replaced file needs a fresh approval.
    if (payload.dev !== undefined &&
        (st.dev !== payload.dev || st.ino !== payload.ino || st.size !== payload.size || st.mtimeMs !== payload.mtime_ms)) {
      throw new JailError('file changed since approval - refusing; request a fresh approval');
    }
    const trashDir = path.join(ctx.cfg.install_dir, 'trash');
    fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });
    const dest = path.join(trashDir, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '-' + path.basename(real));
    moveToTrash(real, dest, st.mode & 0o777);
    fs.appendFileSync(path.join(trashDir, 'manifest.jsonl'),
      JSON.stringify({ ts: new Date().toISOString(), original: real, trashed_as: dest, agent: ctx.agent.id }) + '\n', { mode: 0o600 });
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.delete', decision: 'executed', detail: real + ' -> ' + dest });
    return { moved_to_trash: dest, note: 'Restore with: mv <trashed_as> <original> (see trash/manifest.jsonl)' };
  },
};

tools['process.run'] = {
  description: 'Run an allowlisted program with an argv array (no shell). Other programs need approval; approved workspace files run from a frozen copy.',
  schema: {
    type: 'object',
    properties: {
      argv: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 64 },
      cwd: { type: 'string' },
      timeout_ms: { type: 'integer' },
    },
    required: ['argv'], additionalProperties: false,
  },
  approval: 'conditional',
  plan(ctx, args) {
    requireCap(ctx.agent, 'process_run');
    const argv = args.argv;
    if (!Array.isArray(argv) || argv.length === 0 || argv.length > 64) {
      throw new ToolError('invalid_params', 'argv must be an array of 1..64 strings');
    }
    for (const a of argv) {
      if (typeof a !== 'string' || a.length === 0 || a.length > 2048 || a.includes('\0')) {
        throw new ToolError('invalid_params', 'bad argv element');
      }
    }
    const bin = path.basename(argv[0]);
    const timeout = optInt(args.timeout_ms, 'timeout_ms', 1000, ctx.cfg.exec_timeout_ms_max, 30000);
    let cwd = ctx.cfg.workspace_root;
    if (args.cwd) cwd = ctx.policy.fullMode
      ? realpathOrSelf(optStr(args.cwd, 'cwd'))
      : resolveInRoots(optStr(args.cwd, 'cwd'), [ctx.cfg.workspace_root], ctx.cfg.workspace_root).real;

    if (ctx.policy.fullMode) {
      return { summary: 'run argv=' + JSON.stringify(argv), payload: { argv, cwd, timeout, bin }, needsApproval: false };
    }
    // Auto-allow requires ALL of:
    //  1. bare program name (no slash) resolved via the scrubbed system PATH
    //     - anything else could be a planted binary;
    //  2. EITHER a human-curated per-agent grant (the human owns that call)
    //     OR the program's exact argument grammar (deny-by-default flags,
    //     every positional path existing and jailed to the workspace, and
    //     passed to the program as its real path).
    const hasSlash = argv[0].includes('/');
    const agentExtra = Array.isArray(ctx.agent.allowed_programs) ? ctx.agent.allowed_programs : [];
    const granted = !hasSlash && agentExtra.includes(bin);
    const grammar = Object.hasOwn(PROGRAM_GRAMMARS, bin) ? PROGRAM_GRAMMARS[bin] : undefined;
    const grammarArgv = !granted && !hasSlash && grammar ? grammarRun(argv, grammar, cwd, ctx.cfg.workspace_root) : null;
    if (granted || grammarArgv) {
      return { summary: 'run argv=' + JSON.stringify(argv), payload: { argv: granted ? argv : grammarArgv, cwd, timeout, bin }, needsApproval: false };
    }
    // Approval path. Freeze every workspace file named in argv into an
    // agent-invisible snapshot; the execution runs the frozen copies, so
    // nothing the agent does after this plan can change what the human
    // approved. Summary leads with the binding status so it cannot be
    // truncated away (oversize summaries are refused, never cut).
    const fz = freezeArgvFiles(argv, cwd, ctx.cfg);
    const bindNote = fz.frozen.length
      ? `BINDING: ${fz.frozen.length} workspace file(s) frozen at request time` +
        (fz.contextCount ? ` (+${fz.contextCount} sibling file(s) for imports)` : '') +
        '; later edits CANNOT affect this run. Anything the command reads by a path not named in argv is NOT bound. '
      : 'BINDING: no workspace files named in argv - runs against live files. Anything the command reads is NOT bound. ';
    const summary = bindNote + 'run argv=' + JSON.stringify(argv) + (args.cwd ? ' cwd=' + cwd : '');
    return {
      summary,
      payload: {
        argv, cwd, timeout, bin,
        snapshot_id: fz.snapshotId, snapshot_dir: fz.snapshotDir, rewrite: fz.rewrite,
      },
      needsApproval: true,
    };
  },
  async execute(ctx, payload) {
    // Re-validate cwd at execution time: it may have been swapped for a
    // symlink between approval and execution.
    const cwd = ctx.policy.fullMode
      ? payload.cwd
      : resolveInRoots(payload.cwd, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root }).real;
    let argv = payload.argv;
    if (payload.snapshot_dir) {
      // The frozen copies must still be there (agent-invisible dir). If the
      // human removed it, refuse rather than silently falling back to live
      // files.
      if (!fs.existsSync(payload.snapshot_dir)) {
        throw new ToolError('changed', 'frozen snapshot no longer exists - request a fresh approval');
      }
      argv = payload.argv.map((a, i) => (payload.rewrite && payload.rewrite[i]) || a);
    }
    ctx.audit.record({ agent: ctx.agent.id, tool: 'process.run', decision: 'execute_start', detail: argv.join(' ').slice(0, 300) });
    const r = await spawnCaptured({ argv0: argv[0], args: argv.slice(1), cwd, env: scrubbedEnv(), timeout: payload.timeout });
    try {
      ctx.audit.record({
        agent: ctx.agent.id, tool: 'process.run',
        decision: r.started === false ? 'spawn_failed' : 'executed',
        detail: payload.argv.join(' ').slice(0, 300) + (r.started === false ? ' -> ' + r.error : ' -> exit ' + r.exit_code + (r.timed_out ? ' (timed out)' : '')),
      });
    } catch {}
    return r;
  },
};

const SHELL_BIN = process.platform === 'darwin' ? '/bin/zsh' : '/bin/sh';

tools['shell.exec'] = {
  description: 'Run a raw shell command. Disabled unless the bridge was installed with --enable-shell. ALWAYS requires on-device approval.',
  schema: {
    type: 'object',
    properties: {
      command: { type: 'string' },
      cwd: { type: 'string' },
      timeout_ms: { type: 'integer' },
    },
    required: ['command'], additionalProperties: false,
  },
  approval: 'shell',
  plan(ctx, args) {
    requireCap(ctx.agent, 'shell'); // profiles apply in BOTH modes
    if (!ctx.policy.fullMode && !ctx.cfg.enable_shell) {
      throw new ToolError('disabled', 'shell.exec is disabled on this bridge (install with --enable-shell to allow, still approval-gated)');
    }
    const command = needStr(args.command, 'command', 8192);
    const timeout = optInt(args.timeout_ms, 'timeout_ms', 1000, ctx.cfg.exec_timeout_ms_max, 30000);
    let cwd = ctx.cfg.workspace_root;
    if (args.cwd) cwd = ctx.policy.fullMode
      ? realpathOrSelf(optStr(args.cwd, 'cwd'))
      : resolveInRoots(optStr(args.cwd, 'cwd'), [ctx.cfg.workspace_root], ctx.cfg.workspace_root).real;
    // A shell command's files cannot be enumerated or bound. Say so on the
    // approval line - the human is approving the command TEXT only.
    const summary = 'BINDING: command text only; a shell command reads files not shown here and they are NOT bound. shell: ' + command;
    return { summary, payload: { command, cwd, timeout }, needsApproval: !ctx.policy.fullMode };
  },
  async execute(ctx, payload) {
    // Re-validate cwd in limited mode (it may have been swapped since approval).
    const cwd = ctx.policy.fullMode
      ? payload.cwd
      : resolveInRoots(payload.cwd, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root }).real;
    ctx.audit.record({ agent: ctx.agent.id, tool: 'shell.exec', decision: 'execute_start', detail: payload.command.slice(0, 300) });
    const r = await spawnCaptured({ argv0: SHELL_BIN, args: ['-c', payload.command], cwd, env: scrubbedEnv(), timeout: payload.timeout });
    r.via = 'shell.exec';
    try {
      ctx.audit.record({
        agent: ctx.agent.id, tool: 'shell.exec',
        decision: r.started === false ? 'spawn_failed' : 'executed',
        detail: payload.command.slice(0, 300) + (r.started === false ? ' -> ' + r.error : ' -> exit ' + r.exit_code + (r.timed_out ? ' (timed out)' : '')),
      });
    } catch {}
    return r;
  },
};

tools['approval.status'] = {
  description: 'Poll an approval. If approved, the planned action executes exactly once and returns its result.',
  schema: {
    type: 'object',
    properties: { approval_id: { type: 'string' } },
    required: ['approval_id'], additionalProperties: false,
  },
  approval: false,
  async run(ctx, args) {
    const id = needStr(args.approval_id, 'approval_id', 64);
    const { state, approval } = ctx.approvals.status(id);
    // Approvals are private to their owner: another agent learns nothing,
    // not even whether the id exists.
    if (approval && approval.agent_id && approval.agent_id !== ctx.agent.id) return { status: 'unknown' };
    if (state === 'unknown' || state === 'expired' || state === 'pending' || state === 'denied') {
      return { status: state };
    }
    if (state === 'consumed') return { status: 'already_executed' };
    if (state === 'executing') return { status: 'executing' };
    if (state !== 'approved') return { status: state };
    // Approvals go stale: a "yes" is valid for 10 minutes, not forever.
    if (approval.decided_at && Date.now() - Date.parse(approval.decided_at) > 10 * 60 * 1000) {
      ctx.approvals.expire(id);
      return { status: 'expired' };
    }
    // Two-phase: mark executing (atomic), run, then mark consumed. Strictly
    // single-use: a FAILED execution is consumed too (with the error on the
    // record), never returned to 'approved' for a retry.
    if (!ctx.approvals.beginExecution(id)) return { status: 'already_executed' };
    ctx.audit.record({ agent: ctx.agent.id, tool: 'approval.status', decision: 'approved_execute', detail: approval.kind + ': ' + approval.summary });
    const toolName = approval.tool_name || mapKindToTool(approval.kind);
    const tool = Object.hasOwn(tools, toolName || '') ? tools[toolName] : undefined;
    if (!tool || !tool.execute) {
      ctx.approvals.finishExecution(id, 'no executor for ' + approval.kind);
      return { status: 'error', error: 'no executor for ' + approval.kind };
    }
    try {
      const result = await tool.execute(ctx, approval.payload);
      ctx.approvals.finishExecution(id);
      return { status: 'executed', result };
    } catch (e) {
      ctx.approvals.finishExecution(id, e.message);
      ctx.audit.record({ agent: ctx.agent.id, tool: 'approval.status', decision: 'execution_failed', detail: String(e.message).slice(0, 200) });
      return { status: 'execution_failed', error: String(e.message).slice(0, 300) };
    }
  },
};

function mapKindToTool(kind) {
  return { shell: 'shell.exec', process: 'process.run', delete: 'fs.delete' }[kind];
}

module.exports = { tools, ToolError, pendingResult, profileCaps };
