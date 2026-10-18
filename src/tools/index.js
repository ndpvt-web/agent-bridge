'use strict';
// Tool implementations. Every tool receives a context { cfg, agent, approvals,
// audit, keystore } and a validated argument object. Tools return plain data
// or throw ToolError { code, message }.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { JailError, resolveInRoots, assertRegularFileOrDir, safeOpen } = require('../lib/jail');
const { PROFILES, PROCESS_ALLOWLIST, PROGRAM_GRAMMARS, scrubbedEnv } = require('../lib/config');

// --- per-program argument grammar engine (deny by default) ---
// Any flag not explicitly listed, any joined long form, any path outside the
// workspace jail => not auto-allowed => on-device approval required.
function validateValue(type, v) {
  if (typeof v !== 'string') return false;
  switch (type) {
    case 'int': return /^[0-9]{1,10}$/.test(v);
    case 'text': return v.length <= 512 && !v.includes('\0');
    default: return false;
  }
}

function grammarAllows(argv, grammar, cwd, workspaceRoot) {
  const flags = new Set(grammar.flags || []);
  const valueFlags = grammar.valueFlags || {};
  const longFlags = new Set(grammar.longFlags || []);
  const maxArgs = grammar.maxArgs === undefined ? 16 : grammar.maxArgs;
  if (argv.length - 1 > maxArgs) return false;
  let positionalSeen = 0;
  let endOfFlags = false;
  let i = 1;
  while (i < argv.length) {
    const tok = argv[i];
    if (!endOfFlags && tok === '--') { endOfFlags = true; i++; continue; }
    if (!endOfFlags && grammar.plusArgs && tok.startsWith('+') && tok.length > 1 && tok.length <= 512) { i++; continue; }
    if (!endOfFlags && tok.startsWith('--')) {
      const eq = tok.indexOf('=');
      if (eq !== -1) return false; // joined long values are never auto-allowed
      if (longFlags.has(tok)) { i++; continue; }
      const vt = valueFlags[tok];
      if (vt === 'pair') {
        const name = argv[i + 1], val = argv[i + 2];
        if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name || '') || typeof val !== 'string' || val.length > 4096) return false;
        i += 3; continue;
      }
      if (vt) {
        const v = argv[i + 1];
        if (v === undefined || !validateValue(vt, v)) return false;
        i += 2; continue;
      }
      return false;
    }
    if (!endOfFlags && tok.startsWith('-') && tok !== '-') {
      const chars = tok.slice(1);
      if (chars.length === 0) return false;
      let j = 0;
      while (j < chars.length) {
        const f = '-' + chars[j];
        if (flags.has(f)) { j++; continue; }
        const vt = valueFlags[f];
        if (vt) {
          const joined = chars.slice(j + 1);
          if (joined) { if (!validateValue(vt, joined)) return false; }
          else {
            const v = argv[i + 1];
            if (v === undefined || !validateValue(vt, v)) return false;
            i++;
          }
          j = chars.length;
          break;
        }
        return false;
      }
      i++; continue;
    }
    // positional argument
    positionalSeen++;
    let kind;
    if (positionalSeen === 1 && grammar.firstPositional === 'any') kind = 'any';
    else if (grammar.pathArgs === 'any') kind = 'any';
    else if (grammar.pathArgs === 'none') kind = 'none';
    else kind = 'jailed';
    if (kind === 'none') return false;
    if (kind === 'jailed') {
      try { resolveInRoots(tok, [workspaceRoot], cwd); } catch { return false; }
    }
    i++;
  }
  return true;
}

class ToolError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const MAX_LIST_ENTRIES = 5000;
const MAX_OUTPUT_BYTES = 1024 * 1024;

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
  const { id, expires_at } = ctx.approvals.create({
    kind, agentId: ctx.agent.id, summary, payload, toolName,
  });
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
  description: 'Summary of the Mac: hostname, OS, CPU, memory, uptime, bridge version.',
  schema: { type: 'object', properties: {}, additionalProperties: false },
  approval: false,
  run(ctx) {
    return {
      hostname: os.hostname(), platform: os.platform(), arch: os.arch(),
      release: os.release(), cpus: os.cpus().length,
      memory: { total: os.totalmem(), free: os.freemem() },
      uptime_s: Math.floor(os.uptime()), user: os.userInfo().username,
      bridge: { version: ctx.version, profile: ctx.agent.profile, shell_enabled: !!ctx.cfg.enable_shell },
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
    const { real } = resolveInRoots(p, ctx.readRoots, ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root });
    const entries = fs.readdirSync(real, { withFileTypes: true }).slice(0, MAX_LIST_ENTRIES);
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
    const { real } = resolveInRoots(p, ctx.readRoots, ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root });
    assertRegularFileOrDir(real);
    const maxBytes = Math.min(optInt(args.max_bytes, 'max_bytes', 1, ctx.cfg.max_read_bytes, ctx.cfg.max_read_bytes), ctx.cfg.max_read_bytes);
    const st = fs.statSync(real);
    const fd = safeOpen(real, fs.constants.O_RDONLY);
    try {
      const size = Math.min(st.size, maxBytes);
      const buf = Buffer.alloc(size);
      let off = 0;
      while (off < size) { off += fs.readSync(fd, buf, off, size - off, off); }
      const truncated = st.size > maxBytes;
      return {
        path: real, size: st.size, returned_bytes: size, truncated,
        modified: st.mtime.toISOString(),
        content: args.encoding === 'base64' ? buf.toString('base64') : buf.toString('utf8'),
      };
    } finally { fs.closeSync(fd); }
  },
};

// fs.read records the path for forensics (read access is the sensitive op).
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
    const { real } = resolveInRoots(p, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root });

    // Reject a symlink at the lexical final component (the resolved target may
    // be inside the workspace, but silent write-through is never what you want).
    const lexAbs = path.isAbsolute(p) ? p : path.resolve(ctx.cfg.workspace_root, p.replace(/^~(?=$|\/)/, require('os').homedir()));
    try { if (fs.lstatSync(lexAbs).isSymbolicLink()) throw new JailError('refusing to write through symlink'); } catch (e) { if (e.code !== 'ENOENT') throw e; }

    const existed = fs.existsSync(real);
    if (mode === 'create' && existed) throw new ToolError('exists', 'file exists (mode=create)');
    if (existed) {
      const st = fs.lstatSync(real);
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
      // half-written file; the versioned copy stays recoverable.
      const tmpName = real + '.abtmp-' + process.pid + '-' + crypto.randomBytes(6).toString('hex');
      const fd = safeOpen(tmpName, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
      try { fs.writeSync(fd, buf, 0, buf.length, 0); }
      finally { fs.closeSync(fd); }
      if (mode === 'create' && fs.existsSync(real)) {
        fs.unlinkSync(tmpName);
        throw new ToolError('exists', 'file exists (mode=create)');
      }
      fs.renameSync(tmpName, real);
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
    const { real } = resolveInRoots(p, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root });
    if (real === require('../lib/jail').realpathOrSelf(ctx.cfg.workspace_root)) {
      throw new ToolError('forbidden', 'refusing to delete the workspace root itself');
    }
    const st = assertRegularFileOrDir(real);
    if (st.isDirectory()) throw new ToolError('is_directory', 'fs.delete removes files only, not directories');
    if (st.nlink > 1) throw new JailError('hardlinked file - refusing to delete');
    return { summary: 'delete file: ' + real, payload: { real } };
  },
  execute(ctx, payload) {
    // Re-validate at execution time: the world may have changed since approval.
    const { real } = resolveInRoots(payload.real, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root });
    if (real !== payload.real) throw new JailError('path changed since approval - refusing');
    const st = assertRegularFileOrDir(real);
    if (st.isDirectory()) throw new JailError('target became a directory since approval - refusing');
    if (st.nlink > 1) throw new JailError('hardlinked file - refusing to delete');
    const trashDir = path.join(ctx.cfg.install_dir, 'trash');
    fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });
    const dest = path.join(trashDir, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '-' + path.basename(real));
    fs.renameSync(real, dest);
    fs.appendFileSync(path.join(trashDir, 'manifest.jsonl'),
      JSON.stringify({ ts: new Date().toISOString(), original: real, trashed_as: dest, agent: ctx.agent.id }) + '\n', { mode: 0o600 });
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.delete', decision: 'executed', detail: real + ' -> ' + dest });
    return { moved_to_trash: dest, note: 'Restore with: mv <trashed_as> <original> (see trash/manifest.jsonl)' };
  },
};

tools['process.run'] = {
  description: 'Run an allowlisted program with an argv array (no shell). Other programs need approval.',
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
    if (args.cwd) cwd = resolveInRoots(optStr(args.cwd, 'cwd'), [ctx.cfg.workspace_root], ctx.cfg.workspace_root).real;
    // Auto-allow requires ALL of:
    //  1. bare program name (no slash) resolved via the scrubbed system PATH
    //     - anything else could be a planted binary;
    //  2. EITHER a human-curated per-agent grant (the human owns that call)
    //     OR the program's exact argument grammar (deny-by-default flags,
    //     every positional path jailed to the workspace).
    const hasSlash = argv[0].includes('/');
    const agentExtra = Array.isArray(ctx.agent.allowed_programs) ? ctx.agent.allowed_programs : [];
    const granted = !hasSlash && agentExtra.includes(bin);
    const grammar = PROGRAM_GRAMMARS[bin];
    const grammarOk = !hasSlash && !!grammar && grammarAllows(argv, grammar, cwd, ctx.cfg.workspace_root);
    const autoAllowed = granted || grammarOk;
    const needsApproval = !autoAllowed;
    // Summary must let the human see EXACTLY what runs: argv as a JSON array,
    // never an ambiguous space-joined string.
    const summary = 'run argv=' + JSON.stringify(argv) + (args.cwd ? ' cwd=' + cwd : '');
    return { summary, payload: { argv, cwd, timeout, bin }, needsApproval };
  },
  execute(ctx, payload) {
    // Re-validate cwd at execution time: it may have been swapped for a
    // symlink between approval and execution.
    const cwd = resolveInRoots(payload.cwd, [ctx.cfg.workspace_root], ctx.cfg.workspace_root, { installDir: ctx.cfg.install_dir, workspaceRoot: ctx.cfg.workspace_root }).real;
    return new Promise((resolve) => {
      const child = spawn(payload.argv[0], payload.argv.slice(1), {
        cwd, env: scrubbedEnv(), shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = Buffer.alloc(0), err = Buffer.alloc(0), timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM'); setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 2000).unref(); }, payload.timeout);
      const cap = (acc, chunk) => acc.length < MAX_OUTPUT_BYTES ? Buffer.concat([acc, chunk]) : acc;
      child.stdout.on('data', d => { out = cap(out, d); });
      child.stderr.on('data', d => { err = cap(err, d); });
      child.on('error', e => { clearTimeout(timer); resolve({ started: false, error: e.message }); });
      child.on('close', code => {
        clearTimeout(timer);
        ctx.audit.record({ agent: ctx.agent.id, tool: 'process.run', decision: 'executed', detail: payload.argv.join(' ') + ' -> exit ' + code });
        resolve({
          started: true, exit_code: code, timed_out: timedOut,
          stdout: out.toString('utf8').slice(0, MAX_OUTPUT_BYTES),
          stderr: err.toString('utf8').slice(0, MAX_OUTPUT_BYTES),
        });
      });
    });
  },
};

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
    if (!ctx.cfg.enable_shell) {
      throw new ToolError('disabled', 'shell.exec is disabled on this bridge (install with --enable-shell to allow, still approval-gated)');
    }
    const command = needStr(args.command, 'command', 8192);
    const timeout = optInt(args.timeout_ms, 'timeout_ms', 1000, ctx.cfg.exec_timeout_ms_max, 30000);
    let cwd = ctx.cfg.workspace_root;
    if (args.cwd) cwd = resolveInRoots(optStr(args.cwd, 'cwd'), [ctx.cfg.workspace_root], ctx.cfg.workspace_root).real;
    return { summary: `shell: ${command}`, payload: { command, cwd, timeout }, needsApproval: true };
  },
  execute(ctx, payload) {
    return tools['process.run'].execute(ctx, {
      argv: ['/bin/zsh', '-c', payload.command], cwd: payload.cwd, timeout: payload.timeout, bin: 'zsh',
    }).then(r => { r.via = 'shell.exec'; return r; });
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
    if (state === 'unknown' || state === 'expired' || state === 'pending' || state === 'denied') {
      return { status: state };
    }
    if (state === 'consumed') return { status: 'already_executed' };
    if (state === 'executing') return { status: 'executing' };
    if (state !== 'approved') return { status: state };
    // Ownership BEFORE any state change: another agent polling must not burn it.
    if (approval.agent_id !== ctx.agent.id) {
      return { status: 'forbidden', error: 'approval belongs to a different agent' };
    }
    // Approvals go stale: a "yes" is valid for 10 minutes, not forever.
    if (approval.decided_at && Date.now() - Date.parse(approval.decided_at) > 10 * 60 * 1000) {
      ctx.approvals.expire(id);
      return { status: 'expired' };
    }
    // Two-phase: mark executing (atomic), run, then mark consumed. A failed
    // execution returns the approval to 'approved' so it can be retried.
    if (!ctx.approvals.beginExecution(id)) return { status: 'already_executed' };
    ctx.audit.record({ agent: ctx.agent.id, tool: 'approval.status', decision: 'approved_execute', detail: approval.kind + ': ' + approval.summary });
    const tool = tools[approval.tool_name || mapKindToTool(approval.kind)];
    if (!tool || !tool.execute) { ctx.approvals.failExecution(id); return { status: 'error', error: 'no executor for ' + approval.kind }; }
    try {
      const result = await tool.execute(ctx, approval.payload);
      ctx.approvals.finishExecution(id);
      return { status: 'executed', result };
    } catch (e) {
      ctx.approvals.failExecution(id);
      ctx.audit.record({ agent: ctx.agent.id, tool: 'approval.status', decision: 'execution_failed', detail: String(e.message).slice(0, 200) });
      return { status: 'execution_failed', error: String(e.message).slice(0, 300) };
    }
  },
};

function mapKindToTool(kind) {
  return { shell: 'shell.exec', process: 'process.run', delete: 'fs.delete', write: 'fs.write' }[kind];
}

module.exports = { tools, ToolError, pendingResult, profileCaps };
