'use strict';
// Tool implementations. Every tool receives a context { cfg, agent, approvals,
// audit, keystore } and a validated argument object. Tools return plain data
// or throw ToolError { code, message }.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { JailError, resolveInRoots, assertRegularFileOrDir } = require('../lib/jail');
const { PROFILES, PROCESS_ALLOWLIST, scrubbedEnv } = require('../lib/config');

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
    const { real } = resolveInRoots(p, ctx.readRoots, ctx.cfg.workspace_root);
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
    const { real } = resolveInRoots(p, ctx.readRoots, ctx.cfg.workspace_root);
    assertRegularFileOrDir(real);
    const maxBytes = Math.min(optInt(args.max_bytes, 'max_bytes', 1, ctx.cfg.max_read_bytes, ctx.cfg.max_read_bytes), ctx.cfg.max_read_bytes);
    const st = fs.statSync(real);
    // O_NOFOLLOW as a second layer against symlink races on the final component.
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
    const fd = fs.openSync(real, flags);
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
    const buf = Buffer.from(needStr(args.content_base64, 'content_base64', ctx.cfg.max_body_bytes), 'base64');
    if (buf.length > ctx.cfg.max_body_bytes) throw new ToolError('too_large', 'content exceeds limit');
    // Writes are confined to the workspace root. Never the read-only extra roots.
    const { real } = resolveInRoots(p, [ctx.cfg.workspace_root], ctx.cfg.workspace_root);

    const existed = fs.existsSync(real);
    if (mode === 'create' && existed) throw new ToolError('exists', 'file exists (mode=create)');
    if (existed) {
      const st = fs.lstatSync(real);
      if (st.isDirectory()) throw new ToolError('is_directory', 'path is a directory');
      if (st.isSymbolicLink()) throw new JailError('refusing to write through symlink');
      // Version the previous content (bounded: 20 versions per file).
      const vdir = path.join(ctx.cfg.install_dir, 'versions');
      const key = crypto.createHash('sha256').update(real).digest('hex').slice(0, 24);
      const fdir = path.join(vdir, key);
      fs.mkdirSync(fdir, { recursive: true, mode: 0o700 });
      fs.copyFileSync(real, path.join(fdir, Date.now() + '-' + path.basename(real)));
      const versions = fs.readdirSync(fdir).sort();
      while (versions.length > 20) fs.unlinkSync(path.join(fdir, versions.shift()));
    }
    fs.mkdirSync(path.dirname(real), { recursive: true, mode: 0o700 });
    // Open with O_NOFOLLOW so a symlink swapped in after the jail check
    // (TOCTOU) cannot redirect the write outside the workspace.
    const NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
    const openFlags = mode === 'append'
      ? fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | NOFOLLOW
      : fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | NOFOLLOW;
    let fd;
    try { fd = fs.openSync(real, openFlags, 0o600); }
    catch (e) {
      if (e && e.code === 'ELOOP') throw new JailError('refusing to write through symlink');
      throw e;
    }
    try { fs.writeSync(fd, buf, 0, buf.length, mode === 'append' ? null : 0); }
    finally { fs.closeSync(fd); }
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.write', decision: 'executed', detail: real + ' (' + buf.length + ' bytes, ' + mode + ')' });
    return { path: real, bytes: buf.length, mode, versioned: existed };
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
    const { real } = resolveInRoots(p, [ctx.cfg.workspace_root], ctx.cfg.workspace_root);
    assertRegularFileOrDir(real);
    return { summary: `delete ${real}`, payload: { real } };
  },
  execute(ctx, payload) {
    const trashDir = path.join(ctx.cfg.install_dir, 'trash');
    fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });
    const dest = path.join(trashDir, Date.now() + '-' + path.basename(payload.real));
    fs.renameSync(payload.real, dest);
    ctx.audit.record({ agent: ctx.agent.id, tool: 'fs.delete', decision: 'executed', detail: payload.real + ' -> ' + dest });
    return { moved_to_trash: dest };
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
    // The auto-allowlist applies ONLY to bare program names resolved through
    // the scrubbed system PATH. Any slash in argv[0] (./tool, /tmp/x, a binary
    // the agent itself wrote into the workspace) always needs approval,
    // otherwise an agent could plant a binary named 'ls' and run it freely.
    const hasSlash = argv[0].includes('/');
    const agentExtra = Array.isArray(ctx.agent.allowed_programs) ? ctx.agent.allowed_programs : [];
    const autoAllowed = !hasSlash && (PROCESS_ALLOWLIST.has(bin) || agentExtra.includes(bin));
    const needsApproval = !autoAllowed;
    return { summary: `run ${argv.join(' ')}`, payload: { argv, cwd, timeout, bin }, needsApproval };
  },
  execute(ctx, payload) {
    return new Promise((resolve) => {
      const child = spawn(payload.argv[0], payload.argv.slice(1), {
        cwd: payload.cwd, env: scrubbedEnv(), shell: false,
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
    if (state !== 'approved') return { status: state };
    // Execute exactly once.
    if (!ctx.approvals.consume(id)) return { status: 'already_executed' };
    ctx.audit.record({ agent: ctx.agent.id, tool: 'approval.status', decision: 'approved_execute', detail: approval.kind + ': ' + approval.summary });
    if (approval.agent_id !== ctx.agent.id) {
      return { status: 'forbidden', error: 'approval belongs to a different agent' };
    }
    const tool = tools[approval.tool_name || mapKindToTool(approval.kind)];
    if (!tool || !tool.execute) return { status: 'error', error: 'no executor for ' + approval.kind };
    const result = await tool.execute(ctx, approval.payload);
    return { status: 'executed', result };
  },
};

function mapKindToTool(kind) {
  return { shell: 'shell.exec', process: 'process.run', delete: 'fs.delete', write: 'fs.write' }[kind];
}

module.exports = { tools, ToolError, pendingResult, profileCaps };
