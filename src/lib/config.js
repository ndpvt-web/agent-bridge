'use strict';
// Bridge configuration and security profiles.
const fs = require('fs');
const os = require('os');
const path = require('path');

// Profiles define what paired agents may do.
// - readonly : system.info, fs.list, fs.read (inside roots)
// - workspace: + fs.write, fs.delete (trash), inside workspace root
// - developer: + process.run of allowlisted binaries (approval for anything else)
// Shell access is NEVER part of a profile. It is a separate install-time
// opt-in (enable_shell) and every call still needs on-device approval.
const PROFILES = {
  readonly:  { fs_read: true,  fs_write: false, fs_delete: false, process_run: false },
  workspace: { fs_read: true,  fs_write: true,  fs_delete: true,  process_run: false },
  developer: { fs_read: true,  fs_write: true,  fs_delete: true,  process_run: true },
};

// Programs a developer-profile agent may run without per-call approval.
// Rule: ONLY programs that cannot execute attacker-controlled code and cannot
// write outside their arguments. Interpreters (node, python3), build tools
// (make, xcodebuild), package managers (npm), and shells are NOT here: they
// are shells in disguise. They require on-device approval, or a curated
// per-agent allowlist entry set by the human via the CLI (never by the API).
const PROCESS_ALLOWLIST = new Set([
  'ls', 'pwd', 'cat', 'head', 'tail', 'wc', 'file', 'stat', 'which',
  'uname', 'sw_vers', 'df', 'du', 'date', 'echo', 'printf',
  'grep', 'rg', 'sort', 'uniq', 'diff', 'jq', 'shasum', 'md5',
]);

// Environment passed to spawned processes: minimal, deterministic.
function scrubbedEnv() {
  return {
    PATH: '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/sbin',
    HOME: os.homedir(),
    LANG: 'en_US.UTF-8',
    TMPDIR: os.tmpdir(),
  };
}

function defaultConfig(home) {
  const installDir = path.join(home || os.homedir(), 'agent-bridge');
  return {
    version: 2,
    port: 7899,
    bind: '127.0.0.1',
    profile_default: 'workspace',
    enable_shell: false,          // install-time opt-in; even then, approval-gated
    allowed_roots: [path.join(installDir, 'workspace')],
    workspace_root: path.join(installDir, 'workspace'),
    read_roots_extra: [os.homedir()], // read-only visibility, writes stay jailed
    max_body_bytes: 8 * 1024 * 1024,
    max_read_bytes: 16 * 1024 * 1024,
    exec_timeout_ms_max: 120000,
    rate_limit_per_minute: 240,
    pair_rate_limit: { attempts: 6, window_ms: 600000 },
    tunnel_host_suffixes: ['.trycloudflare.com'],
  };
}

function loadConfig(installDir) {
  const cfg = defaultConfig();
  // Defaults derive from the install dir, not the process environment.
  cfg.install_dir = installDir;
  cfg.workspace_root = path.join(installDir, 'workspace');
  cfg.allowed_roots = [cfg.workspace_root];
  const p = path.join(installDir, 'config.json');
  try {
    const onDisk = JSON.parse(fs.readFileSync(p, 'utf8'));
    Object.assign(cfg, onDisk);
    cfg.install_dir = installDir; // never overridable from disk
  } catch {}
  return cfg;
}

module.exports = { PROFILES, PROCESS_ALLOWLIST, scrubbedEnv, defaultConfig, loadConfig };
