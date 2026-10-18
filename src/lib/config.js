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
  readonly:  { fs_read: true,  fs_write: false, fs_delete: false, process_run: false, shell: false },
  workspace: { fs_read: true,  fs_write: true,  fs_delete: true,  process_run: false, shell: false },
  developer: { fs_read: true,  fs_write: true,  fs_delete: true,  process_run: true,  shell: true },
};

// Programs a developer-profile agent may run without per-call approval, and
// the EXACT argument grammar each is allowed to use. Deny-by-default: any
// flag not listed, any joined long-flag form, any positional path outside
// the workspace jail forces on-device approval.
//
// Grammar fields:
//   flags:        single-letter flags taking NO value (bundles like -la ok)
//   valueFlags:   flags consuming the next token (or joined rest) as value:
//                 'int' = ^[0-9]+$; 'text' = any string that is NOT treated
//                 as a path (pattern, label, format) and cannot be a path
//   longFlags:    exact '--name' tokens allowed (no '=' joined forms ever)
//   plusArgs:     tokens starting with '+' (e.g. date formats), any content
//   firstPositional: 'any' allows the first positional to be a pattern/filter
//   patternFlags: flags that SUPPLY the pattern (e.g. grep -e). When any is
//                 present, every positional is a file operand and is jailed.
//   isolateHome:  spawn with HOME pointed at an empty dir (jq reads ~/.jq
//                 and exposes env to filters)
// Positional args after that must resolve inside the workspace jail.
//
// NOT HERE: interpreters, shells, build tools, package managers, anything
// with an exec/run/pre/output/compress-program option. Those always need
// approval or a human CLI grant.
const PROGRAM_GRAMMARS = {
  ls:    { flags: '-l -a -la -al -lh -hl -R -1 -t -S -d -h -G -F -p -i'.split(' '), longFlags: ['--help', '--version'] },
  pwd:   { flags: ['-L', '-P'], longFlags: ['--help'], maxArgs: 0 },
  cat:   { flags: '-n -b -e -t -v -s -A'.split(' '), longFlags: ['--help', '--version'] },
  head:  { flags: ['-q', '-v'], valueFlags: { '-n': 'int', '-c': 'int' }, longFlags: ['--help', '--version'] },
  tail:  { flags: ['-q', '-v'], valueFlags: { '-n': 'int', '-c': 'int' }, longFlags: ['--help', '--version'] },
  wc:    { flags: '-l -w -c -m -L'.split(' '), longFlags: ['--help', '--version'] },
  file:  { flags: ['-b', '-i', '-z', '-L'], longFlags: ['--help', '--version'] },
  stat:  process.platform === 'darwin'
           ? { flags: ['-l', '-x', '-L', '-r', '-s', '-q'], valueFlags: { '-f': 'text', '-t': 'text' }, longFlags: ['--help', '--version'] }
           // GNU coreutils: -t/-f take NO value; -c takes the format string.
           : { flags: ['-L', '-t', '-f'], valueFlags: { '-c': 'text' }, longFlags: ['--help', '--version'] },
  which: { flags: ['-a', '-s'], pathArgs: 'any', longFlags: ['--help'] },
  uname: { flags: '-a -m -n -p -r -s -v'.split(' '), longFlags: ['--help'], maxArgs: 0 },
  sw_vers: { flags: [], longFlags: [], maxArgs: 0 },
  df:    { flags: ['-h', '-k', '-H', '-i', '-l', '-m', '-g', '-b'], longFlags: ['--help'] },
  du:    { flags: ['-h', '-s', '-a', '-x', '-k', '-m'], valueFlags: { '-d': 'int', '-t': 'text' }, longFlags: ['--help', '--version'] },
  date:  { flags: ['-u', '-R', '-r', '-n', '-j'], plusArgs: true, pathArgs: 'none', longFlags: ['--help'], maxArgs: 1 },
  echo:  { flags: ['-n', '-e', '-E'], pathArgs: 'any', longFlags: ['--help', '--version'] },
  printf: { flags: [], pathArgs: 'any', longFlags: ['--help'] },
  // -R is NOT here: it follows symlinks during traversal, out of the jail.
  // -r recurses without following links. -e supplies the pattern by flag,
  // which makes every positional a jailed file operand (patternFlags).
  grep:  { flags: ['-i','-v','-n','-c','-l','-L','-w','-x','-E','-F','-o','-r','-h','-H','-q','-s','-z'],
           valueFlags: { '-m': 'int', '-A': 'int', '-B': 'int', '-C': 'int', '-e': 'text' },
           patternFlags: ['-e'],
           longFlags: ['--help', '--version'], firstPositional: 'any' },
  rg:    { flags: '-i -v -n -c -l -w -x -S -F -o -h -H -q -s -u -N -M -j -0'.split(' '),
           valueFlags: { '-m': 'int', '-A': 'int', '-B': 'int', '-C': 'int', '-e': 'text', '-t': 'text', '-T': 'text', '-g': 'text' },
           patternFlags: ['-e'],
           longFlags: ['--help', '--version'], firstPositional: 'any' },
  sort:  { flags: '-n -r -u -f -R -c -m -b -d -i -h -g -z -s -V -M'.split(' '), longFlags: ['--help', '--version'] },
  uniq:  { flags: ['-c', '-d', '-u', '-i', '-z', '-D'], valueFlags: { '-f': 'int', '-s': 'int', '-w': 'int' }, longFlags: ['--help', '--version'] },
  // -r is NOT here: recursive diff follows symlinks during traversal, out
  // of the jail. Recursive diff needs approval.
  diff:  { flags: '-u -c -q -i -w -b -y -p -a -e -n -s -l -t -E -B -Z -d'.split(' '),
           valueFlags: { '-U': 'int', '-C': 'int', '-L': 'text' }, longFlags: ['--help', '--version', '--brief', '--report-identical-files'] },
  jq:    { flags: ['-r','-c','-n','-e','-s','-R','-j','-M','-S','-C','-a'],
           longFlags: ['--help', '--version', '--raw-output', '--compact-output', '--null-input', '--exit-status', '--slurp', '--raw-input', '--join-output', '--monochrome-output', '--sort-keys', '--tab'],
           valueFlags: { '--indent': 'int', '--arg': 'pair', '--argjson': 'pair' },
           // jq auto-loads ~/.jq and its filters can read the process env;
           // an isolated empty HOME keeps both from leaking anything real.
           isolateHome: true,
           firstPositional: 'any' },
  // -c is NOT here: the paths listed INSIDE a checksum file are not jailed,
  // making -c an existence/hash oracle for any file on disk. It needs approval.
  shasum: { flags: ['-p', '-U', '-q', '-s', '-b', '-t', '-x'], valueFlags: { '-a': 'int' }, longFlags: ['--help', '--version'] },
  md5:   { flags: ['-q', '-r', '-p'], valueFlags: { '-s': 'text' }, longFlags: [] },
};

const PROCESS_ALLOWLIST = new Set(Object.keys(PROGRAM_GRAMMARS));

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
    // Read-only extra roots are EMPTY by default: the agent sees its workspace
    // and nothing else. The human adds roots deliberately (config.json), and
    // the bridge's own install dir is denied regardless (see jail.js).
    read_roots_extra: [],
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
    if (onDisk && typeof onDisk === 'object' && !Array.isArray(onDisk)) {
      // Whitelisted keys with type/range checks - never a wholesale assign:
      // config.json feeds the jail roots and the bind address, and a bad
      // value here (crafted installer flag, hand edit gone wrong) must not
      // silently widen the attack surface.
      if (Number.isInteger(onDisk.port) && onDisk.port >= 1024 && onDisk.port <= 65535) cfg.port = onDisk.port;
      if (typeof onDisk.bind === 'string') {
        // Loopback only, always. A non-loopback bind undoes the whole
        // threat model; refuse it rather than trusting the file.
        if (['127.0.0.1', '::1', 'localhost'].includes(onDisk.bind)) cfg.bind = onDisk.bind;
      }
      if (typeof onDisk.profile_default === 'string' && PROFILES[onDisk.profile_default]) {
        cfg.profile_default = onDisk.profile_default;
      }
      if (typeof onDisk.enable_shell === 'boolean') cfg.enable_shell = onDisk.enable_shell;
      if (Array.isArray(onDisk.read_roots_extra)) {
        cfg.read_roots_extra = onDisk.read_roots_extra
          .filter(r => typeof r === 'string' && path.isAbsolute(r) && r.length > 1 && r.length <= 512);
      }
      if (Array.isArray(onDisk.tunnel_host_suffixes)) {
        // Force the leading dot: 'trycloudflare.com' would also match
        // 'evil-trycloudflare.com'; '.trycloudflare.com' cannot.
        cfg.tunnel_host_suffixes = onDisk.tunnel_host_suffixes
          .filter(x => typeof x === 'string' && x.length > 1 && x.length <= 128)
          .map(x => x.startsWith('.') ? x : '.' + x);
      }
      if (Number.isInteger(onDisk.max_body_bytes)) cfg.max_body_bytes = Math.min(Math.max(onDisk.max_body_bytes, 1024), 64 * 1024 * 1024);
      if (Number.isInteger(onDisk.max_read_bytes)) cfg.max_read_bytes = Math.min(Math.max(onDisk.max_read_bytes, 4096), 256 * 1024 * 1024);
      if (Number.isInteger(onDisk.exec_timeout_ms_max)) cfg.exec_timeout_ms_max = Math.min(Math.max(onDisk.exec_timeout_ms_max, 5000), 600000);
      if (Number.isInteger(onDisk.rate_limit_per_minute)) cfg.rate_limit_per_minute = Math.min(Math.max(onDisk.rate_limit_per_minute, 10), 10000);
    }
  } catch {}
  cfg.install_dir = installDir; // never overridable from disk
  return cfg;
}

module.exports = { PROFILES, PROCESS_ALLOWLIST, PROGRAM_GRAMMARS, scrubbedEnv, defaultConfig, loadConfig };
