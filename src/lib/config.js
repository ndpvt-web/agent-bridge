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
  stat:  { flags: ['-l', '-x', '-L', '-r', '-s', '-q'], valueFlags: { '-f': 'text', '-t': 'text' }, longFlags: ['--help', '--version'] },
  which: { flags: ['-a', '-s'], pathArgs: 'any', longFlags: ['--help'] },
  uname: { flags: '-a -m -n -p -r -s -v'.split(' '), longFlags: ['--help'], maxArgs: 0 },
  sw_vers: { flags: [], longFlags: [], maxArgs: 0 },
  df:    { flags: ['-h', '-k', '-H', '-i', '-l', '-m', '-g', '-b'], longFlags: ['--help'] },
  du:    { flags: ['-h', '-s', '-a', '-x', '-k', '-m'], valueFlags: { '-d': 'int', '-t': 'text' }, longFlags: ['--help', '--version'] },
  date:  { flags: ['-u', '-R', '-r', '-n', '-j'], plusArgs: true, pathArgs: 'none', longFlags: ['--help'], maxArgs: 1 },
  echo:  { flags: ['-n', '-e', '-E'], pathArgs: 'any', longFlags: ['--help', '--version'] },
  printf: { flags: [], pathArgs: 'any', longFlags: ['--help'] },
  grep:  { flags: ['-i','-v','-n','-c','-l','-L','-w','-x','-E','-F','-o','-r','-R','-h','-H','-q','-s','-z'],
           valueFlags: { '-m': 'int', '-A': 'int', '-B': 'int', '-C': 'int', '-e': 'text' },
           longFlags: ['--help', '--version'], firstPositional: 'any' },
  rg:    { flags: '-i -v -n -c -l -w -x -S -F -o -h -H -q -s -u -N -M -j -0'.split(' '),
           valueFlags: { '-m': 'int', '-A': 'int', '-B': 'int', '-C': 'int', '-e': 'text', '-t': 'text', '-T': 'text', '-g': 'text' },
           longFlags: ['--help', '--version'], firstPositional: 'any' },
  sort:  { flags: '-n -r -u -f -R -c -m -b -d -i -h -g -z -s -V -M'.split(' '), longFlags: ['--help', '--version'] },
  uniq:  { flags: ['-c', '-d', '-u', '-i', '-z', '-D'], valueFlags: { '-f': 'int', '-s': 'int', '-w': 'int' }, longFlags: ['--help', '--version'] },
  diff:  { flags: '-u -c -q -r -i -w -b -y -p -a -e -n -s -l -t -E -B -Z -d'.split(' '),
           valueFlags: { '-U': 'int', '-C': 'int', '-L': 'text' }, longFlags: ['--help', '--version', '--brief', '--report-identical-files'] },
  jq:    { flags: ['-r','-c','-n','-e','-s','-R','-j','-M','-S','-C','-a'],
           longFlags: ['--help', '--version', '--raw-output', '--compact-output', '--null-input', '--exit-status', '--slurp', '--raw-input', '--join-output', '--monochrome-output', '--sort-keys', '--tab'],
           valueFlags: { '--indent': 'int', '--arg': 'pair', '--argjson': 'pair' },
           firstPositional: 'any' },
  shasum: { flags: ['-p', '-U', '-q', '-s', '-c', '-b', '-t', '-x'], valueFlags: { '-a': 'int' }, longFlags: ['--help', '--version'] },
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
    Object.assign(cfg, onDisk);
    cfg.install_dir = installDir; // never overridable from disk
  } catch {}
  return cfg;
}

module.exports = { PROFILES, PROCESS_ALLOWLIST, PROGRAM_GRAMMARS, scrubbedEnv, defaultConfig, loadConfig };
