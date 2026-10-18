#!/usr/bin/env node
'use strict';
// agent-bridge CLI: pairing, approvals, agent management, audit verification.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { KeyStore } = require('./lib/keystore');
const { Approvals } = require('./lib/approvals');
const { AuditLog } = require('./lib/audit');
const { loadConfig, PROFILES } = require('./lib/config');

const installDir = process.env.AGENT_BRIDGE_HOME || path.join(os.homedir(), 'agent-bridge');
const keystore = new KeyStore(path.join(installDir, 'secrets'));
const approvals = new Approvals(path.join(installDir, 'approvals'));
const cfg = loadConfig(installDir);
const audit = new AuditLog(path.join(installDir, 'logs', 'audit.jsonl'), keystore.auditKey());

// Programs that are shells in disguise: granting them to an agent grants
// full code execution for that agent. We allow it - the human owns the Mac -
// but never silently.
const DANGEROUS_PROGRAMS = new Set(['node','python3','python','ruby','perl','php','zsh','bash','sh','dash','ksh','npm','npx','yarn','pip','pip3','cargo','go','make','xcodebuild','swift','swiftc','xcrun','gcc','cc','clang','git','curl','wget','osascript','defaults','launchctl','crontab','tar','zip','find','sed','awk','ssh','scp','rsync','docker','brew','vim','vi','nvim','view','less','more','man','nano','emacs','ed','ex','sqlite3','script','env','ftp','telnet','nc','socat','lldb','gdb','screen','tmux','expect','rg','xargs','parallel','watch','nohup','nice','stdbuf','timeout','java','jshell','deno','bun','lua','Rscript','tclsh','wish','at','batch','open','automator','shortcuts','sudo','doas','su','sort','dd','cp','mv','ln','tee','install','ditto','chmod','caffeinate','arch','time','security','sandbox-exec']);

// Print a value exactly as stored - nothing reaches the terminal raw.
// JSON.stringify covers C0 controls; escape the rest (C1 controls, DEL,
// Unicode format characters, U+2028/9) on top: some terminals treat C1 as
// CSI, and bidi/zero-width chars are a Trojan-Source spoof of the display.
function escapeForTerminal(str) {
  return str.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, c => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0'));
}
function showEscaped(label, val) {
  console.log('  ' + label + ': ' + escapeForTerminal(JSON.stringify(String(val))));
}

function showApproval(a) {
  console.log(`${a.id}  [${a.kind}] from ${a.agent_id}  status=${a.status}`);
  showEscaped('summary', a.summary);
  showEscaped('payload', JSON.stringify(a.payload));
  console.log('  expires ' + new Date(a.expires_at).toISOString());
}

// Confirmation must come from the human at the keyboard: read /dev/tty
// directly, never stdin (a pipe must not be able to answer), and there is
// NO --yes bypass - any process running as you (including an approved
// script) would otherwise be able to approve its own requests.
function confirmInteractive(question) {
  let tty;
  try { tty = fs.openSync('/dev/tty', 'r+'); } catch { return false; }
  try {
    fs.writeSync(tty, question + ' [y/N] ');
    const buf = Buffer.alloc(64);
    const n = fs.readSync(tty, buf, 0, 64, null);
    return buf.slice(0, n).toString().trim().toLowerCase() === 'y';
  } catch { return false; }
  finally { try { fs.closeSync(tty); } catch {} }
}

// What the RUNNING server reports (config changes need a restart).
function runningInfo() {
  try {
    const info = JSON.parse(fs.readFileSync(path.join(installDir, 'run', 'server-info.json'), 'utf8'));
    let alive = false;
    try { process.kill(info.pid, 0); alive = true; } catch (e) { alive = e.code === 'EPERM'; }
    return { ...info, alive };
  } catch { return null; }
}

const [,, cmd, ...rest] = process.argv;

function usage() {
  console.log(`agent-bridge <command>

  pair [--profile readonly|workspace|developer]   Create a one-time pairing code (10 min TTL)
  agents                                          List paired agents
  revoke <agent_id>                               Revoke an agent immediately
  allow <agent_id> <program>                      Let this agent run <program> without approval
  disallow <agent_id> <program>                   Remove that permission
  pending                                         List pending approvals
  approve <approval_id>                           Approve a pending action
  deny <approval_id>                              Deny a pending action
  audit [--verify]                                Show audit log stats / verify integrity
  trash                                           List trashed files + how to restore them
  mode [safe|full]                                Show or switch the permission mode (safe = limited)
  status                                          Show config summary (no secrets)

  Uninstall: ~/agent-bridge/uninstall.sh`);
}

switch (cmd) {
  case 'pair': {
    let profile = cfg.profile_default || 'workspace';
    const i = rest.indexOf('--profile');
    if (i !== -1 && rest[i + 1]) profile = rest[i + 1];
    if (!PROFILES[profile]) { console.error('unknown profile: ' + profile); process.exit(1); }
    const code = keystore.createPairingCode(profile);
    console.log('Pairing code (valid 10 minutes, single use, profile: ' + profile + '):');
    console.log('');
    console.log('    ' + code);
    console.log('');
    console.log('Paste it to your cloud agent together with your tunnel URL (see: agent-bridge status).');
    break;
  }
  case 'agents': {
    const agents = keystore.listAgents();
    if (!agents.length) { console.log('No paired agents.'); break; }
    for (const a of agents) {
      console.log(`${a.revoked ? '[REVOKED] ' : ''}${a.id}  ${escapeForTerminal(JSON.stringify(a.name))}  profile=${a.profile}  paired=${a.created_at}${a.last_seen_at ? '  last_seen=' + a.last_seen_at : ''}`);
    }
    break;
  }
  case 'allow':
  case 'disallow': {
    if (!rest[0] || !rest[1]) { console.error('usage: agent-bridge ' + cmd + ' <agent_id> <program>'); process.exit(1); }
    const prog = path.basename(rest[1]); // bare names only, resolved via system PATH
    if (cmd === 'allow') {
      console.log('WARNING: a grant runs OUTSIDE the filesystem jail and the argument rules.');
      console.log(prog + ' will run with ANY arguments against your ENTIRE disk as you.');
      if (DANGEROUS_PROGRAMS.has(prog)) {
        console.log(prog + ' can also execute arbitrary code - this grants FULL CONTROL of this account.');
      }
      console.log('It stays logged; undo anytime: agent-bridge disallow ' + rest[0] + ' ' + prog);
      if (!confirmInteractive('Grant ' + prog + ' anyway?')) { console.log('Aborted (not confirmed).'); process.exit(1); }
    }
    const ok = keystore.setProgramAllowed(rest[0], prog, cmd === 'allow');
    if (ok) audit.record({ agent: rest[0], tool: 'cli.' + cmd, decision: cmd === 'allow' ? 'program_granted' : 'program_revoked', detail: prog });
    console.log(ok ? `${prog} ${cmd === 'allow' ? 'allowed' : 'disallowed'} for ${rest[0]}` : 'No such agent.');
    if (!ok) process.exit(1);
    break;
  }
  case 'revoke': {
    if (!rest[0]) { console.error('usage: agent-bridge revoke <agent_id>'); process.exit(1); }
    const ok = keystore.revokeAgent(rest[0]);
    if (ok) audit.record({ agent: rest[0], tool: 'cli.revoke', decision: 'agent_revoked', detail: rest[0] });
    console.log(ok ? 'Revoked ' + rest[0] : 'No such agent.');
    if (!ok) process.exit(1);
    break;
  }
  case 'pending': {
    const list = approvals._read().filter(a => a.status === 'pending' && Date.now() < a.expires_at);
    if (!list.length) { console.log('No pending approvals.'); break; }
    for (const a of list) showApproval(a);
    break;
  }
  case 'approve':
  case 'deny': {
    if (!rest[0]) { console.error('usage: agent-bridge ' + cmd + ' <approval_id>'); process.exit(1); }
    // Show EXACTLY what is being decided before deciding. Never approve blind.
    const rec = approvals._read().find(a => a.id === rest[0]);
    if (!rec) { console.error('Cannot ' + cmd + ': unknown approval id'); process.exit(1); }
    showApproval(rec);
    if (cmd === 'approve') {
      console.log('');
      console.log('  Approved actions run as you on this Mac. You have 120 seconds to');
      console.log('  approve a request; once approved it executes once, within 10 minutes.');
      if (!confirmInteractive('Approve this exact action?')) { console.log('Aborted (not confirmed).'); process.exit(1); }
    }
    const r = approvals.decide(rest[0], cmd);
    if (!r.ok) { console.error('Cannot ' + cmd + ': ' + r.reason); process.exit(1); }
    audit.record({ agent: rec.agent_id, tool: 'cli.' + cmd, decision: cmd + 'd', detail: rest[0] + ' [' + rec.kind + '] ' + String(rec.summary).slice(0, 200) });
    console.log(cmd === 'approve' ? 'Approved. Valid 10 minutes; executes once, on the agent\'s next poll.' : 'Denied.');
    break;
  }
  case 'audit': {
    const logPath = path.join(installDir, 'logs', 'audit.jsonl');
    if (rest.includes('--verify')) {
      let any = false, bad = null, total = 0;
      for (const f of [logPath + '.1', logPath]) {
        try {
          const r = AuditLog.verify(f, keystore.auditKey());
          any = true; total += r.entries;
          if (!r.ok) bad = `${path.basename(f)}: entry ${r.at}: ${r.reason}`;
        } catch { /* missing file */ }
      }
      if (!any) { console.log('No audit log yet.'); break; }
      console.log(bad ? 'AUDIT LOG TAMPERED - ' + bad : `Audit log intact (${total} entries).`);
      process.exit(bad ? 2 : 0);
      break;
    }
    try {
      const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
      console.log(lines.length + ' audit entries. Last 10:');
      for (const l of lines.slice(-10)) {
        const e = JSON.parse(l);
        console.log(`  #${e.seq} ${e.ts} ${e.agent || '-'} ${e.tool} ${e.decision}${e.detail ? ' - ' + escapeForTerminal(JSON.stringify(e.detail)) : ''}`);
      }
    } catch { console.log('No audit log yet.'); }
    break;
  }
  case 'status': {
    const running = runningInfo();
    console.log('AgentBridge status');
    console.log('  install dir : ' + installDir);
    console.log('  running     : ' + (running && running.alive ? 'yes (pid ' + running.pid + ', mode ' + running.mode.toUpperCase() + ', v' + running.version + ')' : 'no'));
    const bind = cfg.bind || '127.0.0.1';
    console.log('  bind        : ' + bind + ':' + cfg.port + (bind === '127.0.0.1' ? ' (loopback only)' : ' *** NOT LOOPBACK - exposed to the network ***'));
    console.log('  profile     : ' + (cfg.profile_default || 'workspace'));
    console.log('  mode (config): ' + (cfg.mode === 'full' ? '*** FULL - no jail, no approvals ***' : 'limited (jail + approvals)'));
    if (running && running.alive && running.mode !== cfg.mode) {
      console.log('  *** configured mode differs from the RUNNING mode (' + running.mode.toUpperCase() + ') - restart the bridge to apply ***');
    }
    console.log('  shell       : ' + (cfg.enable_shell || cfg.mode === 'full' ? 'ENABLED' + (cfg.mode === 'full' ? ' (full mode, no approval)' : ' (approval-gated)') : 'disabled'));
    console.log('  workspace   : ' + cfg.workspace_root);
    console.log('  read roots  : ' + JSON.stringify([cfg.workspace_root, ...(cfg.read_roots_extra || [])]));
    console.log('  agents      : ' + keystore.listAgents().filter(a => !a.revoked).length + ' active');
    try { console.log('  tunnel URL  : ' + fs.readFileSync(path.join(installDir, '.tunnel-url'), 'utf8').trim() + '  (quick tunnels change on reconnect)'); } catch { console.log('  tunnel URL  : (unknown yet - check logs/tunnel.log)'); }
    break;
  }
  case 'mode': {
    const configPath = path.join(installDir, 'config.json');
    let onDisk = {};
    const raw = (() => { try { return fs.readFileSync(configPath, 'utf8'); } catch { return null; } })();
    if (raw !== null) {
      try { onDisk = JSON.parse(raw); }
      catch { console.error('config.json is not valid JSON - fix it by hand (' + configPath + '); refusing to rewrite it.'); process.exit(1); }
    }
    if (!rest[0]) {
      console.log('Permission mode (configured): ' + (cfg.mode === 'full' ? 'FULL (no jail, no approvals - every agent with process rights has full control)' : 'LIMITED (jail + allowlist + your approvals)'));
      const running = runningInfo();
      if (running && running.alive) {
        console.log('Permission mode (RUNNING):    ' + running.mode.toUpperCase() + (running.mode !== cfg.mode ? '  *** restart the bridge to apply the configured mode ***' : ''));
      }
      console.log('Switch: agent-bridge mode safe|full');
      break;
    }
    const want = rest[0] === 'safe' ? 'limited' : rest[0];
    if (want !== 'limited' && want !== 'full') { console.error('usage: agent-bridge mode safe|full'); process.exit(1); }
    if (want === 'full') {
      console.log('FULL mode turns OFF the filesystem jail, the command allowlist and EVERY');
      console.log('approval. Any paired agent with process rights - or anyone who compromises');
      console.log('one - can run ANY command as you on this Mac, exactly like the old v1.');
      console.log('The switch is logged, but a full-mode agent can erase its own tracks from');
      console.log('everything EXCEPT the bridge state dir. After ANY full-mode session, run');
      console.log('agent-bridge audit --verify before trusting the log again.');
      if (!confirmInteractive('Switch to FULL mode?')) { console.log('Aborted (not confirmed).'); process.exit(1); }
    }
    onDisk.mode = want;
    fs.writeFileSync(configPath, JSON.stringify(onDisk, null, 2), { mode: 0o600 });
    audit.record({ agent: null, tool: 'cli.mode', decision: 'mode_' + want, detail: 'permission mode set to ' + want });
    console.log('Mode set to ' + want.toUpperCase() + ' (configured). Restart the bridge to apply:');
    console.log('  launchctl unload ~/Library/LaunchAgents/com.agentbridge.server.plist && launchctl load ~/Library/LaunchAgents/com.agentbridge.server.plist');
    break;
  }
  case 'trash': {
    try {
      const lines = fs.readFileSync(path.join(installDir, 'trash', 'manifest.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
      console.log(lines.length + ' items in trash (newest last):');
      for (const l of lines.slice(-20)) {
        const e = JSON.parse(l);
        // Filenames are agent-controlled: escape before printing.
        console.log(`  ${e.ts}  ${escapeForTerminal(JSON.stringify(e.original))}  ->  ${escapeForTerminal(JSON.stringify(e.trashed_as))}`);
      }
      console.log('Restore with: mv <trashed_as> <original>');
    } catch { console.log('Trash is empty.'); }
    break;
  }
  default:
    usage();
    process.exit(cmd ? 1 : 0);
}
