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
const DANGEROUS_PROGRAMS = new Set(['node','python3','python','ruby','perl','php','zsh','bash','sh','npm','npx','yarn','make','xcodebuild','swift','swiftc','xcrun','git','curl','wget','osascript','defaults','launchctl','crontab','tar','zip','find','sed','awk','ssh','scp','rsync','docker','brew','vim','vi','nvim','view','less','more','man','nano','emacs','ed','ex','sqlite3','script','env','ftp','telnet','lldb','gdb','screen','tmux','expect','rg','xargs','parallel','watch','nohup','nice','stdbuf','timeout','java','jshell','deno','bun','lua','Rscript','tclsh','wish','at','batch','open','automator','shortcuts','sudo','doas','su','sort','dd','lldb']);

// Print a value exactly as stored - no control characters reach the terminal,
// no padding tricks, no forged lines. JSON.stringify covers C0/C1; Unicode
// format characters (bidi overrides, zero-width, U+2028/9) are escaped on
// top - a Trojan-Source-style spoof of the approval display is otherwise
// possible.
function escapeFormatChars(str) {
  return str.replace(/[\p{Cf}\u2028\u2029]/gu, c => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0'));
}
function showEscaped(label, val) {
  console.log('  ' + label + ': ' + escapeFormatChars(JSON.stringify(String(val))));
}

function showApproval(a) {
  console.log(`${a.id}  [${a.kind}] from ${a.agent_id}  status=${a.status}`);
  showEscaped('summary', a.summary);
  showEscaped('payload', JSON.stringify(a.payload));
  console.log('  expires ' + new Date(a.expires_at).toISOString());
}

function confirmInteractive(question) {
  if (process.argv.includes('--yes')) return true;
  if (!process.stdin.isTTY) return false;
  process.stdout.write(question + ' [y/N] ');
  const fs = require('fs');
  const buf = Buffer.alloc(64);
  let n = 0;
  try { n = fs.readSync(0, buf, 0, 64, null); } catch { return false; }
  return buf.slice(0, n).toString().trim().toLowerCase() === 'y';
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
  mode [limited|full]                             Show or switch the permission mode
  status                                          Show config summary (no secrets)`);
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
    console.log('Paste it to your cloud agent together with your tunnel URL.');
    break;
  }
  case 'agents': {
    const agents = keystore.listAgents();
    if (!agents.length) { console.log('No paired agents.'); break; }
    for (const a of agents) {
      console.log(`${a.revoked ? '[REVOKED] ' : ''}${a.id}  ${escapeFormatChars(JSON.stringify(a.name))}  profile=${a.profile}  paired=${a.created_at}${a.last_seen_at ? '  last_seen=' + a.last_seen_at : ''}`);
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
    console.log(keystore.revokeAgent(rest[0]) ? 'Revoked ' + rest[0] : 'No such agent.');
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
    if (rec) showApproval(rec);
    if (cmd === 'approve') {
      console.log('');
      console.log('  Approved actions run as you on this Mac. An approval is valid');
      console.log('  for 10 minutes and executes exactly once.');
      if (!confirmInteractive('Approve this exact action?')) { console.log('Aborted (not confirmed).'); process.exit(1); }
    }
    const r = approvals.decide(rest[0], cmd);
    if (!r.ok) { console.error('Cannot ' + cmd + ': ' + r.reason); process.exit(1); }
    audit.record({ agent: rec ? rec.agent_id : null, tool: 'cli.' + cmd, decision: cmd + 'd', detail: rest[0] + (rec ? ' [' + rec.kind + '] ' + String(rec.summary).slice(0, 200) : '') });
    console.log(cmd === 'approve' ? 'Approved. Valid 10 minutes; executes once, on the agent\'s next poll.' : 'Denied.');
    break;
  }
  case 'audit': {
    const logPath = path.join(installDir, 'logs', 'audit.jsonl');
    if (rest.includes('--verify')) {
      try {
        const r = AuditLog.verify(logPath, keystore.auditKey());
        console.log(r.ok ? `Audit log intact (${r.entries} entries).` : `AUDIT LOG TAMPERED at entry ${r.at}: ${r.reason}`);
        process.exit(r.ok ? 0 : 2);
      } catch { console.log('No audit log yet.'); }
      break;
    }
    try {
      const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
      console.log(lines.length + ' audit entries. Last 10:');
      for (const l of lines.slice(-10)) {
        const e = JSON.parse(l);
        console.log(`  #${e.seq} ${e.ts} ${e.agent || '-'} ${e.tool} ${e.decision}${e.detail ? ' - ' + escapeFormatChars(JSON.stringify(e.detail)) : ''}`);
      }
    } catch { console.log('No audit log yet.'); }
    break;
  }
  case 'status': {
    console.log('AgentBridge status');
    console.log('  install dir : ' + installDir);
    const bind = cfg.bind || '127.0.0.1';
    console.log('  bind        : ' + bind + ':' + cfg.port + (bind === '127.0.0.1' ? ' (loopback only)' : ' *** NOT LOOPBACK - exposed to the network ***'));
    console.log('  profile     : ' + (cfg.profile_default || 'workspace'));
    console.log('  mode        : ' + (cfg.mode === 'full' ? '*** FULL - no jail, no approvals ***' : 'limited (jail + approvals)'));
    console.log('  shell       : ' + (cfg.enable_shell || cfg.mode === 'full' ? 'ENABLED' + (cfg.mode === 'full' ? ' (full mode, no approval)' : ' (approval-gated)') : 'disabled'));
    console.log('  workspace   : ' + cfg.workspace_root);
    console.log('  read roots  : ' + JSON.stringify([cfg.workspace_root, ...(cfg.read_roots_extra || [])]));
    console.log('  agents      : ' + keystore.listAgents().filter(a => !a.revoked).length + ' active');
    try { console.log('  tunnel URL  : ' + fs.readFileSync(path.join(installDir, '.tunnel-url'), 'utf8').trim()); } catch { console.log('  tunnel URL  : (unknown yet - check logs/tunnel.log)'); }
    break;
  }
  case 'mode': {
    const configPath = path.join(installDir, 'config.json');
    let onDisk = {};
    try { onDisk = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch {}
    if (!rest[0]) {
      console.log('Permission mode: ' + (cfg.mode === 'full' ? 'FULL (no jail, no approvals - every agent has full control)' : 'LIMITED (jail + allowlist + your approvals)'));
      console.log('Switch: agent-bridge mode limited|full');
      break;
    }
    if (rest[0] !== 'limited' && rest[0] !== 'full') { console.error('usage: agent-bridge mode limited|full'); process.exit(1); }
    if (rest[0] === 'full') {
      console.log('FULL mode turns OFF the filesystem jail, the command allowlist and EVERY');
      console.log('approval. Any paired agent - or anyone who compromises one - can run ANY');
      console.log('command as you on this Mac, exactly like the old v1. This stays logged.');
      if (!confirmInteractive('Switch to FULL mode?')) { console.log('Aborted (not confirmed).'); process.exit(1); }
    }
    onDisk.mode = rest[0];
    fs.writeFileSync(configPath, JSON.stringify(onDisk, null, 2), { mode: 0o600 });
    audit.record({ agent: null, tool: 'cli.mode', decision: 'mode_' + rest[0], detail: 'permission mode set to ' + rest[0] });
    console.log('Mode set to ' + rest[0].toUpperCase() + '. Restart the bridge to apply:');
    console.log('  launchctl unload ~/Library/LaunchAgents/com.agentbridge.server.plist && launchctl load ~/Library/LaunchAgents/com.agentbridge.server.plist');
    break;
  }
  case 'trash': {
    try {
      const lines = fs.readFileSync(path.join(installDir, 'trash', 'manifest.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
      console.log(lines.length + ' items in trash (newest last):');
      for (const l of lines.slice(-20)) {
        const e = JSON.parse(l);
        console.log(`  ${e.ts}  ${e.original}  ->  ${e.trashed_as}`);
      }
      console.log('Restore with: mv <trashed_as> <original>');
    } catch { console.log('Trash is empty.'); }
    break;
  }
  default:
    usage();
    process.exit(cmd ? 1 : 0);
}
