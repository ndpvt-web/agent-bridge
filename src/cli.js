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
      console.log(`${a.revoked ? '[REVOKED] ' : ''}${a.id}  ${a.name}  profile=${a.profile}  paired=${a.created_at}${a.last_seen_at ? '  last_seen=' + a.last_seen_at : ''}`);
    }
    break;
  }
  case 'allow':
  case 'disallow': {
    if (!rest[0] || !rest[1]) { console.error('usage: agent-bridge ' + cmd + ' <agent_id> <program>'); process.exit(1); }
    const prog = path.basename(rest[1]); // bare names only, resolved via system PATH
    const ok = keystore.setProgramAllowed(rest[0], prog, cmd === 'allow');
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
    for (const a of list) {
      console.log(`${a.id}  [${a.kind}] from ${a.agent_id}`);
      console.log(`    ${a.summary}`);
      console.log(`    expires ${new Date(a.expires_at).toISOString()}`);
    }
    break;
  }
  case 'approve':
  case 'deny': {
    if (!rest[0]) { console.error('usage: agent-bridge ' + cmd + ' <approval_id>'); process.exit(1); }
    const r = approvals.decide(rest[0], cmd);
    if (!r.ok) { console.error('Cannot ' + cmd + ': ' + r.reason); process.exit(1); }
    console.log(cmd === 'approve' ? 'Approved. The agent executes it on next poll.' : 'Denied.');
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
        console.log(`  #${e.seq} ${e.ts} ${e.agent || '-'} ${e.tool} ${e.decision}${e.detail ? ' — ' + e.detail : ''}`);
      }
    } catch { console.log('No audit log yet.'); }
    break;
  }
  case 'status': {
    console.log('AgentBridge status');
    console.log('  install dir : ' + installDir);
    console.log('  bind        : ' + (cfg.bind || '127.0.0.1') + ':' + cfg.port + ' (loopback only)');
    console.log('  profile     : ' + (cfg.profile_default || 'workspace'));
    console.log('  shell       : ' + (cfg.enable_shell ? 'ENABLED (approval-gated)' : 'disabled'));
    console.log('  workspace   : ' + cfg.workspace_root);
    console.log('  agents      : ' + keystore.listAgents().filter(a => !a.revoked).length + ' active');
    break;
  }
  default:
    usage();
    process.exit(cmd ? 1 : 0);
}
