// E2E: a real agent's first session, exactly as a cloud agent would experience it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../src/server.js';
import { KeyStore } from '../src/lib/keystore.js';
import { BridgeClient } from './client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-e2e-'));
let inst = await startServer(tmp, { port: 0 });
const keystore = new KeyStore(path.join(tmp, 'secrets'));
let pass = 0, fail = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}

// The human runs: agent-bridge pair --profile developer
const code = keystore.createPairingCode('developer');

// The agent receives: tunnel URL + pairing code. It must figure out the rest.
const agent = new BridgeClient(`http://127.0.0.1:${inst.port}`);
const pairRes = await agent.pair(code, 'claude-cloud');
check('pairing works with just URL + code', pairRes.status === 200 && pairRes.data.agent_id);

const init = await agent.rpc('initialize', { protocolVersion: '2025-06-18' });
check('initialize negotiates', init.data.result?.serverInfo?.name === 'agent-bridge');

const list = await agent.rpc('tools/list');
check('tools/list returns catalog', (list.data.result?.tools || []).length >= 8);

const info = await agent.call('system.info');
check('system.info works', info.rpc.result?.structuredContent?.bridge?.version === '2.1.0');

// Agent workflow: create a project file, read it back, list the dir
const w = await agent.call('fs.write', { path: 'project/notes.md', content_base64: Buffer.from('# hello\n').toString('base64') });
check('write project file', w.rpc.result?.structuredContent?.bytes === 8);
const r = await agent.call('fs.read', { path: 'project/notes.md' });
check('read it back', r.rpc.result?.structuredContent?.content === '# hello\n');
const l = await agent.call('fs.list', { path: 'project' });
check('list dir', l.rpc.result?.structuredContent?.items?.[0]?.name === 'notes.md');

// Developer flow: git needs approval -> human approves -> result flows back
const g = await agent.call('process.run', { argv: ['git', '--version'] });
check('git --version requires approval', g.rpc.result?.structuredContent?.status === 'pending_approval');
const apid = g.rpc.result.structuredContent.approval_id;
// human: agent-bridge approve <id>
const { Approvals } = await import('../src/lib/approvals.js');
new Approvals(path.join(tmp, 'approvals')).decide(apid, 'approve');
const g2 = await agent.call('approval.status', { approval_id: apid });
check('approved git executes and returns output', g2.rpc.result?.structuredContent?.result?.stdout?.includes('git version'), JSON.stringify(g2.rpc.result).slice(0, 200));

// The audit log tells the whole story
const { AuditLog } = await import('../src/lib/audit.js');
const v = AuditLog.verify(path.join(tmp, 'logs', 'audit.jsonl'), keystore.auditKey());
check('full session audit chain intact', v.ok && v.entries >= 5, JSON.stringify(v));

console.log(`\nE2E RESULT: ${pass} passed, ${fail} failed`);
await new Promise(r => inst.server.close(r));
process.exit(fail ? 1 : 0);
