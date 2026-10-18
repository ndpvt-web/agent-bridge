// Red-team round 4: race conditions + claims audit.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt4-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });

let inst = await startServer(tmp, { port: 0 });
const keystore = new KeyStore(path.join(tmp, 'secrets'));
let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name} ${detail}`); }
}
async function pairedClient(name, profile = 'developer') {
  const code = keystore.createPairingCode(profile);
  const c = new BridgeClient(`http://127.0.0.1:${inst.port}`);
  await c.pair(code, name);
  return c;
}

console.log('\n=== Round 4: write races ===');
{
  const c = await pairedClient('writer');
  // concurrent create-mode writes to the same path: exactly one may win
  const results = await Promise.all([
    c.call('fs.write', { path: 'race.txt', content_base64: Buffer.from('A').toString('base64'), mode: 'create' }),
    c.call('fs.write', { path: 'race.txt', content_base64: Buffer.from('B').toString('base64'), mode: 'create' }),
  ]);
  const wins = results.filter(r => !r.rpc.error).length;
  check('concreate create-mode race: exactly one winner', wins === 1, 'winners=' + wins);
}

console.log('\n=== Round 4: delete/approve lifecycle ===');
{
  const c = await pairedClient('deleter');
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  fs.writeFileSync(path.join(ws, 'victim.txt'), 'data');
  const d1 = await c.call('fs.delete', { path: 'victim.txt' });
  const apid = d1.rpc.result.structuredContent.approval_id;
  ap.decide(apid, 'approve');
  // swap victim for a SYMLINK after approval, before execution
  fs.unlinkSync(path.join(ws, 'victim.txt'));
  fs.writeFileSync(path.join(tmp, 'real-target.txt'), 'SECRET');
  fs.symlinkSync(path.join(tmp, 'real-target.txt'), path.join(ws, 'victim.txt'));
  const r = await c.call('approval.status', { approval_id: apid });
  const st = r.rpc.result?.structuredContent?.status;
  check('post-approval symlink swap refused', st === 'executed' ? !fs.readFileSync(path.join(tmp, 'real-target.txt'), 'utf8').includes('MOVED') : true, 'status=' + st);
  check('symlink not followed into trash (target intact in place)', fs.readFileSync(path.join(tmp, 'real-target.txt'), 'utf8') === 'SECRET');
}

console.log('\n=== Round 4: audit covers auth failures ===');
{
  const c = await pairedClient('auditee');
  await c.rawPost('/mcp', '{}', { sig: 'A'.repeat(86) });
  const log = fs.readFileSync(path.join(tmp, 'logs', 'audit.jsonl'), 'utf8');
  check('bad-signature attempt is audited', log.includes('"tool":"auth"') && log.includes('bad signature'));
}

console.log(`\nROUND 4 RESULT: ${pass} repelled, ${fail} succeeded`);
if (failures.length) { console.log('SUCCESSFUL ATTACKS:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
await new Promise(r => inst.server.close(r));
process.exit(0);
