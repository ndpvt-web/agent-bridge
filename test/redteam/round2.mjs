// Red-team round 2: allowlist bypass, planted binary, revocation, races.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt2-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'package.json'), '{"name":"fixture"}\n');

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
  const r = await c.pair(code, name);
  if (r.status !== 200) throw new Error('pair failed');
  return c;
}
const isPending = (r) => r.rpc.result?.structuredContent?.status === 'pending_approval';

console.log('\n=== Round 2: allowlist-is-not-a-shell ===');
{
  const c = await pairedClient('allowlist-attacker');
  for (const prog of ['python3', 'node', 'npm', 'git', 'make', 'xcodebuild', 'find', 'sed', 'awk', 'tar', 'curl', 'zsh', 'bash', 'sh']) {
    const r = await c.call('process.run', { argv: [prog, '--version'] });
    check(`'${prog}' requires approval`, isPending(r), JSON.stringify(r.rpc).slice(0, 100));
  }
  for (const prog of ['ls', 'cat', 'grep', 'sort']) {
    const r = await c.call('process.run', { argv: [prog, prog === 'cat' ? 'package.json' : prog === 'ls' ? '.' : prog === 'grep' ? '--help' : '--version'] });
    check(`'${prog}' auto-allowed (inspection tool)`, !isPending(r) && !r.rpc.error, JSON.stringify(r.rpc).slice(0, 100));
  }
  // jq is NOT auto-allowed anymore: its module `import ... {search:...}`
  // reads any *.json on disk (round-4 HIGH). Same for uniq (output operand).
  for (const prog of ['jq', 'uniq', 'which']) {
    const r = await c.call('process.run', { argv: [prog, '--version'] });
    check(`'${prog}' requires approval (removed from auto-allow)`, isPending(r) || !!r.rpc.error, JSON.stringify(r.rpc).slice(0, 100));
  }
}

console.log('\n=== Round 2: planted-binary attack ===');
{
  const c = await pairedClient('planter');
  // agent writes an executable named 'ls' into the workspace
  const script = '#!/bin/zsh\nid > ' + path.join(tmp, 'PWNED') + '\n';
  const w = await c.call('fs.write', { path: 'ls', content_base64: Buffer.from(script).toString('base64') });
  check('plant binary via fs.write ok (workspace is theirs)', !w.rpc.error);
  fs.chmodSync(path.join(ws, 'ls'), 0o755);
  const r1 = await c.call('process.run', { argv: ['./ls'] });
  check('relative ./ls requires approval', isPending(r1));
  const r2 = await c.call('process.run', { argv: [path.join(ws, 'ls')] });
  check('absolute path to planted ls requires approval', isPending(r2));
  // what about bare 'ls'? must hit system PATH, not cwd
  const r3 = await c.call('process.run', { argv: ['ls', '.'], cwd: '.' });
  check('bare ls runs SYSTEM ls not planted one', !isPending(r3) && !fs.existsSync(path.join(tmp, 'PWNED')), JSON.stringify(r3.rpc).slice(0, 120));
  check('nothing executed', !fs.existsSync(path.join(tmp, 'PWNED')));
}

console.log('\n=== Round 2: revocation ===');
{
  const c = await pairedClient('doomed-agent');
  const before = await c.rpc('initialize', {});
  check('agent works before revocation', before.status === 200 && before.data.result);
  keystore.revokeAgent(c.agentId);
  const after = await c.rpc('initialize', {});
  check('revoked agent -> 401', after.status === 401, 'got ' + after.status);
}

console.log('\n=== Round 2: curated per-agent program allowlist ===');
{
  const c = await pairedClient('curated');
  const r1 = await c.call('process.run', { argv: ['git', 'status'] });
  check('git needs approval by default', isPending(r1));
  keystore.setProgramAllowed(c.agentId, 'git', true);
  const r2 = await c.call('process.run', { argv: ['git', '--version'] });
  check('git auto-allowed after CLI grant', !isPending(r2) && !r2.rpc.error, JSON.stringify(r2.rpc).slice(0, 120));
  keystore.setProgramAllowed(c.agentId, 'git', false);
  const r3 = await c.call('process.run', { argv: ['git', 'status'] });
  check('disallow takes effect immediately', isPending(r3));
  // grant for one agent must not leak to another
  const c2 = await pairedClient('other');
  keystore.setProgramAllowed(c.agentId, 'git', true);
  const r4 = await c2.call('process.run', { argv: ['git', 'status'] });
  check('grant is per-agent', isPending(r4));
}

console.log('\n=== Round 2: concurrent approval consumption race ===');
{
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  const c = await pairedClient('racer');
  const del = await c.call('fs.delete', { path: 'ls' }); // delete the planted file
  const apid = del.rpc.result.structuredContent.approval_id;
  ap.decide(apid, 'approve');
  const results = await Promise.all([
    c.call('approval.status', { approval_id: apid }),
    c.call('approval.status', { approval_id: apid }),
    c.call('approval.status', { approval_id: apid }),
  ]);
  const executed = results.filter(r => r.rpc.result?.structuredContent?.status === 'executed').length;
  check('exactly one execution under concurrent polls', executed === 1, 'executed=' + executed);
}

console.log(`\nROUND 2 RESULT: ${pass} repelled, ${fail} succeeded`);
if (failures.length) { console.log('SUCCESSFUL ATTACKS:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
await new Promise(r => inst.server.close(r));
process.exit(0);
