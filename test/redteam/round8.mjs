// Round 8: regression suite for the round-4 root redesign (frozen snapshots,
// shrunk grammars, revived shell.exec, process-group timeout kill).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { Approvals } from '../../src/lib/approvals.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt8-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(tmp, 'config.json'), JSON.stringify({ enable_shell: true }));

let inst = await startServer(tmp, { port: 0 });
const base = `http://127.0.0.1:${inst.port}`;
const keystore = new KeyStore(path.join(tmp, 'secrets'));
const approvals = new Approvals(path.join(tmp, 'approvals'));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name} ${detail}`); }
}
async function pairedClient(name, profile = 'developer', url = base) {
  const code = keystore.createPairingCode(profile);
  const c = new BridgeClient(url);
  const r = await c.pair(code, name);
  if (r.status !== 200) throw new Error('pair failed: ' + JSON.stringify(r));
  return c;
}
const isPending = (r) => r.rpc?.result?.structuredContent?.status === 'pending_approval';
const isErr = (r, re) => !!r.rpc?.error && (!re || re.test(JSON.stringify(r.rpc.error)));

const cA = await pairedClient('r8-a');
const cB = await pairedClient('r8-b');
const cC = await pairedClient('r8-c');
const cD = await pairedClient('r8-d');

console.log('\n=== R8-1: very long paths bind and execute (jail walk + freeze) ===');
{
  // ~1400-char relative path, deeper than any shell-sane limit
  let rel = '';
  for (let i = 0; i < 28; i++) rel += `d${String(i).padStart(2, '0')}_${'x'.repeat(40)}/`;
  fs.mkdirSync(path.join(ws, rel), { recursive: true });
  fs.writeFileSync(path.join(ws, rel, 'run.sh'), 'echo deep-ok\n');
  const r = await cA.call('process.run', { argv: ['sh', rel + 'run.sh'] });
  check('long-path script requires approval', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  approvals.decide(apid, 'approve');
  const st = await cA.call('approval.status', { approval_id: apid });
  const s = st.rpc?.result?.structuredContent;
  check('long-path frozen copy executes', s?.status === 'executed' && s?.result?.stdout === 'deep-ok\n', JSON.stringify(s).slice(0, 160));

  // A >1024-char path-intended operand that does not exist must refuse cleanly
  const r2 = await cA.call('process.run', { argv: ['sh', 'a'.repeat(1100) + '.sh'] });
  check('1100-char missing operand refused, no crash', isErr(r2, /unbindable|does not exist|too long|jail/i), JSON.stringify(r2.rpc).slice(0, 160));
}

console.log('\n=== R8-2: concurrent writer during approval cannot affect the frozen run ===');
{
  fs.writeFileSync(path.join(ws, 'race.sh'), 'echo v1\n');
  const r = await cB.call('process.run', { argv: ['sh', 'race.sh'] });
  check('race.sh requires approval', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  // hammer the file with rewrites before AND after the human decision
  let stop = false;
  const writer = setInterval(() => {
    try { fs.writeFileSync(path.join(ws, 'race.sh'), 'echo PWNED-' + Math.random() + '\n'); } catch {}
  }, 1);
  await new Promise(r2 => setTimeout(r2, 30));
  approvals.decide(apid, 'approve');
  const st = await cB.call('approval.status', { approval_id: apid });
  stop = true; clearInterval(writer);
  const s = st.rpc?.result?.structuredContent;
  check('executed output is exactly the frozen v1', s?.status === 'executed' && s?.result?.stdout === 'v1\n', JSON.stringify(s?.result?.stdout));
  fs.writeFileSync(path.join(ws, 'race.sh'), 'echo v1\n');
}

console.log('\n=== R8-3: ~ operands are rejected, never expanded ===');
{
  for (const argv of [['sh', '~/evil.sh'], ['cat', '~/.ssh/id_rsa'], ['ls', '~']]) {
    const r = await cC.call('process.run', { argv });
    check(`${JSON.stringify(argv)} refused`, isErr(r) && !isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  }
}

console.log('\n=== R8-4: shell.exec works in LIMITED mode - gated by approval, then runs ===');
{
  const r = await cC.call('shell.exec', { command: 'echo limited-ok' });
  check('shell.exec requires approval in LIMITED', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  approvals.decide(apid, 'approve');
  const st = await cC.call('approval.status', { approval_id: apid });
  const s = st.rpc?.result?.structuredContent;
  check('approved shell.exec executes', s?.status === 'executed', JSON.stringify(s).slice(0, 160));
  check('stdout is limited-ok', s?.result?.stdout === 'limited-ok\n', JSON.stringify(s?.result?.stdout));
  // denied approval never runs
  const r2 = await cC.call('shell.exec', { command: 'touch SHELLPWNED' });
  const apid2 = r2.rpc.result.structuredContent.approval_id;
  approvals.decide(apid2, 'deny');
  const st2 = await cC.call('approval.status', { approval_id: apid2 });
  check('denied shell.exec stays denied', st2.rpc?.result?.structuredContent?.status === 'denied');
  check('denied command never ran', !fs.existsSync(path.join(ws, 'SHELLPWNED')));
}

console.log('\n=== R8-5: uniq/jq approval flow end-to-end (frozen operand) ===');
{
  fs.writeFileSync(path.join(ws, 'data.txt'), 'b\na\na\n');
  const r = await cD.call('process.run', { argv: ['uniq', 'data.txt'] });
  check('uniq requires approval', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  approvals.decide(apid, 'approve');
  fs.writeFileSync(path.join(ws, 'data.txt'), 'PWNED\n'); // post-approval edit
  const st = await cD.call('approval.status', { approval_id: apid });
  const s = st.rpc?.result?.structuredContent;
  check('uniq runs the FROZEN data.txt', s?.status === 'executed' && s?.result?.stdout === 'b\na\n', JSON.stringify(s?.result?.stdout));
  fs.writeFileSync(path.join(ws, 'data.txt'), 'b\na\na\n');
}

console.log('\n=== R8-6: timeout kills the whole process GROUP (no orphan grandchildren) ===');
{
  // full-mode server so shell.exec runs directly with a short timeout
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt8full-'));
  const ws2 = path.join(tmp2, 'workspace');
  fs.mkdirSync(ws2, { recursive: true });
  fs.writeFileSync(path.join(tmp2, 'config.json'), JSON.stringify({ mode: 'full', port: 17898 }));
  const inst2 = await startServer(tmp2, { port: 0 });
  const base2 = `http://127.0.0.1:${inst2.port}`;
  const ks2 = new KeyStore(path.join(tmp2, 'secrets'));
  const c2 = new BridgeClient(base2);
  const pr = await c2.pair(ks2.createPairingCode('developer'), 'r8-full');
  check('full-mode pair works', pr.status === 200, 'got ' + pr.status);
  const marker = path.join(ws2, 'ORPHAN-LIVED');
  const r = await c2.call('shell.exec', {
    command: `(sleep 2; touch '${marker}') & sleep 30`,
    timeout_ms: 1000,
  });
  const s = r.rpc?.result?.structuredContent;
  check('command timed out', s?.timed_out === true, JSON.stringify(s).slice(0, 160));
  await new Promise(r2 => setTimeout(r2, 2600)); // grandchild would fire at +2s
  check('orphaned grandchild was killed with the group', !fs.existsSync(marker));
  await new Promise(r => inst2.server.close(r));
}

await new Promise(r => inst.server.close(r));
console.log(`\nROUND 8: ${pass} passed, ${fail} failed`);
if (fail) { console.log('FAILED: ' + failures.join(' | ')); process.exit(1); }
