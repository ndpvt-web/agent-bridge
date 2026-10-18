// Round 7: regression suite for the four round-3 independent reviews
// (exec persona, installer/claims, auth persona, fs persona).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { Approvals } from '../../src/lib/approvals.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt7-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'job.sh'), 'echo good\n');

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
const readStore = () => { try { return JSON.parse(fs.readFileSync(path.join(tmp, 'approvals', 'approvals.json'), 'utf8')); } catch { return []; } };

// Pair every client BEFORE any flood section (per-source rate buckets).
const cSwap = await pairedClient('r7-swap');
const cBind = await pairedClient('r7-bind');
const cWarn = await pairedClient('r7-warn');
const cCap = await pairedClient('r7-cap');
const cReplay = await pairedClient('r7-replay');
const cJail = await pairedClient('r7-jail', 'workspace');

console.log('\n=== R7-1: agent_name rejects bidi / zero-width / U+2028-29 ===');
{
  for (const bad of ['evi\u202El', 'a\u200Bb', 'x\u2028y', 'z\u2066w']) {
    const code = keystore.createPairingCode('workspace');
    const r = await new BridgeClient(base).pair(code, bad);
    check(`name ${JSON.stringify(bad)} rejected`, r.status === 400, 'got ' + r.status);
  }
  const code = keystore.createPairingCode('workspace');
  const ok = await new BridgeClient(base).pair(code, 'perfectly-fine name 1');
  check('plain name still pairs', ok.status === 200, 'got ' + ok.status);
}

console.log('\n=== R7-2: nonexistent-in-workspace argv operand refuses the plan (F1 CRITICAL) ===');
{
  const r = await cBind.call('process.run', { argv: ['sh', 'not-created-yet.sh'] });
  check('missing script plan refused as unbindable', isErr(r, /unbindable|does not exist yet/), JSON.stringify(r.rpc).slice(0, 160));
  // and no approval was created behind the scenes
  check('no pending approval leaked', !isPending(r));
}

console.log('\n=== R7-3: argv[0] content swap after approval is refused at execute (HIGH-1/F2) ===');
{
  fs.writeFileSync(path.join(ws, 'swap.sh'), 'echo good\n');
  const r = await cSwap.call('process.run', { argv: ['sh', 'swap.sh'] });
  check('sh swap.sh requires approval', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  approvals.decide(apid, 'approve');
  // agent rewrites the script AFTER the human approved
  fs.writeFileSync(path.join(ws, 'swap.sh'), 'echo PWNED\n');
  const st = await cSwap.call('approval.status', { approval_id: apid });
  const s = st.rpc?.result?.structuredContent;
  check('swapped content refused', s?.status !== 'executed', JSON.stringify(s).slice(0, 160));
  check('refusal says content changed', /changed|vanished/i.test(JSON.stringify(s) + JSON.stringify(st.rpc?.error || '')));
  fs.writeFileSync(path.join(ws, 'swap.sh'), 'echo good\n');
}

console.log('\n=== R7-4: approval summary warns about indirect reads (interpreters/build tools) ===');
{
  const r1 = await cWarn.call('process.run', { argv: ['sh', 'job.sh'] });
  const pend1 = readStore().find(a => a.id === r1.rpc?.result?.structuredContent?.approval_id);
  check('sh summary warns NOT bound', !!pend1 && /NOT bound/.test(pend1.summary), pend1?.summary);
  if (pend1) approvals.decide(pend1.id, 'deny');
  const r2 = await cWarn.call('process.run', { argv: ['make', 'all'] });
  const pend2 = readStore().find(a => a.id === r2.rpc?.result?.structuredContent?.approval_id);
  check('make summary warns NOT bound', !!pend2 && /NOT bound/.test(pend2.summary), pend2?.summary);
  if (pend2) approvals.decide(pend2.id, 'deny');
}

console.log('\n=== R7-4b: post-approval rewrite of a required module is refused (P1) ===');
{
  fs.writeFileSync(path.join(ws, 'main.js'), 'require("./helper.js");\n');
  fs.writeFileSync(path.join(ws, 'helper.js'), 'console.log("good")\n');
  const r = await cSwap.call('process.run', { argv: ['node', 'main.js'] });
  check('node main.js requires approval', isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  const apid = r.rpc.result.structuredContent.approval_id;
  const rec = readStore().find(a => a.id === apid);
  check('approval summary counts bound modules', /bound module/.test(rec.summary), rec.summary);
  approvals.decide(apid, 'approve');
  fs.writeFileSync(path.join(ws, 'helper.js'), 'require("fs").writeFileSync("/tmp/RT7PWNED","x")\n');
  const st = await cSwap.call('approval.status', { approval_id: apid });
  const sj = JSON.stringify(st.rpc);
  check('rewritten dependency refused at execute', !sj.includes('"executed"') && /changed|vanished/.test(sj), sj.slice(0, 160));
  check('payload never ran', !fs.existsSync('/tmp/RT7PWNED'));
  fs.writeFileSync(path.join(ws, 'helper.js'), 'console.log("good")\n');
}

console.log('\n=== R7-5: per-agent pending queue cap (starvation fix) ===');
{
  let last;
  for (let i = 0; i < 26; i++) last = await cCap.call('process.run', { argv: ['sh', 'job.sh'] });
  check('26th pending from one agent is refused', isErr(last, /too many pending|busy/), JSON.stringify(last.rpc).slice(0, 160));
  // drain so later suites on this approvals dir are unaffected
  for (const a of readStore().filter(x => x.status === 'pending')) approvals.decide(a.id, 'deny');
}

console.log('\n=== R7-6: pre-boot timestamp rejected (restart replay closed) ===');
{
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fs.list', arguments: { path: '.' } } });
  const ts = String(Date.now() - 119000); // inside +-120s window, before boot
  const r = await cReplay.rawPost('/mcp', body, { ts });
  check('pre-boot ts -> 401', r.status === 401, 'got ' + r.status);
}

console.log('\n=== R7-7: LIMITED mode unchanged: /etc/hosts jailed ===');
{
  const r = await cJail.call('fs.read', { path: '/etc/hosts' });
  check('fs.read /etc/hosts refused in limited mode', isErr(r), JSON.stringify(r.rpc).slice(0, 120));
}

console.log('\n=== R7-8: FULL mode: no jail, no approvals, shell on ===');
{
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt7-full-'));
  fs.mkdirSync(path.join(tmp2, 'workspace'), { recursive: true });
  fs.writeFileSync(path.join(tmp2, 'config.json'), JSON.stringify({ mode: 'full', port: 17899 }));
  const inst2 = await startServer(tmp2, { port: 0 });
  const base2 = `http://127.0.0.1:${inst2.port}`;
  const ks2 = new KeyStore(path.join(tmp2, 'secrets'));
  const code = ks2.createPairingCode('workspace');
  const c = new BridgeClient(base2);
  const pr = await c.pair(code, 'r7-full');
  check('full-mode pair works', pr.status === 200, 'got ' + pr.status);

  const sh = await c.call('shell.exec', { command: 'echo fullmode-ok' });
  const shOut = sh.rpc?.result?.structuredContent?.stdout || '';
  // Executes directly (no approval). /bin/zsh is macOS-only, so on this Linux
  // sandbox the spawn itself may ENOENT - either outcome proves the gate is off.
  const shErr = JSON.stringify(sh.rpc);
  check('shell.exec runs without approval in full mode', shOut.includes('fullmode-ok') || /ENOENT|spawn/.test(shErr), shErr.slice(0, 160));

  const etc = await c.call('fs.read', { path: '/etc/hosts' });
  check('fs.read /etc/hosts allowed in full mode', !!etc.rpc?.result?.structuredContent?.content, JSON.stringify(etc.rpc).slice(0, 120));

  const del = await c.call('fs.delete', { path: '/etc/hosts-definitely-not' });
  check('no approval is created in full mode (errors or executes directly)', !isPending(del));

  await new Promise(r => inst2.server.close(r));
  fs.rmSync(tmp2, { recursive: true, force: true });
}

console.log('\n=== R7-9: fs.write preserves the exec bit on overwrite ===');
{
  const exe = path.join(ws, 'tool.sh');
  fs.writeFileSync(exe, 'echo v1\n');
  fs.chmodSync(exe, 0o755);
  const w = await cJail.call('fs.write', { path: 'tool.sh', content_base64: Buffer.from('echo v2\n').toString('base64') });
  check('overwrite succeeds', !!w.rpc?.result, JSON.stringify(w.rpc).slice(0, 120));
  const mode = fs.statSync(exe).mode & 0o777;
  check('exec bit preserved', (mode & 0o100) !== 0, 'mode=' + mode.toString(8));
}

console.log(`\nROUND 7: ${pass} passed, ${fail} failed`);
if (failures.length) console.log('FAILED: ' + failures.join(' | '));
await new Promise(r => inst.server.close(r));
process.exit(fail ? 1 : 0);
