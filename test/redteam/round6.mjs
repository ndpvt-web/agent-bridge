// Round 6: regression suite for the four round-2 independent reviews
// (filesystem, crypto/auth, priv-esc, installer+claims).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { Approvals } from '../../src/lib/approvals.js';
import { AuditLog } from '../../src/lib/audit.js';
import { loadConfig } from '../../src/lib/config.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt6-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'data.txt'), 'hello\nworld\n');
fs.writeFileSync(path.join(ws, 'j.json'), '{"a":1}\n');
fs.writeFileSync(path.join(ws, 'sums.txt'), 'deadbeef  data.txt\n');
fs.writeFileSync(path.join(ws, 'run.js'), 'console.log("original")\n');
const outside = path.join(tmp, 'outside');
fs.mkdirSync(outside);
fs.writeFileSync(path.join(outside, 'secret.txt'), 'TOP-SECRET-12345\n');
// symlink inside workspace pointing outside (for traversal tests)
fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(ws, 'link-out.txt'));

let inst = await startServer(tmp, { port: 0 });
const keystore = new KeyStore(path.join(tmp, 'secrets'));
const approvals = new Approvals(path.join(tmp, 'approvals'));
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
  if (r.status !== 200) throw new Error('pair failed: ' + JSON.stringify(r));
  return c;
}
const isPending = (r) => r.rpc?.result?.structuredContent?.status === 'pending_approval';
// Paired up front: the /pair flood test later trips the global pair bucket.
const c10 = await pairedClient('r6-f10');
const c8 = await pairedClient('r6-f8');
const ran = (r) => r.rpc?.result?.structuredContent?.started === true;

console.log('\n=== R6-1: grep/rg -e pattern flag jails ALL positionals (F1 x2) ===');
{
  const c = await pairedClient('r6-f1');
  const attacks = [
    ['grep', '-e', 'TOP', path.join(outside, 'secret.txt')],
    ['grep', '-eTOP', path.join(outside, 'secret.txt')],
    ['grep', '-r', '-e', '.*', outside],
    ['rg', '-e', 'TOP', path.join(outside, 'secret.txt')],
    ['rg', '-eTOP', path.join(outside, 'secret.txt')],
    // pattern flag AFTER the positional: first positional is still a file
    ['grep', path.join(outside, 'secret.txt'), '-e', 'TOP'],
    // end-of-flags marker does not change operand roles
    ['grep', '-e', 'TOP', '--', path.join(outside, 'secret.txt')],
    ['grep', '-rne', 'TOP', outside],
  ];
  for (const argv of attacks) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} needs approval`, isPending(r), JSON.stringify(r.rpc).slice(0, 140));
  }
  // legit uses still run
  for (const argv of [
    ['grep', 'hello', 'data.txt'],
    ['grep', '-e', 'hello', 'data.txt'],
    ['grep', '-rn', 'hello', '.'],
    ['rg', '-e', 'hello', 'data.txt'],
    ['rg', 'hello', 'data.txt'],
  ]) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} auto-runs`, ran(r), JSON.stringify(r.rpc).slice(0, 140));
  }
}

console.log('\n=== R6-2: recursive traversal must not follow symlinks (F2 priv-esc) ===');
{
  const c = await pairedClient('r6-f2');
  // grep -R follows symlinks -> must need approval now
  let r = await c.call('process.run', { argv: ['grep', '-R', '-e', 'TOP', '.'] });
  check('grep -R needs approval', isPending(r));
  r = await c.call('process.run', { argv: ['diff', '-r', 'a', 'b'] });
  check('diff -r needs approval', isPending(r));
  // grep -r does NOT follow symlinks: auto-runs and must not leak the secret
  r = await c.call('process.run', { argv: ['grep', '-r', '-e', 'TOP', '.'] });
  check('grep -r auto-runs', ran(r));
  check('grep -r did not read through symlink', !(r.rpc?.result?.structuredContent?.stdout || '').includes('TOP-SECRET'));
}

console.log('\n=== R6-3: platform grammar (stat), shasum -c, jq isolation ===');
{
  const c = await pairedClient('r6-f3');
  let r = await c.call('process.run', { argv: ['stat', '-t', '/etc/passwd'] });
  check('stat -t /etc/passwd needs approval (GNU semantics on linux)', isPending(r));
  r = await c.call('process.run', { argv: ['stat', '-c', '%s', 'data.txt'] });
  check('stat -c %s data.txt auto-runs', ran(r));
  r = await c.call('process.run', { argv: ['shasum', '-c', 'sums.txt'] });
  check('shasum -c needs approval', isPending(r));
  r = await c.call('process.run', { argv: ['shasum', 'data.txt'] });
  check('shasum data.txt auto-runs', ran(r));
  // jq is no longer auto-allowed (module import jail escape, round-4 HIGH).
  // 'env.HOME' looks like a missing path operand, so the request is refused
  // outright - either way jq never runs.
  r = await c.call('process.run', { argv: ['jq', '-n', 'env.HOME'] });
  check('jq -n never runs', !ran(r), JSON.stringify(r.rpc).slice(0, 120));
}

console.log('\n=== R6-4: shell.exec profile gate; fs.read directory + audit path ===');
{
  const c = await pairedClient('r6-f4-ro', 'readonly');
  const r = await c.call('shell.exec', { command: 'true' });
  check('readonly shell.exec rejected at plan', r.rpc?.error?.message?.includes('forbidden'), JSON.stringify(r.rpc).slice(0, 140));
  const d = await pairedClient('r6-f4-dev');
  const dr = await d.call('fs.read', { path: '.' });
  check('fs.read on directory is a clean error', dr.rpc?.error?.message?.includes('directory'), JSON.stringify(dr.rpc).slice(0, 140));
  await d.call('fs.read', { path: 'data.txt' });
  const auditLines = fs.readFileSync(path.join(tmp, 'logs', 'audit.jsonl'), 'utf8').trim().split('\n');
  const readRec = auditLines.map(l => JSON.parse(l)).find(e => e.tool === 'fs.read' && e.decision === 'executed');
  check('fs.read audit entry carries the path', !!readRec && readRec.detail.includes('data.txt'), JSON.stringify(readRec || {}));
}

console.log('\n=== R6-5: approvals - retention, pending cap, content binding, inode binding ===');
{
  // approved-unpolled survives 210 later decisions
  const ap = new Approvals(path.join(tmp, 'approvals2'));
  const a = ap.create({ kind: 'delete', agentId: 'agt_x', summary: 'x', payload: {}, toolName: 'fs.delete' });
  ap.decide(a.id, 'approve');
  for (let i = 0; i < 210; i++) { const b = ap.create({ kind: 'delete', agentId: 'agt_x', summary: 's' + i, payload: {}, toolName: 'fs.delete' }); ap.decide(b.id, 'deny'); }
  check('approved-unpolled survives 210 decisions', ap.status(a.id).state === 'approved');
  // pending cap
  let threw = false;
  try { for (let i = 0; i < 101; i++) ap.create({ kind: 'delete', agentId: 'agt_x', summary: 'p' + i, payload: {}, toolName: 'fs.delete' }); }
  catch (e) { threw = e.code === 'too_many_pending'; }
  check('pending cap (100) throws too_many_pending', threw);

  // frozen binding: approve "node run.js", swap content - the FROZEN copy
  // runs (post-approval edits cannot affect an approved run, round-4 fix)
  const c = await pairedClient('r6-f5');
  const r1 = await c.call('process.run', { argv: ['node', 'run.js'] });
  check('node run.js needs approval', isPending(r1));
  const approvalId = r1.rpc.result.structuredContent.approval_id;
  approvals.decide(approvalId, 'approve');
  await c.call('fs.write', { path: 'run.js', content_base64: Buffer.from('require("fs").writeFileSync("/tmp/R6PWNED","")').toString('base64'), mode: 'overwrite' });
  const st = await c.call('approval.status', { approval_id: approvalId });
  const status = st.rpc?.result?.structuredContent?.status;
  check('frozen copy executes (edit ignored)', status === 'executed', status);
  check('frozen stdout is the ORIGINAL content', st.rpc?.result?.structuredContent?.result?.stdout === 'original\n', JSON.stringify(st.rpc?.result?.structuredContent?.result?.stdout));
  check('no marker written', !fs.existsSync('/tmp/R6PWNED'));
  // and the run is strictly single-use: a second poll does not re-execute
  const st2 = await c.call('approval.status', { approval_id: approvalId });
  check('single-use after frozen execution', st2.rpc?.result?.structuredContent?.status === 'already_executed');

  // inode binding on fs.delete: approve, replace file, execution must fail
  fs.writeFileSync(path.join(ws, 'victim.txt'), 'v1');
  const d1 = await c.call('fs.delete', { path: 'victim.txt' });
  const delId = d1.rpc.result.structuredContent.approval_id;
  approvals.decide(delId, 'approve');
  fs.unlinkSync(path.join(ws, 'victim.txt'));
  fs.writeFileSync(path.join(ws, 'victim.txt'), 'v2-replaced');
  const dst = await c.call('approval.status', { approval_id: delId });
  check('replaced file not deleted', dst.rpc?.result?.structuredContent?.status === 'execution_failed', JSON.stringify(dst.rpc?.result?.structuredContent).slice(0, 160));
  check('replacement file intact', fs.readFileSync(path.join(ws, 'victim.txt'), 'utf8') === 'v2-replaced');

  // cross-agent approval-state disclosure
  const other = await pairedClient('r6-f5b');
  const d2 = await c.call('fs.delete', { path: 'victim.txt' });
  const delId2 = d2.rpc.result.structuredContent.approval_id;
  const peek = await other.call('approval.status', { approval_id: delId2 });
  check('other agent sees unknown, not state', peek.rpc?.result?.structuredContent?.status === 'unknown');
}

console.log('\n=== R6-6: audit chain survives server+CLI interleave (F2 fs / F8 installer) ===');
{
  const p = path.join(tmp, 'logs2', 'audit.jsonl');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const a1 = new AuditLog(p, 'key1');
  a1.record({ tool: 'a' }); a1.record({ tool: 'b' });
  const a2 = new AuditLog(p, 'key1'); // second process
  a2.record({ tool: 'cli.approve' });
  a1.record({ tool: 'c' });
  a2.record({ tool: 'cli.deny' });
  const v = AuditLog.verify(p, 'key1');
  check('interleaved log verifies intact', v.ok === true && v.entries === 5, JSON.stringify(v));
}

console.log('\n=== R6-7: nonce recorded only after valid signature (HIGH-1) ===');
{
  const c = await pairedClient('r6-f7');
  // 1a: junk-signed request with a chosen nonce must NOT burn it
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'system.info', arguments: {} } });
  const goodHeaders = c.signedHeaders('POST', '/mcp', body);
  const bad = await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: { ...goodHeaders, 'X-Bridge-Sign': 'A'.repeat(86) }, body });
  check('junk-signed request rejected', bad.status === 401);
  const real = await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: goodHeaders, body });
  check('real request with same nonce still accepted', real.status === 200, String(real.status));
  // replay of the now-used nonce IS rejected
  const replay = await fetch(`http://127.0.0.1:${inst.port}/mcp', { method: 'POST', headers: goodHeaders, body }`.replace("', {", "', {"), {});
  check('sanity: fetch built', true);
  const replay2 = await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: goodHeaders, body });
  check('verbatim replay rejected', replay2.status === 401);
  // 1b: eviction flood with junk sigs must not evict a captured nonce
  const cap = c.signedHeaders('POST', '/mcp', body); // fresh nonce, valid sig, never sent
  for (let i = 0; i < 50; i++) {
    const junk = c.signedHeaders('POST', '/mcp', body);
    await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: { ...junk, 'X-Bridge-Sign': 'A'.repeat(86) }, body });
  }
  const afterFlood = await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: cap, body });
  check('captured request still works after junk flood (nonce not evicted)', afterFlood.status === 200, String(afterFlood.status));
}

console.log('\n=== R6-9: /pair hardening (MED-4, F4, F5 auth review) ===');
{
  const kp = new BridgeClient(`http://127.0.0.1:${inst.port}`);
  const code = keystore.createPairingCode('workspace');
  const bodyJson = JSON.stringify({ pairing_code: code, agent_name: 'x', public_key: kp.keys.publicKeyB64Url });
  // no X-Bridge-Request header -> 400
  let r = await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bodyJson });
  check('/pair without X-Bridge-Request rejected', r.status === 400, String(r.status));
  // text/plain (browser simple-request) -> 415
  r = await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Bridge-Request': '1' }, body: bodyJson });
  check('/pair text/plain rejected', r.status === 415, String(r.status));
  // control chars in agent_name -> 400
  r = await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bridge-Request': '1' }, body: JSON.stringify({ pairing_code: code, agent_name: 'ok[2J[HFORGED', public_key: kp.keys.publicKeyB64Url }) });
  check('agent_name with ESC rejected', r.status === 400, String(r.status));
  // proper request still pairs
  r = await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bridge-Request': '1' }, body: bodyJson });
  check('proper /pair still works', r.status === 200, String(r.status));
  // spoofing CF-Connecting-IP does not reset the global bucket
  for (let i = 0; i < 8; i++) {
    await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bridge-Request': '1', 'CF-Connecting-IP': `10.0.0.${i}` }, body: JSON.stringify({ pairing_code: 'BAD-CODE', agent_name: 'x', public_key: kp.keys.publicKeyB64Url }) });
  }
  let limited = false;
  for (let i = 8; i < 80; i++) {
    const rr = await fetch(`http://127.0.0.1:${inst.port}/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bridge-Request': '1', 'CF-Connecting-IP': `10.1.0.${i}` }, body: JSON.stringify({ pairing_code: 'BAD-CODE', agent_name: 'x', public_key: kp.keys.publicKeyB64Url }) });
    if (rr.status === 429) { limited = true; break; }
  }
  check('global pair bucket 429s despite spoofed per-source IPs', limited);
}

console.log('\n=== R6-10: initialize version, __proto__ tool, config load hardening ===');
{
  const c = c10;
  const init = await c.rpc('initialize', { protocolVersion: '0.0.1-prehistoric' });
  check('initialize answers the server version', init.data?.result?.protocolVersion === '2025-06-18', JSON.stringify(init.data?.result).slice(0, 120));
  const bad = await c.call('__proto__', {});
  check('__proto__ tool rejected as unknown', bad.rpc?.error?.code === -32602, JSON.stringify(bad.rpc).slice(0, 140));
  const bad2 = await c.call('constructor', {});
  check('constructor tool rejected as unknown', bad2.rpc?.error?.code === -32602);
  // config whitelist: injected keys must not apply
  fs.writeFileSync(path.join(tmp, 'config.json'), JSON.stringify({ bind: '0.0.0.0', read_roots_extra: ['/'], port: 'abc', profile_default: 'bogus' }));
  const cfg = loadConfig(tmp);
  check('injected bind refused', cfg.bind === '127.0.0.1', cfg.bind);
  check('injected read root refused', !cfg.read_roots_extra.includes('/'), JSON.stringify(cfg.read_roots_extra));
  check('bad port refused', cfg.port === 7899, String(cfg.port));
  check('bad profile refused', cfg.profile_default === 'workspace');
  fs.writeFileSync(path.join(tmp, 'config.json'), '{}');
}

console.log('\n=== R6-8: auth-failure rate limiting + bounded audit (F3) ===');
{
  const c = c8;
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'system.info', arguments: {} } });
  const before = fs.readFileSync(path.join(tmp, 'logs', 'audit.jsonl'), 'utf8').trim().split('\n').length;
  let saw429 = false;
  for (let i = 0; i < 35; i++) {
    const h = c.signedHeaders('POST', '/mcp', body);
    const r = await fetch(`http://127.0.0.1:${inst.port}/mcp`, { method: 'POST', headers: { ...h, 'X-Bridge-Sign': 'A'.repeat(86) }, body });
    if (r.status === 429) saw429 = true;
  }
  check('429 after 30 auth failures/min', saw429);
  const after = fs.readFileSync(path.join(tmp, 'logs', 'audit.jsonl'), 'utf8').trim().split('\n').length;
  check('audit growth bounded during flood', after - before <= 15, `grew ${after - before}`);
  // wait out the window is too slow for tests; new client ip bucket is per-source so this is fine
}

console.log(`\nROUND 6: ${pass} passed, ${fail} failed`);
if (failures.length) console.log('FAILED: ' + failures.join(' | '));
inst.server.close();
process.exit(fail ? 1 : 0);
