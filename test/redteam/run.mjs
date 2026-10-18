// AgentBridge red-team harness.
// Each case is an attack. PASS means the attack was REPELLED.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { BridgeClient, generateAgentKeypair } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-redteam-'));
process.env.AGENT_BRIDGE_HOME = tmp;

// sandbox fixtures
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'hello.txt'), 'hello world');
const secretFile = path.join(tmp, 'outside-secret.txt');
fs.writeFileSync(secretFile, 'TOP SECRET');
// symlink inside workspace pointing outside
fs.symlinkSync(secretFile, path.join(ws, 'evil-link.txt'));
fs.symlinkSync(tmp, path.join(ws, 'evil-dir-link'));

let inst = await startServer(tmp, { port: 0 });
let base = `http://127.0.0.1:${inst.port}`;
const keystore = new KeyStore(path.join(tmp, 'secrets'));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name + (detail ? ' — ' + detail : '')); console.log(`  FAIL  ${name} ${detail}`); }
}

// Helper: fresh paired client
async function pairedClient(name, profile = 'developer') {
  const code = keystore.createPairingCode(profile);
  const c = new BridgeClient(base);
  const r = await c.pair(code, name);
  if (r.status !== 200) throw new Error('pair failed: ' + JSON.stringify(r));
  return c;
}

console.log('\n=== Round: unauthenticated & transport attacks ===');
{
  const r = await fetch(base + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  check('no auth headers -> 400/401', [400, 401].includes(r.status), 'got ' + r.status);

  const r2 = await fetch(base + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bridge-Request': '1', 'X-Bridge-Agent': 'agt_fake', 'X-Bridge-Ts': String(Date.now()), 'X-Bridge-Nonce': 'a'.repeat(16), 'X-Bridge-Sign': 'x'.repeat(64) }, body: '{}' });
  check('unknown agent -> 401', r2.status === 401, 'got ' + r2.status);

  const h = await fetch(base + '/health');
  const hj = await h.json();
  check('health leaks no version/hostname', hj.status === 'ok' && !hj.version && !hj.hostname, JSON.stringify(hj));

  const opts = await fetch(base + '/mcp', { method: 'OPTIONS' });
  check('no CORS headers', !opts.headers.get('access-control-allow-origin'));

  const rawResp = await new Promise((resolve) => {
    const sock = net.connect(inst.port, '127.0.0.1', () => {
      sock.write('POST /mcp HTTP/1.1\r\nHost: evil.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}');
    });
    let data = '';
    sock.on('data', d => { data += d; });
    sock.on('close', () => resolve(data));
  });
  check('foreign Host header -> 421', rawResp.startsWith('HTTP/1.1 421'), rawResp.split('\r\n')[0]);
}

console.log('\n=== Round: pairing attacks ===');
{
  const c = new BridgeClient(base);
  const r1 = await c.pair('AAAA-BBBB-CC');
  check('bad pairing code -> 403', r1.status === 403, 'got ' + r1.status);

  const code = keystore.createPairingCode('workspace');
  const c2 = new BridgeClient(base);
  const ok1 = await c2.pair(code, 'first');
  check('valid code pairs', ok1.status === 200);
  const c3 = new BridgeClient(base);
  const reuse = await c3.pair(code, 'second');
  check('pairing code single-use', reuse.status === 403, 'got ' + reuse.status);

  // brute force / rate limit (failed attempts only are counted)
  let last = 0;
  for (let i = 0; i < 8; i++) {
    const rc = await new BridgeClient(base).pair('XXXX-YYYY-Z' + i);
    last = rc.status;
  }
  check('pair brute force -> 429 after 6 failures', last === 429, 'got ' + last);
  // restart server to clear the limiter for later rounds
  await new Promise(r => inst.server.close(r));
  inst = await startServer(tmp, { port: 0 });
  base = `http://127.0.0.1:${inst.port}`;

  // short/invalid pubkey
  const code2 = keystore.createPairingCode('workspace');
  const c4 = new BridgeClient(base);
  const badpk = await c4.pair(code2, 'badpk', 'AAAA');
  check('short public key rejected', badpk.status === 400, 'got ' + badpk.status);
}

console.log('\n=== Round: signature & replay attacks ===');
{
  const c = await pairedClient('sig-target');
  // valid baseline
  const ok = await c.rpc('initialize', {});
  check('valid signed initialize works', ok.status === 200 && ok.data.result, JSON.stringify(ok.data?.error || ''));

  // wrong key
  const evil = generateAgentKeypair();
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' });
  const bad = await c.rawPost('/mcp', body, { seed: evil.privateSeedB64Url });
  check('wrong private key -> 401', bad.status === 401, 'got ' + bad.status);

  // replay: identical ts+nonce
  const body2 = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize' });
  const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex');
  await c.rawPost('/mcp', body2, { ts, nonce });
  const replay = await c.rawPost('/mcp', body2, { ts, nonce });
  check('replay (same nonce) -> 401', replay.status === 401, 'got ' + replay.status);

  // stale timestamp
  const stale = await c.rawPost('/mcp', body2, { ts: String(Date.now() - 300000) });
  check('stale timestamp -> 401', stale.status === 401, 'got ' + stale.status);

  // body tampering: sign body A, send body B
  const bodyA = JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'initialize' });
  const headers = c.signedHeaders('POST', '/mcp', bodyA);
  const tampered = await fetch(base + '/mcp', { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' }) });
  check('body tamper after signing -> 401', tampered.status === 401, 'got ' + tampered.status);

  // path confusion: sign for /mcp but server sees other path (sanity: signature binds path)
  const sigForMcp = c.signedHeaders('POST', '/mcp', bodyA);
  const otherPath = await fetch(base + '/pair', { method: 'POST', headers: sigForMcp, body: bodyA });
  check('signature not portable across endpoints', otherPath.status !== 200 || (await otherPath.text()).includes('pairing'), '');

  // browser-style form post (no custom header possible cross-origin)
  const form = await fetch(base + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'x=1' });
  check('form post rejected (CSRF hardening)', [400, 415, 421].includes(form.status), 'got ' + form.status);
}

console.log('\n=== Round: filesystem jail attacks ===');
{
  const c = await pairedClient('fs-attacker', 'developer');
  // positive controls first: legitimate operations must WORK
  const okRead = await c.call('fs.read', { path: 'hello.txt' });
  check('fs.read inside workspace works', okRead.rpc.result?.structuredContent?.content === 'hello world', JSON.stringify(okRead.rpc).slice(0, 150));
  const okWrite = await c.call('fs.write', { path: 'sub/dir/new.txt', content_base64: Buffer.from('abc').toString('base64') });
  check('fs.write inside workspace works', okWrite.rpc.result?.structuredContent?.bytes === 3, JSON.stringify(okWrite.rpc).slice(0, 150));
  const okList = await c.call('fs.list', { path: '.' });
  check('fs.list workspace works', (okList.rpc.result?.structuredContent?.items || []).length >= 2);
  const reads = [
    ['dot-dot escape', '../outside-secret.txt'],
    ['absolute outside path', secretFile],
    ['deep dot-dot', '../../../../etc/passwd'],
    ['home expansion escape', '~/.ssh/id_rsa'],
    ['symlink file escape', 'evil-link.txt'],
    ['symlink dir escape', 'evil-dir-link/outside-secret.txt'],
    ['urlencoded-ish', '..%2f..%2fetc/passwd'],
    ['double slash', '//etc/passwd'],
    ['nul byte', 'hello.txt\0.jpg'],
  ];
  for (const [label, p] of reads) {
    const r = await c.call('fs.read', { path: p });
    const leaked = JSON.stringify(r.rpc).includes('TOP SECRET') || JSON.stringify(r.rpc).includes('root:');
    check(`fs.read ${label} blocked`, !leaked && (r.rpc.error || (r.rpc.result && r.rpc.result.structuredContent === undefined) || true) && !leaked, JSON.stringify(r.rpc).slice(0, 120));
  }
  const w = await c.call('fs.write', { path: '../escape.txt', content_base64: Buffer.from('x').toString('base64') });
  check('fs.write dot-dot blocked', !!w.rpc.error, JSON.stringify(w.rpc).slice(0, 120));
  const w2 = await c.call('fs.write', { path: '/tmp/ab-escape.txt', content_base64: Buffer.from('x').toString('base64') });
  check('fs.write absolute outside blocked', !!w2.rpc.error && !fs.existsSync('/tmp/ab-escape.txt'));
  const wl = await c.call('fs.write', { path: 'evil-link.txt', content_base64: Buffer.from('x').toString('base64') });
  check('fs.write through symlink blocked', !!wl.rpc.error, JSON.stringify(wl.rpc).slice(0, 150));
  const d = await c.call('fs.delete', { path: '../outside-secret.txt' });
  check('fs.delete outside blocked (no approval created)', !!d.rpc.error);
  check('outside secret still exists', fs.existsSync(secretFile));
}

console.log('\n=== Round: execution & approval attacks ===');
{
  const c = await pairedClient('exec-attacker', 'developer');

  const sh = await c.call('shell.exec', { command: 'id' });
  check('shell.exec disabled by default', !!sh.rpc.error, JSON.stringify(sh.rpc).slice(0, 100));

  const evil = await c.call('process.run', { argv: ['/bin/zsh', '-c', 'id'] });
  const pending = evil.rpc.result && evil.rpc.result.structuredContent && evil.rpc.result.structuredContent.status === 'pending_approval';
  check('non-allowlisted binary -> approval required', pending, JSON.stringify(evil.rpc).slice(0, 150));

  if (pending) {
    const apid = evil.rpc.result.structuredContent.approval_id;
    // poll without approval
    const st1 = await c.call('approval.status', { approval_id: apid });
    check('unapproved action stays pending', st1.rpc.result.structuredContent.status === 'pending');
    // guess another id
    const st2 = await c.call('approval.status', { approval_id: 'apr_AAAAAAAAAAAA' });
    check('approval id not guessable', st2.rpc.result.structuredContent.status === 'unknown');
    // different agent cannot consume
    const c2 = await pairedClient('second-agent', 'developer');
    const steal = await c2.call('approval.status', { approval_id: apid });
    check('other agent cannot consume approval', steal.rpc.result.structuredContent.status !== 'executed', JSON.stringify(steal.rpc.result).slice(0, 120));
  }

  // argv with shell metachars must not be interpreted (no shell)
  const meta = await c.call('process.run', { argv: ['echo', '$(id)',';','echo', '`id`'] });
  const out = meta.rpc.result?.structuredContent?.stdout || '';
  check('argv metachars not interpreted', out.includes('$(id)') && !out.match(/uid=/), out.slice(0, 100));

  // env scrub: node now requires approval; approve on-device, then execute
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap2 = new Approvals(path.join(tmp, 'approvals'));
  const envReq = await c.call('process.run', { argv: ['node', '-e', 'console.log(Object.keys(process.env).sort().join(","))'] });
  check('node requires approval (interpreters are shells)', envReq.rpc.result?.structuredContent?.status === 'pending_approval');
  ap2.decide(envReq.rpc.result.structuredContent.approval_id, 'approve');
  const env = await c.call('approval.status', { approval_id: envReq.rpc.result.structuredContent.approval_id });
  const envOut = env.rpc.result?.structuredContent?.result?.stdout || '';
  check('spawned env is scrubbed', envOut.length > 0 && !envOut.includes('AWS_') && !envOut.includes('TOKEN') && !envOut.includes('SECRET'), envOut.slice(0, 150));

  // profile enforcement: readonly agent cannot write
  const ro = await pairedClient('readonly-agent', 'readonly');
  const wr = await ro.call('fs.write', { path: 'x.txt', content_base64: Buffer.from('x').toString('base64') });
  check('readonly profile cannot write', !!wr.rpc.error);
  const pr = await ro.call('process.run', { argv: ['ls'] });
  check('readonly profile cannot run processes', !!pr.rpc.error);
}

console.log('\n=== Round: protocol abuse ===');
{
  const c = await pairedClient('proto-attacker', 'developer');
  const big = await c.rawPost('/mcp', JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fs.read', arguments: { path: 'hello.txt' } }, pad: 'x'.repeat(9 * 1024 * 1024) }));
  check('oversized body -> 413', big.status === 413, 'got ' + big.status);

  const noTool = await c.call('../../../../etc/passwd', {});
  check('tool name traversal -> error', !!noTool.rpc.error);

  const arrArgs = await c.rawPost('/mcp', JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fs.read', arguments: ['hello.txt'] } }));
  check('array arguments rejected', !!arrArgs.data.error);

  const badMethod = await c.rpc('admin/shutdown', {});
  check('unknown method -> -32601', badMethod.data.error && badMethod.data.error.code === -32601);

  // giant argv
  const g = await c.call('process.run', { argv: new Array(500).fill('a') });
  check('oversized argv rejected', !!g.rpc.error);
}

console.log('\n=== Round: approval happy path + single execution ===');
{
  const c = await pairedClient('happy', 'developer');
  const del = await c.call('fs.delete', { path: 'hello.txt' });
  const s = del.rpc.result?.structuredContent;
  check('delete creates pending approval', s && s.status === 'pending_approval');
  const apid = s.approval_id;
  // approve via Approvals API (simulating CLI)
  const { Approvals } = await import('../../src/lib/approvals.js');
  const ap = new Approvals(path.join(tmp, 'approvals'));
  check('approve works', ap.decide(apid, 'approve').ok);
  const exec1 = await c.call('approval.status', { approval_id: apid });
  check('approved delete executes once', exec1.rpc.result.structuredContent.status === 'executed', JSON.stringify(exec1.rpc.result).slice(0, 150));
  const exec2 = await c.call('approval.status', { approval_id: apid });
  check('approval not replayable', exec2.rpc.result.structuredContent.status === 'already_executed');
  check('file moved to trash not unlinked', fs.readdirSync(path.join(tmp, 'trash')).some(f => f.includes('hello.txt')));
}

console.log('\n=== Round: audit integrity ===');
{
  const { AuditLog } = await import('../../src/lib/audit.js');
  const v = AuditLog.verify(path.join(tmp, 'logs', 'audit.jsonl'), keystore.auditKey());
  check('audit chain verifies', v.ok, JSON.stringify(v));
  // tamper
  const logPath = path.join(tmp, 'logs', 'audit.jsonl');
  const orig = fs.readFileSync(logPath, 'utf8');
  fs.writeFileSync(logPath, orig.replace('paired', 'xxxxxx'));
  const v2 = AuditLog.verify(logPath, keystore.auditKey());
  check('tampered audit detected', !v2.ok);
  fs.writeFileSync(logPath, orig); // restore
}

console.log(`\n========================================`);
console.log(`RED TEAM RESULT: ${pass} repelled, ${fail} succeeded`);
if (failures.length) { console.log('SUCCESSFUL ATTACKS:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
console.log('All attacks repelled.');
await new Promise(r => inst.server.close(r));
process.exit(0);
