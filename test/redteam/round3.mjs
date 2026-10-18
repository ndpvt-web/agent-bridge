// Red-team round 3: jail escape via allowlisted tools, pairing races, header tricks.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { startServer } from '../../src/server.js';
import { KeyStore } from '../../src/lib/keystore.js';
import { BridgeClient } from '../client.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt3-'));
const ws = path.join(tmp, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'in.txt'), 'inside');

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
  if (r.status !== 200) throw new Error('pair failed: ' + JSON.stringify(r.data));
  return c;
}
const isPending = (r) => r.rpc.result?.structuredContent?.status === 'pending_approval';

console.log('\n=== Round 3: allowlisted tool as jail escape ===');
{
  const c = await pairedClient('escape-artist');
  for (const argv of [
    ['cat', '/etc/passwd'],
    ['cat', '../../etc/passwd'],
    ['head', '/etc/master.passwd'],
    ['tail', '-n', '5', '/etc/passwd'],
    ['grep', 'root', '/etc/passwd'],
    ['rg', 'root', '/etc/'],
    ['ls', '/'],
    ['which', 'node'],
    ['jq', '.', '/etc/passwd'],
    ['shasum', '/etc/passwd'],
    ['wc', '/etc/passwd'],
    ['diff', '/etc/passwd', '/etc/group'],
  ]) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} requires approval`, isPending(r), JSON.stringify(r.rpc).slice(0, 120));
  }
  // '~' operands are rejected outright (spawn does not expand them)
  {
    const r = await c.call('process.run', { argv: ['ls', '~'] });
    check(`["ls","~"] rejected (no tilde expansion)`, isPending(r) || !!r.rpc.error, JSON.stringify(r.rpc).slice(0, 120));
  }
  // and the legit uses still auto-run
  for (const argv of [['ls', '.'], ['cat', 'in.txt'], ['grep', 'in', 'in.txt'], ['echo', 'hello'], ['date'], ['ls', '-la', '.']]) {
    const r = await c.call('process.run', { argv });
    check(`${JSON.stringify(argv)} still auto-allowed`, !isPending(r) && !r.rpc.error, JSON.stringify(r.rpc).slice(0, 120));
  }
}

console.log('\n=== Round 3: pairing races and code handling ===');
{
  // concurrent consumption of one code: only one may succeed
  const code = keystore.createPairingCode('workspace');
  const clients = [new BridgeClient(`http://127.0.0.1:${inst.port}`), new BridgeClient(`http://127.0.0.1:${inst.port}`)];
  const results = await Promise.all(clients.map(c => c.pair(code, 'racer')));
  const okCount = results.filter(r => r.status === 200).length;
  check('one pairing code, two concurrent pairs -> exactly one wins', okCount === 1, 'winners=' + okCount);

  // lowercase code should still work (human transcription)
  const code2 = keystore.createPairingCode('workspace');
  const c3 = new BridgeClient(`http://127.0.0.1:${inst.port}`);
  const lower = await c3.pair(code2.toLowerCase(), 'lowercase');
  check('lowercase pairing code accepted', lower.status === 200, 'got ' + lower.status);
}

console.log('\n=== Round 3: HTTP-level trickery ===');
{
  const c = await pairedClient('header-hacker');
  // duplicate signature headers (raw socket)
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' });
  const good = c.signedHeaders('POST', '/mcp', body);
  const raw = await new Promise((resolve) => {
    const sock = net.connect(inst.port, '127.0.0.1', () => {
      sock.write(
        'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n' +
        `X-Bridge-Request: 1\r\nX-Bridge-Agent: ${c.agentId}\r\nX-Bridge-Ts: ${good['X-Bridge-Ts']}\r\n` +
        `X-Bridge-Nonce: ${good['X-Bridge-Nonce']}\r\nX-Bridge-Sign: AAAA\r\nX-Bridge-Sign: ${good['X-Bridge-Sign']}\r\n` +
        `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n` + body);
    });
    let d = ''; sock.on('data', c => d += c); sock.on('close', () => resolve(d));
  });
  check('duplicate signature headers cannot smuggle a bad one', raw.startsWith('HTTP/1.1 401') || raw.startsWith('HTTP/1.1 400'), raw.split('\r\n')[0]);

  // query string must not change routing/auth expectations
  const q = await c.rawPost('/mcp?action=delete', body);
  check('query string does not confuse auth', [200, 401, 404].includes(q.status), 'got ' + q.status);
}

console.log(`\nROUND 3 RESULT: ${pass} repelled, ${fail} succeeded`);
if (failures.length) { console.log('SUCCESSFUL ATTACKS:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
await new Promise(r => inst.server.close(r));
process.exit(0);
