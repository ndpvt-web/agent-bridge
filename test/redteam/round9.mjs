// Round 9: tunnel URL self-healing (discovery inbox + urlwatch).
// The inbox must carry ONLY the tunnel URL - never keys, codes, or payloads.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { extractTunnelUrl, ensureDiscovery, reportTunnelUrl, loadDiscovery } = require('../../src/lib/discovery.js');

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name} ${detail}`); }
}

// --- local mock of the webhook.site inbox API ---
const posted = [];      // every body the mock inbox received
let tokenCreations = 0;
const mock = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    if (req.method === 'POST' && req.url === '/token') {
      tokenCreations++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ uuid: '11111111-2222-3333-4444-555555555555' }));
    } else if (req.method === 'POST' && req.url.startsWith('/11111111-')) {
      posted.push(body);
      res.writeHead(200).end('ok');
    } else { res.writeHead(404).end(); }
  });
});
await new Promise(r => mock.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${mock.address().port}`;
process.env.AGENT_BRIDGE_DISCOVERY_BASE = BASE;

// --- extractTunnelUrl ---
check('extract: last URL wins', extractTunnelUrl('x https://old-one.trycloudflare.com y https://new-one.trycloudflare.com z') === 'https://new-one.trycloudflare.com');
check('extract: junk -> null', extractTunnelUrl('no urls here') === null);
check('extract: lookalike rejected', extractTunnelUrl('https://evil-trycloudflare.com.evil.com') === null);

// --- ensureDiscovery with a fresh home ---
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt9-'));
fs.mkdirSync(path.join(home, 'logs'), { recursive: true });
fs.mkdirSync(path.join(home, 'secrets'), { recursive: true });
const d1 = await ensureDiscovery(home);
check('discovery created', !!d1 && d1.read_url.includes('/token/11111111-'));
check('discovery persisted', !!loadDiscovery(home));
const mode = fs.statSync(path.join(home, 'secrets', 'discovery.json')).mode & 0o777;
check('discovery file is 0600', mode === 0o600, String(mode.toString(8)));
const d2 = await ensureDiscovery(home);
check('discovery not recreated', tokenCreations === 1 && d2.uuid === d1.uuid);

// --- reportTunnelUrl payload discipline ---
posted.length = 0;
const okRep = await reportTunnelUrl(home, 'https://alpha-beta-gamma.trycloudflare.com');
check('report accepted', okRep === true && posted.length === 1);
const payload = JSON.parse(posted[0]);
check('payload keys are exactly tunnel_url+ts', JSON.stringify(Object.keys(payload).sort()) === '["ts","tunnel_url"]', posted[0]);
check('payload carries the url', payload.tunnel_url === 'https://alpha-beta-gamma.trycloudflare.com');
check('rejects non-tunnel url', await reportTunnelUrl(home, 'https://evil.example.com/x') === false);
check('rejects url with path', await reportTunnelUrl(home, 'https://a-b.trycloudflare.com/secret') === false);

// --- failure path: dead inbox must not throw ---
process.env.AGENT_BRIDGE_DISCOVERY_BASE = 'http://127.0.0.1:1';
const home2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt9b-'));
fs.mkdirSync(path.join(home2, 'secrets'), { recursive: true });
const dead = await ensureDiscovery(home2).catch(() => 'threw');
check('dead inbox -> null, no throw', dead === null);
check('dead inbox -> report false', await reportTunnelUrl(home2, 'https://a-b.trycloudflare.com') === false);
process.env.AGENT_BRIDGE_DISCOVERY_BASE = BASE;

// --- end-to-end: urlwatch child process follows a rotation ---
const home3 = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-rt9c-'));
fs.mkdirSync(path.join(home3, 'logs'), { recursive: true });
fs.mkdirSync(path.join(home3, 'secrets'), { recursive: true });
fs.writeFileSync(path.join(home3, 'logs', 'tunnel.log'), 'boot\nhttps://first-url.trycloudflare.com\n');
posted.length = 0;
const child = spawn(process.execPath, [path.resolve('src/urlwatch.js')], {
  env: { ...process.env, AGENT_BRIDGE_HOME: home3, AGENT_BRIDGE_DISCOVERY_BASE: BASE },
  stdio: 'ignore',
});
const deadline = Date.now() + 15000;
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
let stored = '';
while (Date.now() < deadline) {
  try { stored = fs.readFileSync(path.join(home3, '.tunnel-url'), 'utf8').trim(); } catch { /* not yet */ }
  if (stored === 'https://first-url.trycloudflare.com') break;
  await sleep(200);
}
check('watcher stored the boot URL', stored === 'https://first-url.trycloudflare.com');
// rotate: cloudflared restarts and prints a fresh URL
fs.appendFileSync(path.join(home3, 'logs', 'tunnel.log'), 'restart\nhttps://second-url.trycloudflare.com\n');
stored = '';
while (Date.now() < deadline) {
  try { stored = fs.readFileSync(path.join(home3, '.tunnel-url'), 'utf8').trim(); } catch { /* not yet */ }
  if (stored === 'https://second-url.trycloudflare.com') break;
  await sleep(200);
}
check('watcher followed the rotation', stored === 'https://second-url.trycloudflare.com');
await sleep(500);   // let the POST land
check('inbox got both URLs, newest last', posted.length >= 2 && JSON.parse(posted[posted.length - 1]).tunnel_url === 'https://second-url.trycloudflare.com', String(posted.length));
const everyPayloadLean = posted.every(b => { const k = Object.keys(JSON.parse(b)).sort(); return JSON.stringify(k) === '["ts","tunnel_url"]'; });
check('every watcher POST carried only tunnel_url+ts', everyPayloadLean);
child.kill('SIGTERM');
await sleep(300);
check('watcher exits on SIGTERM', child.exitCode === 0 || child.signalCode === 'SIGTERM');

mock.close();
console.log(`\nRound 9: ${pass} passed, ${fail} failed`);
if (fail) { console.log('FAILURES:', failures.join(', ')); process.exit(1); }
