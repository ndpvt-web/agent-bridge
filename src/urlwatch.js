#!/usr/bin/env node
'use strict';
// Tunnel URL watcher: keeps .tunnel-url current and reports every new
// address to the discovery inbox so a paired agent can find the bridge
// after a quick-tunnel restart - no re-pasting, no account.
// Reads only logs/tunnel.log; writes only .tunnel-url; POSTs only the URL.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { reportTunnelUrl, extractTunnelUrl, ensureDiscovery } = require('./lib/discovery');

const home = process.env.AGENT_BRIDGE_HOME || path.join(os.homedir(), 'agent-bridge');
const TUNNEL_LOG = path.join(home, 'logs', 'tunnel.log');
const URL_FILE = path.join(home, '.tunnel-url');
const POLL_MS = 2000;
const TAIL_BYTES = 65536;

function log(msg) {
  const line = new Date().toISOString() + ' ' + msg + '\n';
  try { fs.appendFileSync(path.join(home, 'logs', 'urlwatch.log'), line); } catch { /* nowhere to log */ }
}

function currentStored() {
  try { return fs.readFileSync(URL_FILE, 'utf8').trim(); } catch { return ''; }
}

function latestFromLog() {
  let fd;
  try {
    fd = fs.openSync(TUNNEL_LOG, 'r');
    const size = fs.fstatSync(fd).size;
    const buf = Buffer.alloc(Math.min(size, TAIL_BYTES));
    fs.readSync(fd, buf, 0, buf.length, Math.max(0, size - buf.length));
    return extractTunnelUrl(buf.toString('utf8'));
  } catch { return null; }
  finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ } }
}

let lastSeen = currentStored();
let inFlight = false;

async function tick() {
  if (inFlight) return;           // a slow POST must not stack ticks
  inFlight = true;
  try {
    const url = latestFromLog();
    if (!url || url === lastSeen) return;
    // Log-first truth: the tunnel process printed it, so it is live.
    const tmp = URL_FILE + '.tmp';
    fs.writeFileSync(tmp, url + '\n', { mode: 0o600 });
    fs.renameSync(tmp, URL_FILE);
    lastSeen = url;
    log('tunnel url now ' + url);
    const ok = await reportTunnelUrl(home, url);
    if (!ok) {
      // One retry; the next rotation (or process restart) reports afresh.
      await new Promise(r => setTimeout(r, 5000));
      const ok2 = await reportTunnelUrl(home, url);
      log(ok2 ? 'reported to discovery inbox' : 'discovery report failed (will retry on next change)');
    } else {
      log('reported to discovery inbox');
    }
  } catch (e) {
    log('tick error: ' + String(e && e.message || e).slice(0, 200));
  } finally {
    inFlight = false;
  }
}

async function main() {
  log('urlwatch starting');
  // Warm the inbox at boot so `agent-bridge pair` can print the link even
  // before the first rotation. Failure is fine - reportTunnelUrl retries.
  try { await ensureDiscovery(home); } catch { /* offline at boot */ }
  // Startup reconcile: the tunnel may have restarted while we were down.
  await tick();
  fs.watchFile(TUNNEL_LOG, { interval: POLL_MS }, () => { tick(); });
}

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
main();
