'use strict';
// Discovery inbox: lets a paired agent find the current tunnel URL after a
// quick-tunnel restart, without an account and without the user re-pasting.
//
// Design: at pair time we create a free webhook.site token (no account,
// random 128-bit UUID). The urlwatch process POSTs ONLY the public tunnel
// URL to that inbox whenever cloudflared prints a new one. An agent that
// loses the tunnel GETs the inbox (a URL it was given once, next to the
// tunnel URL) and reads the newest address. The inbox never carries keys,
// pairing codes, approvals, or any request content - the tunnel URL alone
// grants nothing: every bridge call still needs a paired Ed25519 key.
const fs = require('fs');
const path = require('path');

// Base is overridable ONLY for the test-suite's local mock inbox; the
// launchd jobs never set it, so production always talks to webhook.site.
// Read lazily so tests can set it after require().
const base = () => (process.env.AGENT_BRIDGE_DISCOVERY_BASE || 'https://webhook.site').replace(/\/+$/, '');
const TUNNEL_RE = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/g;

function discoveryPath(home) { return path.join(home, 'secrets', 'discovery.json'); }

function loadDiscovery(home) {
  try { return JSON.parse(fs.readFileSync(discoveryPath(home), 'utf8')); } catch { return null; }
}

// The newest tunnel URL in a chunk of cloudflared log text, or null.
function extractTunnelUrl(text) {
  const m = String(text).match(TUNNEL_RE);
  return m ? m[m.length - 1] : null;
}

// Create the inbox once; on any failure (including offline) return null
// (caller retries later). fetchImpl is injectable for tests.
async function ensureDiscovery(home, fetchImpl = fetch) {
  const have = loadDiscovery(home);
  if (have && have.uuid && have.post_url && have.read_url) return have;
  let res;
  try {
    res = await fetchImpl(base() + '/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
      body: '{}',
      signal: AbortSignal.timeout(10000),
    });
  } catch { return null; }
  if (!res.ok) return null;
  let body;
  try { body = await res.json(); } catch { return null; }
  if (!body || typeof body.uuid !== 'string' || !/^[0-9a-f-]{36}$/i.test(body.uuid)) return null;
  const rec = {
    uuid: body.uuid,
    post_url: base() + '/' + body.uuid,
    read_url: base() + '/token/' + body.uuid + '/requests?sorting=newest&per_page=1',
    created_at: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(discoveryPath(home)), { recursive: true });
  const tmp = discoveryPath(home) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(rec, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, discoveryPath(home));
  return rec;
}

// POST exactly {tunnel_url, ts} to the inbox. Never anything else.
// Returns true on acceptance, false on any failure (caller may retry).
async function reportTunnelUrl(home, url, fetchImpl = fetch) {
  if (!/^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(url)) return false;
  let rec = loadDiscovery(home);
  if (!rec) rec = await ensureDiscovery(home, fetchImpl);
  if (!rec) return false;
  try {
    const res = await fetchImpl(rec.post_url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tunnel_url: url, ts: new Date().toISOString() }),
      signal: AbortSignal.timeout(10000),
    });
    return !!res && res.ok !== false;
  } catch { return false; }
}

module.exports = { loadDiscovery, ensureDiscovery, reportTunnelUrl, extractTunnelUrl, discoveryPath };
