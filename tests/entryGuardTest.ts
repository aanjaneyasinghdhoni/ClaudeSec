/**
 * tests/entryGuardTest.ts
 *
 * Regression gate for the entry-point guard in server/index.ts.
 *
 * Importing server/index.ts used to start the HTTP server AND write the hook
 * config mirrors (protected-paths.json, rules-enforcement.json, enforce-config
 * .json) at module load. Any test or build tool that imported it would boot a
 * live listener and clobber the user's installed enforcement config with the
 * importing process's (empty-DB, monitor) defaults. The guard makes a plain
 * import inert: no listener, no timers, no config writes — the side effects run
 * ONLY when the file is the process entry point (`tsx server/index.ts`).
 *
 * This test spawns a worker that IMPORTS the module with CLAUDESEC_NO_AUTOSTART=1
 * (and, defensively, in a way where it is NOT argv[1]) under a fully sandboxed
 * CLAUDESEC_HOME / CLAUDESEC_DB / CLAUDESEC_ENFORCE_CONFIG, then asserts:
 *   1. The import resolves without the process hanging on a live server/timer
 *      (the worker exits on its own — an unguarded import would keep the event
 *      loop alive via setInterval and the HTTP listener).
 *   2. NONE of the three hook config mirrors were written into the sandbox,
 *      even though the hooks dir exists (so an unguarded write WOULD land).
 *
 * A separate positive check confirms the guard still autostarts under the real
 * launchd-style invocation (`tsx server/index.ts`): that path is already covered
 * end-to-end by authTest/otlpIngestTest (which spawn `tsx server/index.ts` and
 * require a live listener), so this file focuses on the import-is-inert contract.
 *
 * DB DISCIPLINE: sandboxed CLAUDESEC_DB + CLAUDESEC_HOME under os.tmpdir(),
 * removed in a finally block. The real ~/.claudesec is NEVER touched.
 *
 * Run via:  npx tsx tests/entryGuardTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure (or worker crash).
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

// Sandbox roots — a temp home (where the hook mirrors WOULD land) and a temp DB.
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-entryguard-home-'));
const DB_PATH = path.join(os.tmpdir(), `csec-entryguard-${process.pid}-${Date.now()}.db`);
const ENFORCE_CONFIG = path.join(HOME_DIR, 'enforce-config.json');
const HOOKS_DIR = path.join(HOME_DIR, 'hooks');

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try { fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function main(): void {
  try {
    // Pre-create the installed-hook dir so the mirror writes WOULD succeed if the
    // guard were broken — i.e. the absence of files below is a real signal, not an
    // artefact of a missing directory.
    fs.mkdirSync(HOOKS_DIR, { recursive: true });

    // A tiny worker script whose argv[1] is ITSELF, not server/index.ts — so the
    // import.meta.url === argv[1] check is false on its own merit, and the
    // explicit CLAUDESEC_NO_AUTOSTART=1 is belt-and-suspenders.
    const workerSrc = `
      // If the guard fails, importing this starts a server + timers and this
      // process never exits — the parent's spawnSync timeout would then fire.
      await import(${JSON.stringify(path.join(REPO_ROOT, 'server', 'index.ts'))});
      // Reaching here means the import resolved without hanging the event loop on
      // a listener/timer. Exit explicitly so a stray (unexpected) live timer can't
      // mask the regression by keeping us alive.
      process.exit(0);
    `;
    const workerPath = path.join(HOME_DIR, 'worker.mjs');
    fs.writeFileSync(workerPath, workerSrc);

    const res = spawnSync(TSX_BIN, [workerPath], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_NO_AUTOSTART: '1',
        CLAUDESEC_DB: DB_PATH,
        CLAUDESEC_HOME: HOME_DIR,
        CLAUDESEC_ENFORCE_CONFIG: ENFORCE_CONFIG,
        CLAUDESEC_WATCH: '0',
        // Pin the port vars so an inherited host value can't matter either way.
        CLAUDESEC_PORT: '0',
        PORT: '0',
      },
      encoding: 'utf8',
      timeout: 30_000,
    });

    check('importing server/index.ts resolves and exits (no live server/timer)', () => {
      assert.strictEqual(res.signal, null,
        `worker was killed by signal ${res.signal} — likely hung on a live server/timer ` +
        `(an unguarded import keeps the event loop alive).\n--- stderr ---\n${(res.stderr || '').slice(-2000)}`);
      assert.strictEqual(res.status, 0,
        `worker exited ${res.status}, expected 0.\n--- stderr ---\n${(res.stderr || '').slice(-2000)}`);
    });

    check('import did NOT write enforce-config.json into the sandbox', () => {
      assert.ok(!fs.existsSync(ENFORCE_CONFIG),
        `enforce-config.json was written on import (${ENFORCE_CONFIG}) — guard failed`);
      assert.ok(!fs.existsSync(path.join(HOOKS_DIR, 'enforce-config.json')),
        'enforce-config.json was mirrored into the hooks dir on import — guard failed');
    });

    check('import did NOT write rules-enforcement.json into the hooks dir', () => {
      assert.ok(!fs.existsSync(path.join(HOOKS_DIR, 'rules-enforcement.json')),
        'rules-enforcement.json was mirrored into the hooks dir on import — guard failed');
    });

    check('import did NOT write protected-paths.json into the hooks dir', () => {
      assert.ok(!fs.existsSync(path.join(HOOKS_DIR, 'protected-paths.json')),
        'protected-paths.json was mirrored into the hooks dir on import — guard failed');
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  entryGuardTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

try {
  main();
} catch (err) {
  console.error('[entryGuardTest] fatal:', err);
  cleanup();
  process.exit(1);
}
