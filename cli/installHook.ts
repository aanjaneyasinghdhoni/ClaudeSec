/**
 * cli/installHook.ts
 *
 * `claudesec install-hook` / `claudesec uninstall-hook`.
 *
 * Registers the PreToolUse enforcement hook (cli/hooks/claudesec-enforce.cjs)
 * with Claude Code by merging two entries into the user's settings.json — one
 * matching Bash, one matching the file-editing tools. The hook can BLOCK
 * dangerous tool calls before they run, but only when enforce mode is also on;
 * by default it monitors (logs would-block, allows). It is fail-open by design:
 * any error inside the hook allows the call through.
 *
 * Safety:
 *   • Consent is mandatory — we print the exact JSON to be added and the target
 *     file, then require an interactive y/N (or --yes). We never run from any
 *     other script.
 *   • We back up the prior settings file before writing.
 *   • Idempotent — re-running refreshes the copied hook + snapshot and never
 *     duplicates settings entries (detected by the command substring).
 *   • We only ever ADD/REMOVE our own two entries; every other key, hook, and
 *     matcher in settings.json is preserved untouched.
 *
 * Test overrides (so the suite never touches the real home):
 *   • CLAUDESEC_HOME            → the ~/.claudesec dir (hooks + log live here).
 *   • CLAUDESEC_CLAUDE_SETTINGS → the settings.json path to merge into.
 */

import { createInterface } from 'readline';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, '..');

// Substring that identifies OUR hook command in a settings entry. Used for both
// idempotency (skip if present) and uninstall (remove only ours).
// Exported so the test suite can assert parity with server/enforceStatus.ts —
// the two modules declare this independently to keep the runtime dependency
// graph clean (server/ never imports from cli/).
export const HOOK_FILENAME = 'claudesec-enforce.cjs';

// The two PreToolUse matchers we register. Bash is split out from the editing
// tools because the catastrophic floor only inspects Bash commands; the editing
// matcher lets rule-based blocking see file contents too.
const BASH_MATCHER = 'Bash';
const EDIT_MATCHER = 'Edit|Write|MultiEdit|NotebookEdit';

export interface InstallPaths {
  /** ~/.claudesec — where we copy the hook + snapshot and append the log. */
  homeDir: string;
  /** ~/.claudesec/hooks — the installed hook + its rules snapshot. */
  hooksDir: string;
  /** The installed hook script. */
  installedHook: string;
  /** The installed rules snapshot, sitting next to the hook. */
  installedSnapshot: string;
  /** The Claude Code settings.json we merge into. */
  settingsFile: string;
  /** ~/.claudesec/install.log */
  logFile: string;
}

/** Resolve every path, honoring the test overrides. */
export function installPaths(): InstallPaths {
  const homeDir =
    process.env.CLAUDESEC_HOME ?? path.join(os.homedir(), '.claudesec');
  const hooksDir = path.join(homeDir, 'hooks');
  const settingsFile =
    process.env.CLAUDESEC_CLAUDE_SETTINGS ??
    path.join(os.homedir(), '.claude', 'settings.json');
  return {
    homeDir,
    hooksDir,
    installedHook: path.join(hooksDir, HOOK_FILENAME),
    installedSnapshot: path.join(hooksDir, 'rules-enforcement.json'),
    settingsFile,
    logFile: path.join(homeDir, 'install.log'),
  };
}

/** Build the two settings entries that run our installed hook. */
function hookEntries(installedHook: string) {
  // Quote the path: an unquoted $HOME with a space would split the argument and,
  // because the hook is fail-open, silently disable enforcement.
  const command = `node "${installedHook}"`;
  const make = (matcher: string) => ({
    matcher,
    hooks: [{ type: 'hook', command }],
  });
  return [make(BASH_MATCHER), make(EDIT_MATCHER)];
}

/** Append a single install/uninstall record to install.log. Best-effort. */
function appendLog(p: InstallPaths, action: string, target: string): void {
  try {
    fs.mkdirSync(p.homeDir, { recursive: true });
    const line = `${new Date().toISOString()}\t${action}\t${target}\n`;
    // 0600 to match the repo's posture for local telemetry (spans.db).
    fs.appendFileSync(p.logFile, line, { mode: 0o600 });
  } catch {
    // logging must never gate the operation
  }
}

/** Ask y/N on stdin. Resolves false on EOF / non-interactive input. */
function confirm(question: string): Promise<boolean> {
  return new Promise(resolve => {
    // A non-interactive (piped/closed) stdin must ABORT, never silently proceed.
    if (!process.stdin.isTTY) {
      const onData = (chunk: Buffer) => {
        cleanup();
        resolve(/^\s*y(es)?\s*$/i.test(chunk.toString()));
      };
      const onEnd = () => { cleanup(); resolve(false); };
      const cleanup = () => {
        process.stdin.off('data', onData);
        process.stdin.off('end', onEnd);
        try { process.stdin.pause(); } catch {}
      };
      process.stdout.write(question);
      process.stdin.resume();
      process.stdin.once('data', onData);
      process.stdin.once('end', onEnd);
      return;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, answer => {
      rl.close();
      resolve(/^\s*y(es)?\s*$/i.test(answer));
    });
  });
}

/**
 * Build the rules snapshot from in-repo source. Runs the existing
 * scripts/build-enforcement-rules.ts via the repo's tsx — no network, ever.
 * Returns the path to the freshly-built rules-enforcement.json in the repo root.
 */
function buildSnapshot(): string {
  const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');
  const script = path.join(REPO_ROOT, 'scripts', 'build-enforcement-rules.ts');
  execFileSync(process.execPath, [tsxCli, script], {
    cwd: REPO_ROOT,
    stdio: 'inherit',
  });
  return path.join(REPO_ROOT, 'rules-enforcement.json');
}

/** Read + parse the settings file, or return {} when absent / unparseable. */
function readSettings(file: string): any {
  let raw: string;
  try { raw = fs.readFileSync(file, 'utf-8'); } catch { return {}; }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    // An unparseable settings file is a hard stop — we will not clobber it.
    throw new Error(
      `Refusing to edit ${file}: it is not valid JSON. Fix it by hand and retry.`,
    );
  }
}

/** Back up the existing settings file (if any) → settings.json.bak-<ts>. */
function backupSettings(file: string): string | null {
  if (!fs.existsSync(file)) return null;
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const backup = `${file}.bak-${ts}`;
  fs.copyFileSync(file, backup);
  return backup;
}

/** Does `entry` already point at our hook? */
function isOurEntry(entry: any): boolean {
  if (!entry || !Array.isArray(entry.hooks)) return false;
  return entry.hooks.some(
    (h: any) => typeof h?.command === 'string' && h.command.includes(HOOK_FILENAME),
  );
}

/**
 * Merge our two entries into settings.PreToolUse, preserving everything else.
 * Returns true if the settings object changed (so the caller knows to write).
 *
 * Strategy: strip EVERY entry that points at our hook, then append the two fresh
 * ones. Matching on the command (not the matcher string) means a future change to
 * our matcher set can't strand a stale ClaudeSec entry next to a new one — the old
 * one is always removed first.
 */
function mergeEntries(settings: any, installedHook: string): boolean {
  if (!settings.hooks || typeof settings.hooks !== 'object') settings.hooks = {};
  const pre = settings.hooks.PreToolUse;
  const list: any[] = Array.isArray(pre) ? pre : [];

  const before = JSON.stringify(list);
  const kept = list.filter(e => !isOurEntry(e));
  kept.push(...hookEntries(installedHook));
  settings.hooks.PreToolUse = kept;

  return JSON.stringify(kept) !== before;
}

/** Remove ONLY our entries from settings.PreToolUse. Returns true if changed. */
function removeEntries(settings: any): boolean {
  const pre = settings?.hooks?.PreToolUse;
  if (!Array.isArray(pre)) return false;
  const kept = pre.filter(e => !isOurEntry(e));
  if (kept.length === pre.length) return false;
  if (kept.length === 0) {
    delete settings.hooks.PreToolUse;
    if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  } else {
    settings.hooks.PreToolUse = kept;
  }
  return true;
}

function writeSettings(file: string, settings: any): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // 0600 to match Claude Code's own settings perms and our spans.db posture. The
  // `mode` option only applies when the file is CREATED, so chmod after the write
  // to also tighten a pre-existing, looser settings.json.
  fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

/** Copy the tracked hook + freshly-built snapshot into ~/.claudesec/hooks/. */
function copyHookArtifacts(p: InstallPaths, snapshotSrc: string): void {
  fs.mkdirSync(p.hooksDir, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, 'cli', 'hooks', HOOK_FILENAME), p.installedHook);
  fs.chmodSync(p.installedHook, 0o755);
  fs.copyFileSync(snapshotSrc, p.installedSnapshot);
}

// ── Public commands ─────────────────────────────────────────────────────────

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[90m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', mag: '\x1b[35m',
};

export async function installHook(args: string[]): Promise<void> {
  const yes = args.includes('--yes') || args.includes('-y');
  const p = installPaths();

  console.log(`\n${C.bold}${C.mag}ClaudeSec — install enforcement hook${C.reset}\n`);

  // 1. Build the rules snapshot from in-repo source (no network).
  let snapshotSrc: string;
  try {
    snapshotSrc = buildSnapshot();
  } catch (err: any) {
    console.error(`${C.red}✗ Could not build the rules snapshot: ${err.message}${C.reset}\n`);
    process.exit(1);
  }

  // 2. Show the user EXACTLY what we will write, then require consent.
  const entries = hookEntries(p.installedHook);
  console.log(`${C.dim}This adds two PreToolUse hooks to your Claude Code settings:${C.reset}`);
  console.log(`  ${C.bold}File:${C.reset} ${p.settingsFile}\n`);
  console.log(JSON.stringify({ hooks: { PreToolUse: entries } }, null, 2));
  console.log(
    `\n${C.dim}The hook copies live to ${p.hooksDir}.${C.reset}\n` +
    `${C.dim}Existing settings and hooks are preserved; a timestamped backup is taken first.${C.reset}\n`,
  );

  if (!yes) {
    const ok = await confirm(`${C.yellow}Proceed? [y/N] ${C.reset}`);
    if (!ok) {
      console.log(`${C.dim}Aborted — nothing was changed.${C.reset}\n`);
      process.exit(1);
    }
  }

  // 3. Copy the hook + snapshot into ~/.claudesec/hooks/.
  copyHookArtifacts(p, snapshotSrc);

  // 4. Merge the settings entries (backup first).
  let settings: any;
  try {
    settings = readSettings(p.settingsFile);
  } catch (err: any) {
    console.error(`${C.red}✗ ${err.message}${C.reset}\n`);
    process.exit(1);
  }
  const backup = backupSettings(p.settingsFile);
  const changed = mergeEntries(settings, p.installedHook);
  writeSettings(p.settingsFile, settings);

  appendLog(p, changed ? 'install' : 'install-refresh', p.settingsFile);

  // 5. Honest output — no "you are now protected".
  console.log(`${C.green}✓ Enforcement hook installed.${C.reset}`);
  console.log(`  ${C.dim}Hook + snapshot:${C.reset} ${p.hooksDir}`);
  if (backup) console.log(`  ${C.dim}Settings backup:${C.reset} ${backup}`);
  console.log(
    changed
      ? `  ${C.dim}Settings updated:${C.reset} ${p.settingsFile}`
      : `  ${C.dim}Settings already current:${C.reset} ${p.settingsFile}`,
  );
  console.log(
    `\n${C.dim}Pre-execution blocking is now enabled (fail-open by design: if the hook\n` +
    `errors, the tool call is allowed through). The catastrophic floor always blocks;\n` +
    `rule-based blocking only takes effect in enforce mode — turn that on in the\n` +
    `Enforce tab or with CLAUDESEC_MODE=enforce. Restart Claude Code to load the hook.${C.reset}\n`,
  );
}

export async function uninstallHook(args: string[]): Promise<void> {
  const yes = args.includes('--yes') || args.includes('-y');
  const purge = args.includes('--purge');
  const p = installPaths();

  console.log(`\n${C.bold}${C.mag}ClaudeSec — remove enforcement hook${C.reset}\n`);
  console.log(`  ${C.bold}File:${C.reset} ${p.settingsFile}`);
  console.log(`${C.dim}Only ClaudeSec's own PreToolUse entries are removed; everything else stays.${C.reset}`);
  if (purge) console.log(`${C.dim}--purge: ${p.hooksDir} will also be deleted.${C.reset}`);
  console.log();

  if (!yes) {
    const ok = await confirm(`${C.yellow}Proceed? [y/N] ${C.reset}`);
    if (!ok) {
      console.log(`${C.dim}Aborted — nothing was changed.${C.reset}\n`);
      process.exit(1);
    }
  }

  let settings: any;
  try {
    settings = readSettings(p.settingsFile);
  } catch (err: any) {
    console.error(`${C.red}✗ ${err.message}${C.reset}\n`);
    process.exit(1);
  }
  const backup = backupSettings(p.settingsFile);
  const changed = removeEntries(settings);
  if (changed) writeSettings(p.settingsFile, settings);

  if (purge) {
    try { fs.rmSync(p.hooksDir, { recursive: true, force: true }); } catch {}
  }

  appendLog(p, purge ? 'uninstall-purge' : 'uninstall', p.settingsFile);

  if (changed) {
    console.log(`${C.green}✓ Removed ClaudeSec's enforcement hook entries.${C.reset}`);
    if (backup) console.log(`  ${C.dim}Settings backup:${C.reset} ${backup}`);
  } else {
    console.log(`${C.dim}No ClaudeSec hook entries were present — nothing to remove.${C.reset}`);
  }
  if (purge) console.log(`  ${C.dim}Deleted:${C.reset} ${p.hooksDir}`);
  console.log(`${C.dim}Restart Claude Code to drop the hook.${C.reset}\n`);
}
