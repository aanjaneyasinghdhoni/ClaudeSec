#!/usr/bin/env node
/**
 * ClaudeSec CLI
 *
 * Usage:
 *   claudesec              — install + start the background watcher, open the dashboard
 *   claudesec start        — same as above
 *   claudesec stop         — stop and remove the background service
 *   claudesec status       — show server health, span/session counts, uptime
 *   claudesec export [file]— download all spans as JSON (default: claudesec-export-<ts>.json)
 *   claudesec reset        — confirm + wipe all spans, sessions, and alerts
 *   claudesec open         — open the dashboard and pair the browser for mutations
 *   claudesec audit-key    — show / move the Ed25519 audit signing key (file ⇄ Keychain)
 *   claudesec install-hook — register the PreToolUse enforcement hook (asks first)
 *   claudesec uninstall-hook — remove the enforcement hook entries
 *
 * The three teardown paths — `stop`, `uninstall` and `uninstall-hook` — are refused
 * by the enforcement floor when they are run from inside an agent session, because
 * an agent that can ask ClaudeSec to remove itself does not need to defeat the floor
 * at all. They work normally from an operator's own shell, which no hook sees.
 */
import { createInterface } from 'readline';
import { execFileSync }    from 'child_process';
import * as fs             from 'fs';
import { installService, uninstallService, cleanupLegacyOtelEnv, platformSupport, servicePaths } from './service.js';
import { installHook, uninstallHook } from './installHook.js';
import { controlKeyPath, pairingUrl } from '../server/controlToken.js';

const PORT     = process.env.CLAUDESEC_PORT ?? '3000';
const BASE_URL = `http://localhost:${PORT}`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function prompt(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, resolve));
}

/** The control-plane pairing key, if this machine has one. Never printed. */
function readPairingKey(): string | undefined {
  try {
    const raw = fs.readFileSync(controlKeyPath(), 'utf8').trim();
    return /^[0-9a-f]{48,128}$/.test(raw) ? raw : undefined;
  } catch {
    return undefined;
  }
}

async function apiFetch(path: string, opts?: { method?: string; body?: unknown }): Promise<any> {
  const url = `${BASE_URL}${path}`;
  // Mutating routes sit behind the control-plane gate even on loopback, so that a
  // local agent cannot disarm the tool that is watching it. Reads stay open, which
  // is why most of this CLI needs no token at all — but `reset` and `bookmark
  // --delete` write, and would otherwise fail with a bare 403.
  // CLAUDESEC_TOKEN first (it is what a remote or containerised install uses),
  // then the local pairing key. Reading the key file is not a privilege the CLI
  // has and the agent lacks — both run as the same user — it is simply how a
  // local tool authenticates without asking the operator to paste a secret.
  const token = process.env.CLAUDESEC_TOKEN || readPairingKey();
  const init: RequestInit = {
    method: opts?.method ?? 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(opts?.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  };
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    if (res.status === 403) {
      throw new Error(
        `HTTP 403: this command changes state, so it needs the control token. ` +
        `Expected it in ${controlKeyPath()} (or CLAUDESEC_TOKEN). If the server ` +
        `runs with a different CLAUDESEC_HOME, set the same one here.`,
      );
    }
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json().catch(() => null);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function waitForHealth(timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE_URL}/api/health`);
      if (res.ok) return true;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
    process.stdout.write('.');
  }
  return false;
}

async function cmdStart() {
  console.log('\n\x1b[1m\x1b[35mClaudeSec\x1b[0m  \x1b[90mzero-config local observatory for your AI agents\x1b[0m\n');

  const support = platformSupport();
  if (support === 'unsupported') {
    console.error(`\x1b[31m✗ Unsupported platform: ${process.platform}\x1b[0m\n`);
    process.exit(1);
  }
  if (support === 'experimental') {
    console.log(`\x1b[33m⚠ The ${process.platform} background service is experimental — verified on macOS.\x1b[0m`);
  }

  const cleaned = cleanupLegacyOtelEnv();
  if (cleaned.length > 0) {
    console.log(`\x1b[90m✓ Removed legacy ClaudeSec OTEL env config from ${cleaned.length} file(s) — the watcher needs no env vars.\x1b[0m`);
  }

  try {
    installService();
    console.log(`\x1b[32m✓ Background service installed and started.\x1b[0m`);
  } catch (err: any) {
    console.error(`\x1b[31m✗ Could not install the background service: ${err.message}\x1b[0m\n`);
    process.exit(1);
  }

  process.stdout.write('\x1b[90mWaiting for the dashboard');
  const healthy = await waitForHealth(20_000);
  console.log('');

  if (healthy) {
    console.log(`\x1b[32m✓ ClaudeSec is live at ${BASE_URL}\x1b[0m\n`);
    cmdOpen();
    console.log(`\x1b[90mIt is now watching every Claude Code & Codex session on this machine.`);
    console.log(`Everything stays local — nothing leaves your computer.`);
    console.log(`Stop anytime with \x1b[33mclaudesec stop\x1b[90m.\x1b[0m\n`);
  } else {
    console.log(`\x1b[33m⚠ Service started but the dashboard is not reachable yet.\x1b[0m`);
    console.log(`\x1b[90mCheck the log: ${servicePaths().logFile}\x1b[0m\n`);
  }
}

async function cmdStop() {
  try {
    uninstallService();
    console.log('\n\x1b[32m✓ ClaudeSec background service stopped and removed.\x1b[0m\n');
  } catch (err: any) {
    console.error(`\n\x1b[31m✗ Could not stop the service: ${err.message}\x1b[0m\n`);
    process.exit(1);
  }
}

async function cmdStatus() {
  console.log(`\n\x1b[1m\x1b[35mClaudeSec Status\x1b[0m  \x1b[90m(${BASE_URL})\x1b[0m\n`);
  let health: any;
  try {
    health = await apiFetch('/api/health');
  } catch {
    console.error(`\x1b[31m✗ Server unreachable at ${BASE_URL}\x1b[0m`);
    console.error('\x1b[90m  Run: pnpm dev  or  docker compose up\x1b[0m\n');
    process.exit(1);
  }

  const uptime  = Number(health.uptime ?? 0);
  const hh      = Math.floor(uptime / 3600);
  const mm      = Math.floor((uptime % 3600) / 60);
  const ss      = Math.floor(uptime % 60);
  const uptimeStr = `${hh}h ${mm}m ${ss}s`;

  const lines: [string, string][] = [
    ['Version',  health.version   ?? '—'],
    ['Uptime',   uptimeStr],
    ['Spans',    String(health.spans    ?? 0)],
    ['Sessions', String(health.sessions ?? 0)],
    ['Alerts',   String(health.alerts   ?? 0)],
    ['DB size',  health.dbSizeBytes ? `${(health.dbSizeBytes / 1024).toFixed(1)} KB` : '—'],
    ['Webhook',  health.webhookConfigured ? `\x1b[32m✓ configured\x1b[0m` : '\x1b[90mnot set\x1b[0m'],
  ];
  for (const [k, v] of lines) {
    console.log(`  ${(k + ':').padEnd(12)} \x1b[1m${v}\x1b[0m`);
  }
  console.log();
}

async function cmdExport(outFile?: string) {
  const ts        = new Date().toISOString().replace(/[:.]/g, '-');
  const file      = outFile ?? `claudesec-export-${ts}.json`;
  const absFile   = file.startsWith('/') ? file : `${process.cwd()}/${file}`;
  console.log(`\n\x1b[90mFetching export from ${BASE_URL}/api/export …\x1b[0m`);
  let data: any;
  try {
    data = await apiFetch('/api/export');
  } catch (err: any) {
    console.error(`\x1b[31m✗ Export failed: ${err.message}\x1b[0m`);
    process.exit(1);
  }
  fs.writeFileSync(absFile, JSON.stringify(data, null, 2));
  const size = (fs.statSync(absFile).size / 1024).toFixed(1);
  console.log(`\x1b[32m✓ Exported ${data.spans?.length ?? 0} spans → ${absFile}  (${size} KB)\x1b[0m\n`);
}

async function cmdReset() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await prompt(rl, '\x1b[31m⚠  This will delete ALL spans, sessions, and alerts. Type "yes" to confirm: \x1b[0m');
  rl.close();
  if (answer.trim().toLowerCase() !== 'yes') {
    console.log('\x1b[90mAborted.\x1b[0m\n');
    return;
  }
  try {
    await apiFetch('/api/reset', { method: 'POST' });
    console.log('\x1b[32m✓ Database cleared.\x1b[0m\n');
  } catch (err: any) {
    console.error(`\x1b[31m✗ Reset failed: ${err.message}\x1b[0m`);
    process.exit(1);
  }
}

async function cmdTail(args: string[]) {
  const harnessIdx = args.indexOf('--harness');
  const sevIdx     = args.indexOf('--severity');
  const harness    = harnessIdx >= 0 ? args[harnessIdx + 1] : undefined;
  const severity   = sevIdx    >= 0 ? args[sevIdx    + 1] : undefined;

  const params = new URLSearchParams();
  if (harness)  params.set('harness',  harness);
  if (severity) params.set('severity', severity);

  const url = `${BASE_URL}/api/tail${params.toString() ? '?' + params.toString() : ''}`;

  const SEV_COLOR: Record<string, string> = {
    high:   '\x1b[31m',
    medium: '\x1b[33m',
    low:    '\x1b[34m',
    none:   '\x1b[32m',
  };

  console.log(`\n\x1b[1m\x1b[35mClaudeSec Live Tail\x1b[0m  \x1b[90m${url}\x1b[0m`);
  console.log(`\x1b[90mStreaming new spans… (Ctrl+C to stop)\x1b[0m\n`);

  let res: Response;
  try {
    res = await fetch(url, { headers: { Accept: 'text/event-stream' } });
  } catch {
    console.error(`\x1b[31m✗ Cannot connect to ${BASE_URL}. Is ClaudeSec running?\x1b[0m\n`);
    process.exit(1);
  }

  if (!res.body) { console.error('\x1b[31m✗ No body in SSE response\x1b[0m'); process.exit(1); }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      try {
        const span = JSON.parse(line.slice(6));
        const col  = SEV_COLOR[span.severity] ?? '\x1b[37m';
        const sev  = (span.severity ?? 'none').toUpperCase().padEnd(6);
        const ts   = new Date().toLocaleTimeString();
        console.log(
          `\x1b[90m${ts}\x1b[0m ${col}${sev}\x1b[0m \x1b[36m${(span.harness ?? 'unknown').padEnd(16)}\x1b[0m ${span.name}`,
        );
        if (span.severity !== 'none' && span.attributes) {
          try {
            const a = typeof span.attributes === 'string' ? JSON.parse(span.attributes) : span.attributes;
            const rule = a['claudesec.threat.rule'];
            if (rule) console.log(`         \x1b[90m↳ ${rule}\x1b[0m`);
          } catch {}
        }
      } catch {}
    }
  }
}

/**
 * Open the dashboard, pairing the browser on the way in.
 *
 * The URL carries the control-plane pairing key exactly once; the server swaps
 * it for an httpOnly cookie and redirects the key out of the address bar. This
 * is the whole reason `open` exists as a command rather than a bookmark: the
 * server will not hand a mutation token to anything that merely asks for it, so
 * something that can read the key file has to put it in front of the browser.
 */
function cmdOpen() {
  let url = BASE_URL;
  try {
    url = pairingUrl(BASE_URL);
  } catch {
    console.log('\x1b[33mNo pairing key yet — start the service first, or the dashboard will be read-only.\x1b[0m');
  }
  // Never print `url`: it contains the key, and terminal scrollback is a file.
  console.log(`\n\x1b[90mOpening ${BASE_URL} …\x1b[0m\n`);
  const platform = process.platform;
  try {
    // execFileSync, not execSync: the URL carries the pairing key, and handing
    // it to a shell would expose it to word splitting and history expansion.
    if (platform === 'darwin')       execFileSync('open', [url]);
    else if (platform === 'win32')   execFileSync('cmd', ['/c', 'start', '', url]);
    else                             execFileSync('xdg-open', [url]);
  } catch {
    console.log(`\x1b[33mCould not open browser. Visit ${BASE_URL} manually — mutations will 403 until you pair.\x1b[0m`);
    console.log(`\x1b[90mThe pairing key is in ${controlKeyPath()}.\x1b[0m`);
  }
}

// ---------------------------------------------------------------------------
// claudesec audit-key — where the Ed25519 signing key lives
// ---------------------------------------------------------------------------

/**
 * Nothing here runs on its own. Migrating the signing key of a live audit chain
 * is a decision, not a default: if it goes wrong the record stops verifying, and
 * on a chain with hundreds of thousands of entries there is no undo. So the
 * server never migrates, `to-keychain` proves a sign/verify round trip through
 * the Keychain before it changes anything, and it does not remove the key file
 * unless you explicitly ask — and even then it renames rather than deletes.
 */
async function cmdAuditKey(args: string[]): Promise<void> {
  const {
    auditKeyStoreStatus, migrateAuditKeyToKeychain, revertAuditKeyToFile,
  } = await import('../server/auditChain.js');

  const sub = args[0] ?? 'status';

  if (sub === 'status') {
    const s = auditKeyStoreStatus();
    console.log(`\n\x1b[1mAudit signing key\x1b[0m`);
    console.log(`  store        ${s.store}${s.degraded ? ' \x1b[31m(UNREADABLE — anchors are unsigned)\x1b[0m' : ''}`);
    console.log(`  keyId        ${s.keyId || '(none)'}`);
    console.log(`  file         ${s.filePath}${s.fileExists ? '' : ' (absent)'}`);
    console.log(`  keychain     ${s.keychainAvailable ? (s.keychainHasItem ? 'item present' : 'available, no item') : 'unavailable on this platform'}`);
    console.log('\n\x1b[90mRecord the keyId somewhere off this machine. A keyId that changes means');
    console.log('the record was re-founded, however cleanly the chain verifies.\x1b[0m\n');
    return;
  }

  if (sub === 'to-keychain') {
    const removeFile = args.includes('--remove-file');
    const before = auditKeyStoreStatus();
    if (!removeFile) {
      console.log('\n\x1b[90mThe key file will be left in place. Re-run with --remove-file to rename it aside once you are satisfied.\x1b[0m');
    }
    const r = migrateAuditKeyToKeychain({ removeFile });
    console.log(r.ok ? `\n\x1b[32m✓\x1b[0m ${r.message}` : `\n\x1b[31m✗\x1b[0m ${r.message}`);
    if (r.ok && before.keyId && r.keyId !== before.keyId) {
      console.error('\x1b[31mThe key identity changed during migration — this should be impossible. Run `claudesec audit-key to-file`.\x1b[0m');
      process.exit(1);
    }
    if (r.ok) console.log('\x1b[90mRestart the service so it picks the key up from the Keychain.\x1b[0m\n');
    else process.exit(1);
    return;
  }

  if (sub === 'to-file') {
    const r = revertAuditKeyToFile();
    console.log(r.ok ? `\n\x1b[32m✓\x1b[0m ${r.message}\n` : `\n\x1b[31m✗\x1b[0m ${r.message}\n`);
    if (!r.ok) process.exit(1);
    return;
  }

  console.error(`\x1b[31mUnknown subcommand: audit-key ${sub}\x1b[0m`);
  console.error('Usage: claudesec audit-key [status | to-keychain [--remove-file] | to-file]');
  process.exit(1);
}

// ── Helper: box-drawing table printer ─────────────────────────────────────

function printTable(headers: string[], rows: (string | number)[][]): void {
  const cols = headers.length;
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map(r => String(r[i] ?? '').replace(/\x1b\[[0-9;]*m/g, '').length)),
  );
  const line = widths.map(w => '─'.repeat(w + 2)).join('┬');
  const line2 = widths.map(w => '─'.repeat(w + 2)).join('┼');
  const line3 = widths.map(w => '─'.repeat(w + 2)).join('┴');
  const pad = (s: string | number, w: number) => {
    const clean = String(s).replace(/\x1b\[[0-9;]*m/g, '');
    return String(s) + ' '.repeat(Math.max(0, w - clean.length));
  };
  console.log(`┌${line}┐`);
  console.log(`│ ${headers.map((h, i) => pad(`\x1b[1m${h}\x1b[0m`, widths[i])).join(' │ ')} │`);
  console.log(`├${line2}┤`);
  for (const row of rows) {
    console.log(`│ ${row.map((c, i) => pad(c, widths[i])).join(' │ ')} │`);
  }
  console.log(`└${line3}┘`);
}

// ── claudesec top ─────────────────────────────────────────────────────────

async function cmdTop(args: string[]) {
  const byIdx  = args.indexOf('--by');
  const by     = byIdx >= 0 ? args[byIdx + 1] : 'spans';
  const limIdx = args.indexOf('--limit');
  const limit  = limIdx >= 0 ? Number(args[limIdx + 1]) : 10;

  let sessions: any[];
  try {
    const data = await apiFetch('/api/sessions');
    sessions = data.sessions ?? [];
  } catch (err: any) {
    console.error(`\x1b[31m✗ ${err.message}\x1b[0m`);
    process.exit(1);
  }

  const sorted = [...sessions].sort((a, b) => {
    if (by === 'threats') return (b.threatCount ?? 0) - (a.threatCount ?? 0);
    if (by === 'health')  return (a.healthScore  ?? 100) - (b.healthScore  ?? 100); // worst first
    return (b.spanCount ?? 0) - (a.spanCount ?? 0);
  }).slice(0, limit);

  console.log(`\n\x1b[1m\x1b[35mClaudeSec Top Sessions\x1b[0m  \x1b[90mby ${by}\x1b[0m\n`);
  if (sorted.length === 0) { console.log('\x1b[90m  No sessions yet.\x1b[0m\n'); return; }

  const healthColor = (s: number) =>
    s >= 80 ? `\x1b[32m${s}\x1b[0m` : s >= 50 ? `\x1b[33m${s}\x1b[0m` : `\x1b[31m${s}\x1b[0m`;
  const sevColor = (n: number) => n > 0 ? `\x1b[31m${n}\x1b[0m` : '\x1b[90m0\x1b[0m';

  printTable(
    ['#', 'Session', 'Spans', 'Threats', 'Health', 'Harnesses'],
    sorted.map((s, i) => [
      String(i + 1),
      (s.name ?? s.traceId).slice(0, 32),
      String(s.spanCount ?? 0),
      sevColor(s.threatCount ?? 0),
      healthColor(s.healthScore ?? 100),
      (s.harnesses ?? 'unknown').replace(/,/g, ' '),
    ]),
  );
  console.log();
}

// ── claudesec search ──────────────────────────────────────────────────────

async function cmdSearch(args: string[]) {
  const query    = args.filter(a => !a.startsWith('--')).join(' ');
  const sevIdx   = args.indexOf('--severity');
  const hIdx     = args.indexOf('--harness');
  const limIdx   = args.indexOf('--limit');
  const severity = sevIdx >= 0 ? args[sevIdx + 1] : '';
  const harness  = hIdx   >= 0 ? args[hIdx   + 1] : '';
  const limit    = limIdx >= 0 ? Number(args[limIdx + 1]) : 20;

  if (!query) {
    console.error('\x1b[31mUsage: claudesec search <query> [--severity high|medium|low|none] [--harness X] [--limit N]\x1b[0m\n');
    process.exit(1);
  }

  const params = new URLSearchParams({ q: query, limit: String(limit) });
  if (severity) params.set('severity', severity);
  if (harness)  params.set('harness', harness);

  let data: any;
  try {
    data = await apiFetch(`/api/search?${params}`);
  } catch (err: any) {
    console.error(`\x1b[31m✗ ${err.message}\x1b[0m`);
    process.exit(1);
  }

  console.log(`\n\x1b[1m\x1b[35mSearch:\x1b[0m \x1b[36m${query}\x1b[0m  \x1b[90m(${data.total ?? 0} total results)\x1b[0m\n`);
  if (!data.spans?.length) { console.log('\x1b[90m  No matches.\x1b[0m\n'); return; }

  const SEV_COL: Record<string, string> = {
    high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[34m', none: '\x1b[32m',
  };

  printTable(
    ['Span Name', 'Harness', 'Severity', 'Trace'],
    data.spans.map((s: any) => [
      (s.name ?? '').slice(0, 40),
      s.harness ?? 'unknown',
      `${SEV_COL[s.severity] ?? ''}${(s.severity ?? 'none').toUpperCase()}\x1b[0m`,
      (s.traceId ?? '').slice(0, 16),
    ]),
  );
  if (data.pages > 1) console.log(`\x1b[90m  Page 1 of ${data.pages}. Use --limit or /api/search?page= for more.\x1b[0m`);
  console.log();
}

// ── claudesec sessions ────────────────────────────────────────────────────

async function cmdSessions(args: string[]) {
  const asJson = args.includes('--json');

  let sessions: any[];
  try {
    const data = await apiFetch('/api/sessions');
    sessions = data.sessions ?? [];
  } catch (err: any) {
    console.error(`\x1b[31m✗ ${err.message}\x1b[0m`);
    process.exit(1);
  }

  if (asJson) { console.log(JSON.stringify(sessions, null, 2)); return; }

  console.log(`\n\x1b[1m\x1b[35mClaudeSec Sessions\x1b[0m  \x1b[90m(${sessions.length} total)\x1b[0m\n`);
  if (sessions.length === 0) { console.log('\x1b[90m  No sessions.\x1b[0m\n'); return; }

  const healthColor = (s: number) =>
    s >= 80 ? `\x1b[32m${s}\x1b[0m` : s >= 50 ? `\x1b[33m${s}\x1b[0m` : `\x1b[31m${s}\x1b[0m`;

  printTable(
    ['Session', 'Created', 'Spans', 'Threats', 'Health', 'Pinned'],
    sessions.map(s => [
      (s.name ?? s.traceId).slice(0, 36),
      new Date(s.createdAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
      String(s.spanCount ?? 0),
      s.threatCount > 0 ? `\x1b[31m${s.threatCount}\x1b[0m` : '\x1b[90m0\x1b[0m',
      healthColor(s.healthScore ?? 100),
      s.pinned ? '\x1b[33m★\x1b[0m' : '',
    ]),
  );
  console.log();
}

// ── claudesec report ──────────────────────────────────────────────────────

async function cmdReport(args: string[]) {
  const outIdx = args.indexOf('--out');
  const outFile = outIdx >= 0 ? args[outIdx + 1] : null;
  const target = args.filter(a => !a.startsWith('--'))[0];

  let sessions: any[];
  try {
    sessions = (await apiFetch('/api/sessions')).sessions ?? [];
  } catch (err: any) {
    console.error(`\x1b[31m✗ Cannot reach server: ${err.message}\x1b[0m`);
    process.exit(1);
  }
  if (sessions.length === 0) { console.error('\x1b[31m✗ No sessions.\x1b[0m\n'); process.exit(1); }

  let session: any;
  if (!target || target === 'latest') {
    session = sessions[0];
  } else {
    session = sessions.find(s => s.traceId === target || s.traceId.startsWith(target) || s.name === target);
    if (!session) { console.error(`\x1b[31m✗ Session not found: ${target}\x1b[0m\n`); process.exit(1); }
  }

  // Fetch spans + alerts for this session
  const [spansData, alertsData, healthData] = await Promise.all([
    apiFetch(`/api/spans?session=${encodeURIComponent(session.traceId)}&limit=200`).catch(() => ({ spans: [] })),
    apiFetch(`/api/alerts?limit=50`).catch(() => ({ alerts: [] })),
    apiFetch(`/api/sessions/${encodeURIComponent(session.traceId)}/health`).catch(() => null),
  ]);
  const spans  = spansData.spans ?? [];
  const alerts = (alertsData.alerts ?? []).filter((a: any) => a.traceId === session.traceId);

  const lines: string[] = [
    `# ClaudeSec Report — ${session.name}`,
    ``,
    `**Generated:** ${new Date().toLocaleString()}  `,
    `**Session ID:** \`${session.traceId}\`  `,
    `**Created:** ${new Date(session.createdAt).toLocaleString()}  `,
    `**Harnesses:** ${session.harnesses ?? 'unknown'}  `,
    ``,
    `## Health`,
    ``,
    healthData
      ? `**Score:** ${healthData.score}/100 (Grade ${healthData.grade})  \n` +
        `**High threats:** ${healthData.threatHigh}  \n` +
        `**Medium threats:** ${healthData.threatMedium}  \n` +
        `**Low threats:** ${healthData.threatLow}  \n` +
        `**Alerts fired:** ${healthData.alertCount}`
      : '_Health data unavailable_',
    ``,
    `## Summary`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total spans | ${session.spanCount} |`,
    `| Total threats | ${session.threatCount} |`,
    `| Alerts | ${alerts.length} |`,
    ``,
    `## Spans (${spans.length})`,
    ``,
    `| Span | Harness | Severity | Duration |`,
    `|------|---------|----------|----------|`,
    ...spans.slice(0, 100).map((s: any) => {
      let dur = '—';
      try {
        const ms = Number((BigInt(s.endNano) - BigInt(s.startNano)) / 1_000_000n);
        dur = ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms}ms`;
      } catch {}
      return `| ${s.name} | ${s.harness} | ${s.severity.toUpperCase()} | ${dur} |`;
    }),
    ...(spans.length > 100 ? [`| _(${spans.length - 100} more not shown)_ | | | |`] : []),
    ``,
    `## Security Alerts (${alerts.length})`,
    ``,
    alerts.length === 0
      ? '_No security alerts for this session._'
      : ['| Time | Rule | Severity | Span |', '|------|------|----------|------|',
         ...alerts.map((a: any) => `| ${new Date(a.ts).toLocaleTimeString()} | ${a.ruleLabel} | ${a.severity.toUpperCase()} | ${a.spanName} |`)].join('\n'),
    ``,
    `---`,
    `_Report generated by [ClaudeSec](https://github.com/aanjaneyasinghdhoni/ClaudeSec) — Local AI Agent Observatory_`,
  ];

  const markdown = lines.join('\n');

  if (outFile) {
    const abs = outFile.startsWith('/') ? outFile : `${process.cwd()}/${outFile}`;
    fs.writeFileSync(abs, markdown);
    console.log(`\x1b[32m✓ Report saved to ${abs}\x1b[0m\n`);
  } else {
    console.log('\n' + markdown + '\n');
  }
}

async function cmdProcesses(_args: string[]) {
  let data: any;
  try {
    data = await apiFetch('/api/processes');
  } catch (e: any) {
    console.error(`\x1b[31mFailed to reach ClaudeSec at ${BASE_URL}: ${e.message}\x1b[0m`);
    process.exit(1);
  }

  if (!data.supported) {
    console.log(`\x1b[33mProcess scanning is only supported on macOS and Linux (current: ${data.platform})\x1b[0m\n`);
    return;
  }

  const procs: any[] = data.processes ?? [];

  if (procs.length === 0) {
    console.log(`\x1b[90mNo agent processes detected. (Scanned at ${new Date(data.scannedAt).toLocaleTimeString()})\x1b[0m\n`);
    return;
  }

  console.log(`\n\x1b[1m\x1b[36m● Local Agent Processes\x1b[0m  (${procs.length} detected · ${new Date(data.scannedAt).toLocaleTimeString()})\n`);

  printTable(
    ['PID', 'Agent', 'User', 'CPU%', 'Mem MB', 'Command'],
    procs.map(p => [
      String(p.pid),
      p.harnessName,
      p.user,
      p.cpuPct.toFixed(1) + '%',
      p.memMb.toFixed(0),
      p.cmd.length > 60 ? p.cmd.slice(0, 60) + '…' : p.cmd,
    ]),
  );
}

async function cmdBookmarks(args: string[]) {
  const sessionFilter = args.includes('--session') ? args[args.indexOf('--session') + 1] : null;
  const deleteId      = args.includes('--delete')  ? args[args.indexOf('--delete') + 1]  : null;

  if (deleteId) {
    const res = await apiFetch(`/api/bookmarks/${deleteId}`, { method: 'DELETE' });
    if (res.ok) console.log('\x1b[32m✓ Bookmark deleted\x1b[0m');
    else console.error('\x1b[31mFailed to delete bookmark\x1b[0m');
    return;
  }

  const params = new URLSearchParams();
  if (sessionFilter) params.set('session', sessionFilter);
  const bookmarks: any[] = await apiFetch(`/api/bookmarks?${params}`).then(r => r.json()).catch(() => []);

  if (!bookmarks?.length) {
    console.log('\x1b[90mNo bookmarks found.\x1b[0m');
    return;
  }

  console.log(`\n\x1b[1m\x1b[33m● Bookmarked Spans\x1b[0m  (${bookmarks.length} total)\n`);
  printTable(
    ['ID', 'Span ID', 'Session', 'Note', 'Created'],
    bookmarks.map((b: any) => [
      String(b.id),
      b.spanId.length > 24 ? b.spanId.slice(0, 24) + '…' : b.spanId,
      b.traceId ? (b.traceId.length > 16 ? b.traceId.slice(0, 16) + '…' : b.traceId) : '—',
      b.note || '—',
      new Date(b.createdAt).toLocaleString(),
    ]),
  );
}

function printHelp() {
  console.log(`
\x1b[1m\x1b[35mClaudeSec CLI\x1b[0m

\x1b[1mSetup & Monitoring:\x1b[0m
  \x1b[33mclaudesec\x1b[0m / \x1b[33mstart\x1b[0m              Install + start the background watcher, open the dashboard
  \x1b[33mclaudesec stop\x1b[0m                    Stop and remove the background service
  \x1b[33mclaudesec status\x1b[0m                  Show server health and span counts
  \x1b[33mclaudesec open\x1b[0m                    Open the dashboard and pair this browser so it
                                       can change settings (reads never need pairing)
  \x1b[33mclaudesec tail\x1b[0m [--harness X] [--severity Y]   Stream live spans
  \x1b[33mclaudesec processes\x1b[0m               List running agent processes (macOS/Linux)

\x1b[1mData:\x1b[0m
  \x1b[33mclaudesec export\x1b[0m [file]           Download all spans as JSON
  \x1b[33mclaudesec reset\x1b[0m                   Wipe all data (with confirmation)
  \x1b[33mclaudesec search\x1b[0m <query> [--severity X] [--harness X] [--limit N]
  \x1b[33mclaudesec sessions\x1b[0m [--json]        List all sessions with health scores
  \x1b[33mclaudesec bookmarks\x1b[0m [--session ID] [--delete ID]   View or delete bookmarks

\x1b[1mAnalytics:\x1b[0m
  \x1b[33mclaudesec top\x1b[0m [--by spans|threats|health] [--limit N]
  \x1b[33mclaudesec report\x1b[0m <sessionId|latest> [--out file.md]

\x1b[1mEnforcement:\x1b[0m
  \x1b[33mclaudesec install-hook\x1b[0m [--yes]    Register the PreToolUse enforcement hook with
                                       Claude Code (asks before editing settings.json).
                                       Blocking is fail-open by design; rule-based
                                       blocking needs enforce mode (Enforce tab / CLAUDESEC_MODE).
  \x1b[33mclaudesec uninstall-hook\x1b[0m [--purge]  Remove only our hook entries (--purge also
                                       deletes ~/.claudesec/hooks). Run this from your own
                                       shell — the enforcement floor refuses it (and
                                       \x1b[33mstop\x1b[0m / \x1b[33muninstall\x1b[0m) inside an agent session, so an
                                       agent cannot ask ClaudeSec to remove itself.
  \x1b[33mclaudesec audit-key\x1b[0m [status]       Show where the Ed25519 audit signing key lives
  \x1b[33mclaudesec audit-key to-keychain\x1b[0m [--remove-file]   Move it into the macOS Keychain,
                                       out of cat/rm range. Verifies a sign+verify round
                                       trip first; leaves the file alone unless asked.
  \x1b[33mclaudesec audit-key to-file\x1b[0m        Move it back to ~/.claudesec/hooks (reversible)
  \x1b[33mclaudesec mcp-proxy\x1b[0m -- <mcp-server-cmd> [args...]   Gate any MCP server's
                                       tool calls against ClaudeSec rules (stdio).
                                       Point an agent's mcpServers config here instead
                                       of the real server. Respects CLAUDESEC_MODE.

\x1b[1mSeverity levels:\x1b[0m  \x1b[31mhigh\x1b[0m  \x1b[33mmedium\x1b[0m  \x1b[34mlow\x1b[0m  \x1b[32mnone\x1b[0m
\x1b[90mDashboard: ${BASE_URL}\x1b[0m
`);
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

async function main() {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case undefined:
    case 'start':
    case 'init':     await cmdStart();               break;
    case 'stop':
    case 'uninstall': await cmdStop();               break;
    case 'status':   await cmdStatus();              break;
    case 'export':   await cmdExport(rest[0]);       break;
    case 'reset':    await cmdReset();               break;
    case 'open':     cmdOpen();                      break;
    case 'tail':     await cmdTail(rest);            break;
    case 'top':      await cmdTop(rest);             break;
    case 'search':   await cmdSearch(rest);          break;
    case 'sessions': await cmdSessions(rest);        break;
    case 'report':    await cmdReport(rest);          break;
    case 'processes':  await cmdProcesses(rest);        break;
    case 'bookmarks':  await cmdBookmarks(rest);        break;
    case 'install-hook':   await installHook(rest);       break;
    case 'uninstall-hook': await uninstallHook(rest);     break;
    case 'audit-key':      await cmdAuditKey(rest);       break;
    case '--help':
    case '-h':
    case 'help':     printHelp();                    break;
    default:
      console.error(`\x1b[31mUnknown command: ${cmd}\x1b[0m`);
      printHelp();
      process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
