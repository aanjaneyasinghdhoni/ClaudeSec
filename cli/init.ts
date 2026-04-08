#!/usr/bin/env node
/**
 * ClaudeSec CLI
 *
 * Usage:
 *   claudesec              — interactive setup wizard (alias for `init`)
 *   claudesec init         — interactive setup wizard
 *   claudesec status       — show server health, span/session counts, uptime
 *   claudesec export [file]— download all spans as JSON (default: claudesec-export-<ts>.json)
 *   claudesec reset        — confirm + wipe all spans, sessions, and alerts
 *   claudesec open         — open dashboard in the default browser
 */
import { createInterface } from 'readline';
import { execSync }        from 'child_process';
import * as fs             from 'fs';
import { HARNESSES, type HarnessConfig } from '../src/harnesses.js';

const PORT     = process.env.CLAUDESEC_PORT ?? '3000';
const BASE_URL = `http://localhost:${PORT}`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function prompt(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, resolve));
}

function printExports(harness: HarnessConfig) {
  const endpoint = `${BASE_URL}/v1/traces`;
  console.log(`\n\x1b[1m\x1b[36m# ${harness.name} — copy and paste into your terminal:\x1b[0m\n`);
  for (const env of harness.envVars) {
    const val = env.value.replace('{{ENDPOINT}}', endpoint);
    console.log(`\x1b[32mexport ${env.key}="${val}"\x1b[0m   # ${env.description}`);
  }
  console.log(`\n\x1b[90mThen restart ${harness.name} and open ${BASE_URL}\x1b[0m\n`);
  if (harness.docsUrl) {
    console.log(`\x1b[90mDocs: ${harness.docsUrl}\x1b[0m\n`);
  }
}

async function apiFetch(path: string, opts?: { method?: string; body?: unknown }): Promise<any> {
  const url = `${BASE_URL}${path}`;
  const init: RequestInit = {
    method: opts?.method ?? 'GET',
    headers: { 'Content-Type': 'application/json' },
    ...(opts?.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  };
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json().catch(() => null);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdInit() {
  console.log('\n\x1b[1m\x1b[35mClaudeSec — Agent Setup Wizard\x1b[0m');
  console.log('\x1b[90mConnects any AI agent harness to the local observatory.\x1b[0m\n');

  const rl      = createInterface({ input: process.stdin, output: process.stdout });
  const choices = HARNESSES.filter(h => h.id !== 'unknown');
  choices.forEach((h, i) => {
    console.log(`  \x1b[33m${i + 1}.\x1b[0m ${h.name.padEnd(20)} \x1b[90m${h.description}\x1b[0m`);
  });
  console.log(`  \x1b[33m${choices.length + 1}.\x1b[0m Show all (generic OTLP)\n`);

  const raw = await prompt(rl, '\x1b[1mSelect your harness (number): \x1b[0m');
  const idx = parseInt(raw.trim(), 10) - 1;

  if (idx === choices.length) {
    for (const h of choices) printExports(h);
  } else if (idx >= 0 && idx < choices.length) {
    printExports(choices[idx]);
  } else {
    console.error('\x1b[31mInvalid selection.\x1b[0m');
    rl.close();
    process.exit(1);
  }
  rl.close();
}

async function cmdStatus() {
  console.log(`\n\x1b[1m\x1b[35mClaudeSec Status\x1b[0m  \x1b[90m(${BASE_URL})\x1b[0m\n`);
  let health: any;
  try {
    health = await apiFetch('/api/health');
  } catch {
    console.error(`\x1b[31m✗ Server unreachable at ${BASE_URL}\x1b[0m`);
    console.error('\x1b[90m  Run: npm run dev  or  docker compose up\x1b[0m\n');
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

function cmdOpen() {
  console.log(`\n\x1b[90mOpening ${BASE_URL} …\x1b[0m\n`);
  const platform = process.platform;
  try {
    if (platform === 'darwin')       execSync(`open "${BASE_URL}"`);
    else if (platform === 'win32')   execSync(`start "${BASE_URL}"`);
    else                             execSync(`xdg-open "${BASE_URL}"`);
  } catch {
    console.log(`\x1b[33mCould not open browser. Visit ${BASE_URL} manually.\x1b[0m`);
  }
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

function printHelp() {
  console.log(`
\x1b[1m\x1b[35mClaudeSec CLI\x1b[0m

\x1b[1mSetup & Monitoring:\x1b[0m
  \x1b[33mclaudesec\x1b[0m / \x1b[33minit\x1b[0m               Interactive harness setup wizard
  \x1b[33mclaudesec status\x1b[0m                  Show server health and span counts
  \x1b[33mclaudesec open\x1b[0m                    Open the dashboard in default browser
  \x1b[33mclaudesec tail\x1b[0m [--harness X] [--severity Y]   Stream live spans
  \x1b[33mclaudesec processes\x1b[0m               List running agent processes (macOS/Linux)

\x1b[1mData:\x1b[0m
  \x1b[33mclaudesec export\x1b[0m [file]           Download all spans as JSON
  \x1b[33mclaudesec reset\x1b[0m                   Wipe all data (with confirmation)
  \x1b[33mclaudesec search\x1b[0m <query> [--severity X] [--harness X] [--limit N]
  \x1b[33mclaudesec sessions\x1b[0m [--json]        List all sessions with health scores

\x1b[1mAnalytics:\x1b[0m
  \x1b[33mclaudesec top\x1b[0m [--by spans|threats|health] [--limit N]
  \x1b[33mclaudesec report\x1b[0m <sessionId|latest> [--out file.md]

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
    case 'init':     await cmdInit();                break;
    case 'status':   await cmdStatus();              break;
    case 'export':   await cmdExport(rest[0]);       break;
    case 'reset':    await cmdReset();               break;
    case 'open':     cmdOpen();                      break;
    case 'tail':     await cmdTail(rest);            break;
    case 'top':      await cmdTop(rest);             break;
    case 'search':   await cmdSearch(rest);          break;
    case 'sessions': await cmdSessions(rest);        break;
    case 'report':    await cmdReport(rest);          break;
    case 'processes': await cmdProcesses(rest);       break;
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
