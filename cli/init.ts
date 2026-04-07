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

function printHelp() {
  console.log(`
\x1b[1m\x1b[35mClaudeSec CLI\x1b[0m

\x1b[1mUsage:\x1b[0m
  \x1b[33mclaudesec\x1b[0m                              Interactive setup wizard
  \x1b[33mclaudesec init\x1b[0m                         Interactive setup wizard
  \x1b[33mclaudesec status\x1b[0m                       Show server health and span counts
  \x1b[33mclaudesec export [file]\x1b[0m                Download all spans as JSON
  \x1b[33mclaudesec reset\x1b[0m                        Wipe all data (with confirmation)
  \x1b[33mclaudesec open\x1b[0m                         Open the dashboard in your browser
  \x1b[33mclaudesec tail [--harness X] [--severity Y]\x1b[0m   Stream live spans to terminal
  \x1b[33mclaudesec help\x1b[0m                         Show this help

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
    case 'init':   await cmdInit();                  break;
    case 'status': await cmdStatus();                break;
    case 'export': await cmdExport(rest[0]);         break;
    case 'reset':  await cmdReset();                 break;
    case 'open':   cmdOpen();                        break;
    case 'tail':   await cmdTail(rest);              break;
    case '--help':
    case '-h':
    case 'help':   printHelp();                      break;
    default:
      console.error(`\x1b[31mUnknown command: ${cmd}\x1b[0m`);
      printHelp();
      process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
