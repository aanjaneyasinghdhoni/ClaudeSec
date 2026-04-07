import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import { detectHarness, HARNESSES } from './src/harnesses.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface OTelSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: number;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: { key: string; value: any }[];
  status: { code: number };
}

interface TraceData {
  resourceSpans: {
    resource: any;
    scopeSpans: { scope: any; spans: OTelSpan[] }[];
  }[];
}

type Severity = 'none' | 'low' | 'medium' | 'high';

interface CustomRule {
  id: string;
  pattern: string;
  flags: string;
  severity: Severity;
  label: string;
  createdAt: string;
}

interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}

// ---------------------------------------------------------------------------
// SQLite setup
// ---------------------------------------------------------------------------

const db = new Database('spans.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS spans (
    spanId     TEXT PRIMARY KEY,
    traceId    TEXT NOT NULL DEFAULT 'unknown',
    parentId   TEXT NOT NULL,
    name       TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'none',
    harness    TEXT NOT NULL DEFAULT 'unknown',
    attributes TEXT NOT NULL DEFAULT '{}',
    startNano  TEXT NOT NULL DEFAULT '0',
    endNano    TEXT NOT NULL DEFAULT '0'
  );
`);

// Safe schema migrations for existing databases
try { db.exec(`ALTER TABLE spans ADD COLUMN traceId TEXT NOT NULL DEFAULT 'unknown'`); } catch {}
try { db.exec(`ALTER TABLE spans ADD COLUMN harness TEXT NOT NULL DEFAULT 'unknown'`); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    traceId   TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

const insertSpan = db.prepare(`
  INSERT OR IGNORE INTO spans
    (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
  VALUES
    (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness, @attributes, @startNano, @endNano)
`);

const upsertSession = db.prepare(
  `INSERT OR IGNORE INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)`
);

const deleteAllSpans    = db.prepare(`DELETE FROM spans`);
const deleteAllSessions = db.prepare(`DELETE FROM sessions`);
const getAllSpans        = db.prepare(`SELECT * FROM spans`);

// ---------------------------------------------------------------------------
// Alerts table
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    ruleLabel   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    spanId      TEXT NOT NULL,
    traceId     TEXT NOT NULL,
    harness     TEXT NOT NULL DEFAULT 'unknown',
    spanName    TEXT NOT NULL,
    matchedText TEXT NOT NULL DEFAULT ''
  );
`);

const insertAlert = db.prepare(`
  INSERT INTO alerts (ts, ruleLabel, severity, spanId, traceId, harness, spanName, matchedText)
  VALUES (@ts, @ruleLabel, @severity, @spanId, @traceId, @harness, @spanName, @matchedText)
`);

const deleteAllAlerts = db.prepare(`DELETE FROM alerts`);

// ---------------------------------------------------------------------------
// Config table (webhook URL, thresholds, etc.)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const getConfig = db.prepare<[string], { value: string }>(`SELECT value FROM config WHERE key = ?`);
const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);
const delConfig = db.prepare(`DELETE FROM config WHERE key = ?`);

// ---------------------------------------------------------------------------
// Custom rules persistence
// ---------------------------------------------------------------------------

const RULES_FILE = path.join(__dirname, 'rules.json');
let customRules: CustomRule[] = [];

function loadCustomRules() {
  try {
    if (fs.existsSync(RULES_FILE)) {
      customRules = JSON.parse(fs.readFileSync(RULES_FILE, 'utf-8'));
    }
  } catch { customRules = []; }
}

function saveCustomRules() {
  fs.writeFileSync(RULES_FILE, JSON.stringify(customRules, null, 2));
}

loadCustomRules();

// ---------------------------------------------------------------------------
// Retention policy + DB health
// ---------------------------------------------------------------------------

function getMaxSpans(): number {
  const env = Number(process.env.CLAUDESEC_MAX_SPANS);
  if (env > 0) return env;
  const cfg = Number(getConfig.get('retention.max_spans')?.value ?? 0);
  return cfg > 0 ? cfg : 50_000;
}

function getRetentionDays(): number {
  const env = Number(process.env.CLAUDESEC_RETENTION_DAYS);
  if (env > 0) return env;
  const cfg = Number(getConfig.get('retention.days')?.value ?? 0);
  return cfg > 0 ? cfg : 30;
}

function pruneSpans(): { prunedByAge: number; prunedByCount: number } {
  let prunedByAge = 0;
  let prunedByCount = 0;

  // Age-based pruning: remove sessions (and their spans/alerts) older than N days
  const cutoffDays = getRetentionDays();
  const cutoffDate = new Date(Date.now() - cutoffDays * 24 * 60 * 60 * 1000).toISOString();
  const oldSessions = db.prepare(
    `SELECT traceId FROM sessions WHERE createdAt < ?`
  ).all(cutoffDate) as { traceId: string }[];

  for (const { traceId } of oldSessions) {
    const deleted = (db.prepare(`DELETE FROM spans WHERE traceId = ?`).run(traceId)).changes;
    db.prepare(`DELETE FROM alerts WHERE traceId = ?`).run(traceId);
    db.prepare(`DELETE FROM sessions WHERE traceId = ?`).run(traceId);
    prunedByAge += deleted;
  }

  // Count-based pruning: keep only the most recent max_spans spans
  const maxSpans = getMaxSpans();
  const totalSpans = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
  if (totalSpans > maxSpans) {
    const excess = totalSpans - maxSpans;
    // Delete oldest spans by rowid
    const result = db.prepare(
      `DELETE FROM spans WHERE rowid IN (SELECT rowid FROM spans ORDER BY startNano ASC LIMIT ?)`
    ).run(excess);
    prunedByCount = result.changes;
  }

  return { prunedByAge, prunedByCount };
}

// ---------------------------------------------------------------------------
// Behavioral anomaly detection
// ---------------------------------------------------------------------------

// Runs after each OTLP batch — checks for statistical anomalies per session
function detectBehavioralAnomalies(traceId: string, harness: string): void {
  const spans = db.prepare(`SELECT * FROM spans WHERE traceId = ?`).all(traceId) as SpanRecord[];
  if (spans.length === 0) return;

  const now = new Date().toISOString();

  // 1. Token spike detection
  //    Flag if a single span uses > 3× the session average input tokens
  const tokenValues: number[] = [];
  for (const span of spans) {
    try {
      const attrs = JSON.parse(span.attributes);
      const ti = Number(attrs['gen_ai.usage.input_tokens'] ?? attrs['llm.usage.input_tokens'] ?? 0);
      if (ti > 0) tokenValues.push(ti);
    } catch {}
  }
  if (tokenValues.length >= 3) {
    const avg = tokenValues.reduce((a, b) => a + b, 0) / tokenValues.length;
    const latest = tokenValues[tokenValues.length - 1];
    if (latest > avg * 4 && latest > 2000) {
      const alreadyFlagged = db.prepare(
        `SELECT 1 FROM alerts WHERE traceId = ? AND ruleLabel = 'Token spike detected' AND ts > datetime('now', '-5 minutes')`
      ).get(traceId);
      if (!alreadyFlagged) {
        insertAlert.run({
          ts: now,
          ruleLabel:   'Token spike detected',
          severity:    'medium' as Severity,
          spanId:      spans[spans.length - 1].spanId,
          traceId,
          harness,
          spanName:    'behavioral-anomaly',
          matchedText: `${latest} tokens (avg: ${Math.round(avg)})`,
        });
      }
    }
  }

  // 2. Threat escalation — >= 3 threats in last 10 spans (concentrated threat burst)
  const recentThreats = spans.slice(-10).filter(s => s.severity !== 'none').length;
  if (recentThreats >= 3) {
    const alreadyFlagged = db.prepare(
      `SELECT 1 FROM alerts WHERE traceId = ? AND ruleLabel = 'Threat burst detected' AND ts > datetime('now', '-10 minutes')`
    ).get(traceId);
    if (!alreadyFlagged) {
      insertAlert.run({
        ts: now,
        ruleLabel:   'Threat burst detected',
        severity:    'high' as Severity,
        spanId:      spans[spans.length - 1].spanId,
        traceId,
        harness,
        spanName:    'behavioral-anomaly',
        matchedText: `${recentThreats} threats in last ${Math.min(spans.length, 10)} spans`,
      });
    }
  }

  // 3. Excessive tool calls — > 100 total tool calls in a session
  let toolCallCount = 0;
  for (const span of spans) {
    try {
      const attrs = JSON.parse(span.attributes);
      if (attrs['gen_ai.tool.name'] || attrs['tool.name']) toolCallCount++;
    } catch {}
  }
  if (toolCallCount > 100 && toolCallCount % 50 === 1) {
    // Flag once per 50 excess tool calls to avoid flooding
    const alreadyFlagged = db.prepare(
      `SELECT 1 FROM alerts WHERE traceId = ? AND ruleLabel = 'Excessive tool calls' AND ts > datetime('now', '-30 minutes')`
    ).get(traceId);
    if (!alreadyFlagged) {
      insertAlert.run({
        ts: now,
        ruleLabel:   'Excessive tool calls',
        severity:    'low' as Severity,
        spanId:      spans[spans.length - 1].spanId,
        traceId,
        harness,
        spanName:    'behavioral-anomaly',
        matchedText: `${toolCallCount} tool calls in session`,
      });
    }
  }

  // 4. Off-hours activity — outside 06:00–23:59 local time
  const hour = new Date().getHours();
  if (hour < 6) {
    const alreadyFlagged = db.prepare(
      `SELECT 1 FROM alerts WHERE traceId = ? AND ruleLabel = 'Off-hours agent activity' AND ts > datetime('now', '-60 minutes')`
    ).get(traceId);
    if (!alreadyFlagged) {
      insertAlert.run({
        ts: now,
        ruleLabel:   'Off-hours agent activity',
        severity:    'low' as Severity,
        spanId:      spans[spans.length - 1].spanId,
        traceId,
        harness,
        spanName:    'behavioral-anomaly',
        matchedText: `Activity at ${String(hour).padStart(2, '0')}:${String(new Date().getMinutes()).padStart(2, '0')} local time`,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Webhook alert delivery
// ---------------------------------------------------------------------------

const SERVER_START_MS = Date.now();

function getWebhookUrl(): string {
  // Env var takes precedence over DB config
  return process.env.CLAUDESEC_WEBHOOK_URL
    ?? (getConfig.get('webhook.url')?.value ?? '');
}

function getWebhookThreshold(): Severity {
  const t = process.env.CLAUDESEC_WEBHOOK_THRESHOLD
    ?? (getConfig.get('webhook.threshold')?.value ?? 'high');
  return (['low', 'medium', 'high'].includes(t) ? t : 'high') as Severity;
}

const SEV_RANK_MAP: Record<Severity, number> = { none: 0, low: 1, medium: 2, high: 3 };

async function fireWebhook(alert: {
  ruleLabel: string; severity: Severity; harness: string;
  spanName: string; matchedText: string; traceId: string;
}) {
  const url = getWebhookUrl();
  if (!url) return;

  const threshold = getWebhookThreshold();
  if (SEV_RANK_MAP[alert.severity] < SEV_RANK_MAP[threshold]) return;

  const isSlack   = url.includes('hooks.slack.com');
  const isDiscord = url.includes('discord.com/api/webhooks');

  const sevEmoji = alert.severity === 'high' ? '🔴' : alert.severity === 'medium' ? '🟠' : '🟡';

  let body: string;
  if (isSlack) {
    body = JSON.stringify({
      text: `${sevEmoji} ClaudeSec *${alert.severity.toUpperCase()}* alert — ${alert.ruleLabel}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `${sevEmoji} ${alert.severity.toUpperCase()}: ${alert.ruleLabel}` },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Agent*\n${alert.harness}` },
            { type: 'mrkdwn', text: `*Span*\n${alert.spanName}` },
            { type: 'mrkdwn', text: `*Matched*\n\`${alert.matchedText}\`` },
            { type: 'mrkdwn', text: `*Trace*\n\`${alert.traceId.slice(0, 12)}…\`` },
          ],
        },
      ],
    });
  } else if (isDiscord) {
    const color = alert.severity === 'high' ? 0xef4444 : alert.severity === 'medium' ? 0xf97316 : 0xeab308;
    body = JSON.stringify({
      username: 'ClaudeSec',
      avatar_url: 'https://raw.githubusercontent.com/aanjaneyasinghdhoni/ClaudeSec/main/public/logo.png',
      embeds: [{
        title: `${sevEmoji} ${alert.severity.toUpperCase()}: ${alert.ruleLabel}`,
        color,
        fields: [
          { name: 'Agent',   value: alert.harness,                         inline: true  },
          { name: 'Span',    value: alert.spanName,                        inline: true  },
          { name: 'Matched', value: `\`${alert.matchedText}\``,            inline: false },
          { name: 'Trace',   value: `\`${alert.traceId.slice(0, 16)}…\``, inline: false },
        ],
        timestamp: new Date().toISOString(),
        footer: { text: 'ClaudeSec · Local AI Agent Observatory' },
      }],
    });
  } else {
    // Generic JSON — works with any webhook handler (PagerDuty, n8n, custom)
    body = JSON.stringify({
      source:      'claudesec',
      severity:    alert.severity,
      rule:        alert.ruleLabel,
      harness:     alert.harness,
      spanName:    alert.spanName,
      matchedText: alert.matchedText,
      traceId:     alert.traceId,
      timestamp:   new Date().toISOString(),
    });
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) console.error(`[ClaudeSec] Webhook returned ${res.status}`);
  } catch (err) {
    console.error('[ClaudeSec] Webhook delivery failed:', (err as Error).message);
  }
}

// ---------------------------------------------------------------------------
// Token cost estimation — per-1M prices (input / output USD)
// ---------------------------------------------------------------------------

const MODEL_PRICING: Record<string, { inputPer1M: number; outputPer1M: number; label: string }> = {
  // Claude
  'claude-opus-4-6':      { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude Opus 4.6' },
  'claude-opus-4-5':      { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude Opus 4.5' },
  'claude-opus-4':        { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude Opus 4' },
  'claude-sonnet-4-6':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 4.6' },
  'claude-sonnet-4-5':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 4.5' },
  'claude-sonnet-3-7':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 3.7' },
  'claude-sonnet-3-5':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 3.5' },
  'claude-haiku-4-5':     { inputPer1M: 0.8,   outputPer1M: 4,     label: 'Claude Haiku 4.5' },
  'claude-haiku-3-5':     { inputPer1M: 0.8,   outputPer1M: 4,     label: 'Claude Haiku 3.5' },
  'claude-3-haiku':       { inputPer1M: 0.25,  outputPer1M: 1.25,  label: 'Claude 3 Haiku' },
  'claude-3-5-sonnet':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude 3.5 Sonnet' },
  'claude-3-5-haiku':     { inputPer1M: 0.8,   outputPer1M: 4,     label: 'Claude 3.5 Haiku' },
  'claude-3-opus':        { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude 3 Opus' },
  // OpenAI
  'gpt-4o':               { inputPer1M: 5,     outputPer1M: 15,    label: 'GPT-4o' },
  'gpt-4o-mini':          { inputPer1M: 0.15,  outputPer1M: 0.6,   label: 'GPT-4o mini' },
  'gpt-4-turbo':          { inputPer1M: 10,    outputPer1M: 30,    label: 'GPT-4 Turbo' },
  'gpt-4':                { inputPer1M: 30,    outputPer1M: 60,    label: 'GPT-4' },
  'gpt-3.5-turbo':        { inputPer1M: 0.5,   outputPer1M: 1.5,   label: 'GPT-3.5 Turbo' },
  // Google
  'gemini-1.5-pro':       { inputPer1M: 3.5,   outputPer1M: 10.5,  label: 'Gemini 1.5 Pro' },
  'gemini-1.5-flash':     { inputPer1M: 0.075, outputPer1M: 0.3,   label: 'Gemini 1.5 Flash' },
  'gemini-2.0-flash':     { inputPer1M: 0.1,   outputPer1M: 0.4,   label: 'Gemini 2.0 Flash' },
  'gemini-pro':           { inputPer1M: 0.5,   outputPer1M: 1.5,   label: 'Gemini Pro' },
};

function lookupPricing(model: string) {
  if (!model) return null;
  const lower = model.toLowerCase();
  // Direct match
  if (MODEL_PRICING[lower]) return MODEL_PRICING[lower];
  // Prefix match (e.g. "claude-opus-4-6-20250514" → "claude-opus-4-6")
  for (const key of Object.keys(MODEL_PRICING)) {
    if (lower.startsWith(key)) return MODEL_PRICING[key];
  }
  return null;
}

// ---------------------------------------------------------------------------
// Security detection
// ---------------------------------------------------------------------------

const SEVERITY_RULES: { pattern: RegExp; severity: Severity; label: string }[] = [
  // HIGH — system compromise / data destruction
  { pattern: /rm\s+-rf\s+[\/\\]/i,                       severity: 'high',   label: 'Recursive root deletion' },
  { pattern: /cat\s+\/etc\/passwd/i,                      severity: 'high',   label: 'Passwd file read' },
  { pattern: /curl\s+.*\|\s*(ba)?sh/i,                    severity: 'high',   label: 'Remote code execution via curl' },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i,                    severity: 'high',   label: 'Remote code execution via wget' },
  { pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)/i,           severity: 'high',   label: 'SQL destructive operation' },
  { pattern: /TRUNCATE\s+TABLE/i,                         severity: 'high',   label: 'SQL table truncation' },
  { pattern: /eval\s*\(/i,                                severity: 'high',   label: 'Code eval injection' },
  { pattern: /exec\s*\(/i,                                severity: 'high',   label: 'Exec injection' },
  // Prompt injection
  { pattern: /ignore\s+(previous|prior|all)\s+instructions?/i, severity: 'high', label: 'Prompt injection attempt' },
  { pattern: /disregard\s+your\s+(previous|prior|system)/i,    severity: 'high', label: 'Prompt injection attempt' },
  { pattern: /you\s+are\s+now\s+DAN/i,                         severity: 'high', label: 'DAN jailbreak attempt' },
  // Secret patterns
  { pattern: /AKIA[0-9A-Z]{16}/,                         severity: 'high',   label: 'AWS access key detected' },
  { pattern: /ghp_[A-Za-z0-9]{36}/,                      severity: 'high',   label: 'GitHub token detected' },
  { pattern: /sk-[A-Za-z0-9]{48}/,                       severity: 'high',   label: 'OpenAI API key detected' },
  // MEDIUM — exfiltration / sensitive access
  { pattern: /process\.env/i,                            severity: 'medium', label: 'Environment variable access' },
  { pattern: /\.env\b/,                                  severity: 'medium', label: 'Dotenv file access' },
  { pattern: /ssh-add/i,                                 severity: 'medium', label: 'SSH key manipulation' },
  { pattern: /\/etc\/(shadow|hosts|sudoers)/i,           severity: 'medium', label: 'Sensitive system file access' },
  { pattern: /atob\s*\(/i,                               severity: 'medium', label: 'Base64 decode' },
  { pattern: /base64\s+-d/i,                             severity: 'medium', label: 'Base64 decode' },
  { pattern: /~\/\.ssh\//i,                              severity: 'medium', label: 'SSH directory access' },
  { pattern: /security\s+find-generic-password/i,        severity: 'medium', label: 'macOS keychain access' },
  // LOW — suspicious but possibly legitimate
  { pattern: /SELECT\s+\*\s+FROM/i,                      severity: 'low',    label: 'Full table scan' },
  { pattern: /chmod\s+[0-7]*7[0-7]*/i,                   severity: 'low',    label: 'World-executable permission' },
  { pattern: /sudo\s+/i,                                 severity: 'low',    label: 'Sudo usage' },
  { pattern: /npm\s+install\s+--global/i,                severity: 'low',    label: 'Global npm package install' },
  { pattern: /pip\s+install/i,                           severity: 'low',    label: 'Python package install' },
  // Supply-chain / advanced
  { pattern: /pip\s+install\s+.*--index-url/i,           severity: 'high',   label: 'Supply-chain: custom PyPI index' },
  { pattern: /npm\s+install.*--registry/i,               severity: 'high',   label: 'Supply-chain: custom npm registry' },
  { pattern: /git\s+clone\s+.*&&\s*(ba)?sh/i,            severity: 'high',   label: 'Clone-and-execute' },
  { pattern: /\/dev\/tcp\//i,                             severity: 'high',   label: 'Bash TCP reverse shell' },
  { pattern: /python[23]?\s+-c\s+["']import/i,           severity: 'medium', label: 'Python one-liner execution' },
];

function detectSeverity(text: string): { severity: Severity; matchedLabel: string; matchedText: string } {
  // Check custom rules first
  for (const rule of customRules) {
    try {
      const re = new RegExp(rule.pattern, rule.flags);
      const m = re.exec(text);
      if (m) return { severity: rule.severity, matchedLabel: rule.label, matchedText: m[0].slice(0, 100) };
    } catch { /* invalid regex — skip */ }
  }
  // Built-in rules
  for (const rule of SEVERITY_RULES) {
    const m = rule.pattern.exec(text);
    if (m) return { severity: rule.severity, matchedLabel: rule.label, matchedText: m[0].slice(0, 100) };
  }
  return { severity: 'none', matchedLabel: '', matchedText: '' };
}

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<Severity, { bg: string; border: string }> = {
  none:   { bg: '',        border: '' },
  low:    { bg: '#fefce8', border: '#eab308' },
  medium: { bg: '#fff7ed', border: '#f97316' },
  high:   { bg: '#fee2e2', border: '#ef4444' },
};

function recordToNode(r: SpanRecord) {
  const style = SEVERITY_STYLES[r.severity as Severity];
  return {
    id: r.spanId,
    data: {
      label:       r.name,
      attributes:  JSON.parse(r.attributes),
      severity:    r.severity,
      isMalicious: r.severity !== 'none',
      protocol:    r.protocol,
      reason:      r.reason,
      harness:     r.harness,
      traceId:     r.traceId,
      startNano:   r.startNano,
      endNano:     r.endNano,
    },
    position: { x: 0, y: 0 },
    style: style.border ? { backgroundColor: style.bg, border: `2px solid ${style.border}` } : {},
  };
}

function recordToEdge(r: SpanRecord) {
  const isAlert  = r.severity !== 'none';
  const edgeColor =
    r.severity === 'high'   ? '#ef4444' :
    r.severity === 'medium' ? '#f97316' :
    r.severity === 'low'    ? '#eab308' : '#64748b';
  return {
    id:       `e-${r.parentId}-${r.spanId}`,
    source:   r.parentId,
    target:   r.spanId,
    label:    r.protocol,
    animated: true,
    style:    isAlert ? { stroke: edgeColor } : {},
  };
}

function buildGraph(sessionFilter?: string) {
  const records: SpanRecord[] = sessionFilter
    ? (db.prepare('SELECT * FROM spans WHERE traceId = ?').all(sessionFilter) as SpanRecord[])
    : (getAllSpans.all() as SpanRecord[]);

  const presentHarnesses = [...new Set(records.map(r => r.harness))];
  let rootNodes: object[];

  if (presentHarnesses.length === 0) {
    rootNodes = [{ id: 'agent', data: { label: 'AI Agent' }, position: { x: 0, y: 0 }, type: 'input' }];
  } else {
    rootNodes = presentHarnesses.map(harnessId => {
      const h = HARNESSES.find(h => h.id === harnessId) ?? HARNESSES[HARNESSES.length - 1];
      return {
        id:   h.id,
        data: { label: h.name, isRoot: true, harnessColor: h.color },
        position: { x: 0, y: 0 },
        type: 'input',
        style: { backgroundColor: h.color + '22', border: `2px solid ${h.color}`, color: '#fff' },
      };
    });
  }

  return { nodes: [...rootNodes, ...records.map(recordToNode)], edges: records.map(recordToEdge) };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function startServer() {
  const app        = express();
  const httpServer = createServer(app);
  const io         = new Server(httpServer, { cors: { origin: '*' } });

  app.use(cors());
  app.use(bodyParser.json({ limit: '10mb' }));

  // ── OTLP ingestion ──────────────────────────────────────────────────────
  app.post('/v1/traces', (req, res) => {
    const traceData: TraceData = req.body;
    let newSessions   = false;
    let alertsChanged = false;

    traceData.resourceSpans?.forEach(rs => {
      const serviceName = String(
        rs.resource?.attributes?.find?.((a: any) => a.key === 'service.name')?.value?.stringValue ?? ''
      );
      const sdkName = String(
        rs.resource?.attributes?.find?.((a: any) => a.key === 'telemetry.sdk.name')?.value?.stringValue ?? ''
      );
      const harness = detectHarness(serviceName, sdkName);

      rs.scopeSpans?.forEach(ss => {
        ss.spans?.forEach(span => {
          const attrs: Record<string, any> = {};
          (span.attributes || []).forEach(attr => {
            attrs[attr.key] =
              attr.value?.stringValue ??
              attr.value?.intValue    ??
              attr.value?.boolValue   ??
              JSON.stringify(attr.value);
          });

          const searchText = JSON.stringify(attrs) + ' ' + span.name;
          const { severity, matchedLabel, matchedText } = detectSeverity(searchText);
          if (matchedLabel) attrs['claudesec.threat.rule'] = matchedLabel;

          const traceId  = span.traceId  || 'unknown';
          const parentId = span.parentSpanId || harness.id;

          // Auto-create session for new traceIds
          if (!db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(traceId)) {
            const sessionName = `${harness.name} · ${new Date().toLocaleTimeString()}`;
            upsertSession.run(traceId, sessionName, new Date().toISOString());
            newSessions = true;
          }

          insertSpan.run({
            spanId:    span.spanId,
            traceId,
            parentId,
            name:      span.name,
            protocol:  String(attrs['protocol'] ?? 'HTTPS'),
            reason:    String(attrs['reason']   ?? 'Processing step'),
            severity,
            harness:   harness.id,
            attributes: JSON.stringify(attrs),
            startNano:  String(span.startTimeUnixNano ?? '0'),
            endNano:    String(span.endTimeUnixNano   ?? '0'),
          } satisfies SpanRecord);

          if (matchedLabel) {
            insertAlert.run({
              ts:          new Date().toISOString(),
              ruleLabel:   matchedLabel,
              severity,
              spanId:      span.spanId,
              traceId,
              harness:     harness.id,
              spanName:    span.name,
              matchedText,
            });
            alertsChanged = true;
            // Fire webhook asynchronously — don't block OTLP ingestion
            fireWebhook({
              ruleLabel:   matchedLabel,
              severity,
              harness:     harness.id,
              spanName:    span.name,
              matchedText,
              traceId,
            }).catch(() => {});
          }
        });
      });
    });

    // Behavioral anomaly detection — run per affected session
    const affectedTraces = new Set<string>();
    traceData.resourceSpans?.forEach(rs => {
      rs.scopeSpans?.forEach(ss => {
        ss.spans?.forEach(span => {
          if (span.traceId) affectedTraces.add(span.traceId);
        });
      });
    });

    for (const traceId of affectedTraces) {
      const traceHarness = (db.prepare('SELECT harness FROM spans WHERE traceId = ? LIMIT 1')
        .get(traceId) as { harness: string } | undefined)?.harness ?? 'unknown';
      detectBehavioralAnomalies(traceId, traceHarness);
    }

    // Retention pruning (async — don't block response)
    setImmediate(() => {
      const { prunedByAge, prunedByCount } = pruneSpans();
      if (prunedByAge + prunedByCount > 0) {
        console.log(`[ClaudeSec] Pruned ${prunedByAge} aged + ${prunedByCount} excess spans`);
        io.emit('sessions-update');
      }
    });

    io.emit('graph-update', buildGraph());
    if (newSessions)   io.emit('sessions-update');
    if (alertsChanged) io.emit('alerts-update');
    res.status(200).json({ status: 'ok' });
  });

  // ── Graph ────────────────────────────────────────────────────────────────
  app.get('/api/graph', (req, res) => {
    const session = req.query.session ? String(req.query.session) : undefined;
    res.json(buildGraph(session));
  });

  // ── Sessions ─────────────────────────────────────────────────────────────
  app.get('/api/sessions', (_req, res) => {
    const rows = db.prepare(`
      SELECT
        se.traceId,
        se.name,
        se.createdAt,
        COUNT(s.spanId) AS spanCount,
        SUM(CASE WHEN s.severity != 'none' THEN 1 ELSE 0 END) AS threatCount,
        MAX(CASE s.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS maxSeverityRank,
        GROUP_CONCAT(DISTINCT s.harness) AS harnesses
      FROM sessions se
      LEFT JOIN spans s ON s.traceId = se.traceId
      GROUP BY se.traceId
      ORDER BY se.createdAt DESC
    `).all();
    res.json({ sessions: rows });
  });

  app.patch('/api/sessions/:traceId', (req, res) => {
    const { name } = req.body as { name?: string };
    if (!name?.trim()) return res.status(400).json({ error: 'name required' }) as any;
    db.prepare('UPDATE sessions SET name = ? WHERE traceId = ?').run(name.trim(), req.params.traceId);
    io.emit('sessions-update');
    res.json({ status: 'ok' });
  });

  // ── Span search ──────────────────────────────────────────────────────────
  app.get('/api/spans', (req, res) => {
    const q       = String(req.query.q       ?? '').trim();
    const session = String(req.query.session ?? '').trim();

    let sql = 'SELECT * FROM spans WHERE 1=1';
    const params: unknown[] = [];

    if (session) { sql += ' AND traceId = ?'; params.push(session); }

    if (q) {
      if (q.includes('=')) {
        const eqIdx = q.indexOf('=');
        const key   = q.slice(0, eqIdx).trim();
        const val   = q.slice(eqIdx + 1).trim();
        sql += ' AND (attributes LIKE ? OR name LIKE ?)';
        params.push(`%"${key}":"${val}%`, `%${val}%`);
      } else {
        sql += ' AND (name LIKE ? OR attributes LIKE ? OR reason LIKE ?)';
        params.push(`%${q}%`, `%${q}%`, `%${q}%`);
      }
    }

    sql += ' ORDER BY startNano ASC LIMIT 500';
    res.json({ spans: db.prepare(sql).all(...params) as SpanRecord[] });
  });

  // ── Export ───────────────────────────────────────────────────────────────
  app.get('/api/export', (_req, res) => {
    const records = getAllSpans.all() as SpanRecord[];
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), version: '0.4.0', spans: records });
  });

  app.get('/api/export/csv', (_req, res) => {
    const records = getAllSpans.all() as SpanRecord[];
    const header  = 'spanId,traceId,name,harness,severity,protocol,reason,startNano,endNano\n';
    const rows    = records.map(r =>
      [
        r.spanId, r.traceId,
        `"${r.name.replace(/"/g, '""')}"`,
        r.harness, r.severity, r.protocol,
        `"${r.reason.replace(/"/g, '""')}"`,
        r.startNano, r.endNano,
      ].join(',')
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${Date.now()}.csv"`);
    res.send(header + rows);
  });

  // ── Active harnesses ─────────────────────────────────────────────────────
  app.get('/api/harnesses', (_req, res) => {
    res.json({
      harnesses: (db.prepare('SELECT DISTINCT harness FROM spans').all() as { harness: string }[])
        .map(r => r.harness),
    });
  });

  // ── Reset ────────────────────────────────────────────────────────────────
  app.post('/api/reset', (_req, res) => {
    deleteAllSpans.run();
    deleteAllSessions.run();
    deleteAllAlerts.run();
    io.emit('graph-update', buildGraph());
    io.emit('sessions-update');
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });

  // ── Rules CRUD ───────────────────────────────────────────────────────────
  app.get('/api/rules', (_req, res) => {
    const builtIn = SEVERITY_RULES.map((r, i) => ({
      id:       `builtin-${i}`,
      pattern:  r.pattern.source,
      flags:    r.pattern.flags,
      severity: r.severity,
      label:    r.label,
      builtin:  true,
    }));
    res.json({ builtIn, custom: customRules });
  });

  app.post('/api/rules', (req, res) => {
    const { pattern, severity, label } = req.body as { pattern?: string; severity?: string; label?: string };
    if (!pattern || !severity || !label) {
      return res.status(400).json({ error: 'pattern, severity, and label are required' }) as any;
    }
    const validSeverities: Severity[] = ['low', 'medium', 'high'];
    if (!validSeverities.includes(severity as Severity)) {
      return res.status(400).json({ error: 'severity must be low, medium, or high' }) as any;
    }
    try { new RegExp(pattern); } catch {
      return res.status(400).json({ error: 'invalid regex pattern' }) as any;
    }
    const rule: CustomRule = {
      id:        `custom-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      pattern,
      flags:     'i',
      severity:  severity as Severity,
      label,
      createdAt: new Date().toISOString(),
    };
    customRules.push(rule);
    saveCustomRules();
    io.emit('rules-update');
    res.status(201).json(rule);
  });

  app.delete('/api/rules/:id', (req, res) => {
    const idx = customRules.findIndex(r => r.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'rule not found' }) as any;
    customRules.splice(idx, 1);
    saveCustomRules();
    io.emit('rules-update');
    res.json({ status: 'ok' });
  });

  // ── Alerts ───────────────────────────────────────────────────────────────
  app.get('/api/alerts', (req, res) => {
    const limit    = Math.min(Number(req.query.limit ?? 200), 1000);
    const severity = req.query.severity ? String(req.query.severity) : null;

    let sql    = 'SELECT * FROM alerts';
    const params: unknown[] = [];
    if (severity && severity !== 'all') {
      sql += ' WHERE severity = ?';
      params.push(severity);
    }
    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    const alerts = db.prepare(sql).all(...params);
    const total  = (db.prepare(severity && severity !== 'all'
      ? 'SELECT COUNT(*) as c FROM alerts WHERE severity = ?'
      : 'SELECT COUNT(*) as c FROM alerts').get(...(severity && severity !== 'all' ? [severity] : [])) as any).c;

    res.json({ alerts, total });
  });

  app.get('/api/alerts/export', (_req, res) => {
    const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC').all();
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-alerts-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), alerts });
  });

  app.delete('/api/alerts', (_req, res) => {
    deleteAllAlerts.run();
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });

  // ── Orchestration ────────────────────────────────────────────────────────
  app.get('/api/orchestration', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];

    // Per-harness stats
    const agentMap = new Map<string, { harness: string; spanCount: number; threatCount: number; tools: Set<string> }>();
    for (const span of allSpans) {
      if (!agentMap.has(span.harness)) {
        agentMap.set(span.harness, { harness: span.harness, spanCount: 0, threatCount: 0, tools: new Set() });
      }
      const entry = agentMap.get(span.harness)!;
      entry.spanCount++;
      if (span.severity !== 'none') entry.threatCount++;
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['gen_ai.tool.name'] || attrs['tool.name'];
        if (toolName) entry.tools.add(String(toolName));
      } catch {}
    }

    const agents = [...agentMap.values()].map(a => ({
      harness:     a.harness,
      spanCount:   a.spanCount,
      threatCount: a.threatCount,
      tools:       [...a.tools],
    }));

    // Group spans by traceId to find co-occurring harnesses
    const traceHarnesses = new Map<string, { harness: string; startNano: string }[]>();
    for (const span of allSpans) {
      if (!traceHarnesses.has(span.traceId)) traceHarnesses.set(span.traceId, []);
      traceHarnesses.get(span.traceId)!.push({ harness: span.harness, startNano: span.startNano });
    }

    const edgeMap = new Map<string, { from: string; to: string; count: number }>();
    for (const [, spans] of traceHarnesses) {
      const unique = [...new Map(spans.map(s => [s.harness, s])).values()];
      if (unique.length < 2) continue;
      unique.sort((a, b) => {
        try { return Number(BigInt(a.startNano) - BigInt(b.startNano) > 0n ? 1 : -1); }
        catch { return 0; }
      });
      for (let i = 0; i < unique.length - 1; i++) {
        const key = `${unique[i].harness}→${unique[i + 1].harness}`;
        if (!edgeMap.has(key)) edgeMap.set(key, { from: unique[i].harness, to: unique[i + 1].harness, count: 0 });
        edgeMap.get(key)!.count++;
      }
    }

    const edges = [...edgeMap.values()];

    // Tool inventory (full matrix: toolName × harness)
    const toolMap = new Map<string, { toolName: string; harness: string; count: number; threatCount: number }>();
    for (const span of allSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['gen_ai.tool.name'] || attrs['tool.name'];
        if (!toolName) continue;
        const key = `${toolName}::${span.harness}`;
        if (!toolMap.has(key)) toolMap.set(key, { toolName: String(toolName), harness: span.harness, count: 0, threatCount: 0 });
        const entry = toolMap.get(key)!;
        entry.count++;
        if (span.severity !== 'none') entry.threatCount++;
      } catch {}
    }
    const tools = [...toolMap.values()].sort((a, b) => b.count - a.count).slice(0, 50);

    // ── Sub-agent spawn tree detection ──────────────────────────────────────
    // A spawn event is when span.parentId references a span from a DIFFERENT traceId.
    // This happens when Claude Code's Agent tool (or similar) creates child agents.

    // Build span index for O(1) parent lookup
    const spanIdx = new Map<string, { traceId: string; harness: string; name: string }>();
    for (const span of allSpans) {
      spanIdx.set(span.spanId, { traceId: span.traceId, harness: span.harness, name: span.name });
    }

    // Pre-fetch sessions for display names
    const sessionNames = new Map<string, string>();
    const sessionRows = db.prepare('SELECT traceId, name FROM sessions').all() as { traceId: string; name: string }[];
    for (const s of sessionRows) sessionNames.set(s.traceId, s.name);

    // Per-trace stats (reuse agentMap data, aggregate by traceId)
    const traceStatMap = new Map<string, { traceId: string; harness: string; spanCount: number; threatCount: number }>();
    for (const span of allSpans) {
      if (!traceStatMap.has(span.traceId)) {
        traceStatMap.set(span.traceId, { traceId: span.traceId, harness: span.harness, spanCount: 0, threatCount: 0 });
      }
      const ts = traceStatMap.get(span.traceId)!;
      ts.spanCount++;
      if (span.severity !== 'none') ts.threatCount++;
    }

    // Find cross-trace parent-child edges (unique by parentTrace→childTrace)
    const spawnChildMap = new Map<string, Set<string>>(); // parentTraceId → Set<childTraceId>
    const hasSpawnParent = new Set<string>();             // traceIds that are children

    for (const span of allSpans) {
      // parentId could be a harness root id (not a real span) — skip those
      const isHarnessRoot = HARNESSES.some(h => h.id === span.parentId);
      if (isHarnessRoot || !span.parentId) continue;

      const parentSpan = spanIdx.get(span.parentId);
      if (parentSpan && parentSpan.traceId !== span.traceId) {
        if (!spawnChildMap.has(parentSpan.traceId)) spawnChildMap.set(parentSpan.traceId, new Set());
        spawnChildMap.get(parentSpan.traceId)!.add(span.traceId);
        hasSpawnParent.add(span.traceId);
      }
    }

    // Also detect spawn-like spans by name/attribute patterns (agent.tool.name = "Agent", sub_agent, etc.)
    for (const span of allSpans) {
      const isSpawnSpan = /\b(sub.?agent|spawn|agent.tool|delegate)\b/i.test(span.name);
      if (!isSpawnSpan) continue;
      try {
        const attrs = JSON.parse(span.attributes);
        const childTraceId = attrs['agent.child_trace_id'] || attrs['subagent.trace_id'];
        if (childTraceId && typeof childTraceId === 'string' && childTraceId !== span.traceId) {
          if (!spawnChildMap.has(span.traceId)) spawnChildMap.set(span.traceId, new Set());
          spawnChildMap.get(span.traceId)!.add(childTraceId);
          hasSpawnParent.add(childTraceId);
        }
      } catch {}
    }

    interface SpawnTreeNode {
      traceId: string;
      harness: string;
      sessionName: string;
      spanCount: number;
      threatCount: number;
      children: SpawnTreeNode[];
    }

    function buildSpawnNode(traceId: string, visited = new Set<string>()): SpawnTreeNode {
      if (visited.has(traceId)) {
        return { traceId, harness: 'unknown', sessionName: traceId.slice(0, 8), spanCount: 0, threatCount: 0, children: [] };
      }
      visited.add(traceId);
      const stats = traceStatMap.get(traceId);
      const children = [...(spawnChildMap.get(traceId) ?? [])].map(c => buildSpawnNode(c, visited));
      return {
        traceId,
        harness:     stats?.harness     ?? 'unknown',
        sessionName: sessionNames.get(traceId) ?? traceId.slice(0, 8),
        spanCount:   stats?.spanCount   ?? 0,
        threatCount: stats?.threatCount ?? 0,
        children,
      };
    }

    // Root spawn nodes: traces that have children but are not themselves children of another
    const rootSpawnTraces = [...traceStatMap.keys()].filter(id =>
      spawnChildMap.has(id) && !hasSpawnParent.has(id)
    );
    const spawnTree = rootSpawnTraces.map(id => buildSpawnNode(id));

    res.json({ agents, edges, tools, spawnTree });
  });

  // ── DB stats + retention config ──────────────────────────────────────────
  app.get('/api/db-stats', (_req, res) => {
    const spansTotal    = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    const sessionsTotal = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c as number;
    const alertsTotal   = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c as number;
    const oldestSession = (db.prepare('SELECT MIN(createdAt) as d FROM sessions').get() as any).d as string | null;
    const newestSession = (db.prepare('SELECT MAX(createdAt) as d FROM sessions').get() as any).d as string | null;
    let dbSizeBytes = 0;
    try { dbSizeBytes = fs.statSync('spans.db').size; } catch {}

    res.json({
      spansTotal,
      sessionsTotal,
      alertsTotal,
      dbSizeBytes,
      dbSizeHuman: dbSizeBytes > 1_048_576
        ? `${(dbSizeBytes / 1_048_576).toFixed(1)} MB`
        : `${(dbSizeBytes / 1024).toFixed(1)} KB`,
      oldestSession,
      newestSession,
      retentionConfig: {
        maxSpans:      getMaxSpans(),
        retentionDays: getRetentionDays(),
      },
    });
  });

  app.post('/api/db-stats/prune', (_req, res) => {
    const result = pruneSpans();
    io.emit('sessions-update');
    io.emit('graph-update', buildGraph());
    res.json({ status: 'ok', ...result });
  });

  app.post('/api/db-stats/retention', (req, res) => {
    const { maxSpans, retentionDays } = req.body as { maxSpans?: number; retentionDays?: number };
    if (maxSpans !== undefined) {
      if (maxSpans < 100) return res.status(400).json({ error: 'maxSpans must be >= 100' }) as any;
      setConfig.run('retention.max_spans', String(maxSpans));
    }
    if (retentionDays !== undefined) {
      if (retentionDays < 1) return res.status(400).json({ error: 'retentionDays must be >= 1' }) as any;
      setConfig.run('retention.days', String(retentionDays));
    }
    res.json({ status: 'ok', maxSpans: getMaxSpans(), retentionDays: getRetentionDays() });
  });

  // ── Session HTML report ───────────────────────────────────────────────────
  app.get('/api/sessions/:traceId/report', (req, res) => {
    const { traceId } = req.params;
    const session = db.prepare('SELECT * FROM sessions WHERE traceId = ?').get(traceId) as
      { traceId: string; name: string; createdAt: string } | undefined;
    if (!session) return res.status(404).json({ error: 'Session not found' }) as any;

    const spans   = db.prepare('SELECT * FROM spans WHERE traceId = ? ORDER BY startNano ASC').all(traceId) as SpanRecord[];
    const alerts  = db.prepare("SELECT * FROM alerts WHERE traceId = ? ORDER BY id DESC").all(traceId) as any[];

    const threatCounts = { high: 0, medium: 0, low: 0 };
    spans.forEach(s => { if (s.severity in threatCounts) (threatCounts as any)[s.severity]++; });

    let totalTokensIn = 0;
    let totalTokensOut = 0;
    const harnessSet = new Set<string>();
    spans.forEach(s => {
      harnessSet.add(s.harness);
      try {
        const a = JSON.parse(s.attributes);
        totalTokensIn  += Number(a['gen_ai.usage.input_tokens']  ?? a['llm.usage.input_tokens']  ?? 0);
        totalTokensOut += Number(a['gen_ai.usage.output_tokens'] ?? a['llm.usage.output_tokens'] ?? 0);
      } catch {}
    });

    const severityColor = (s: string) =>
      s === 'high' ? '#ef4444' : s === 'medium' ? '#f97316' : s === 'low' ? '#eab308' : '#22c55e';
    const severityBg   = (s: string) =>
      s === 'high' ? '#450a0a' : s === 'medium' ? '#431407' : s === 'low' ? '#422006' : '#052e16';

    const spansRows = spans.map(s => {
      let attrs: Record<string, any> = {};
      try { attrs = JSON.parse(s.attributes); } catch {}
      const dur = (() => {
        try { return `${Math.round(Number((BigInt(s.endNano) - BigInt(s.startNano)) / 1_000_000n))}ms`; }
        catch { return '—'; }
      })();
      const toolName = attrs['gen_ai.tool.name'] ?? attrs['tool.name'] ?? '';
      const rule     = attrs['claudesec.threat.rule'] ?? '';
      return `
        <tr style="border-bottom:1px solid #1e293b; ${s.severity !== 'none' ? `background:${severityBg(s.severity)}` : ''}">
          <td style="padding:6px 10px; font-family:monospace; font-size:11px; color:#94a3b8">${s.spanId.slice(0, 8)}</td>
          <td style="padding:6px 10px; font-size:12px; color:#e2e8f0">${s.name.replace(/</g, '&lt;')}</td>
          <td style="padding:6px 10px; font-size:11px">
            <span style="background:${severityBg(s.severity)};color:${severityColor(s.severity)};padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold">
              ${s.severity.toUpperCase()}
            </span>
          </td>
          <td style="padding:6px 10px; font-family:monospace; font-size:11px; color:#64748b">${toolName}</td>
          <td style="padding:6px 10px; font-family:monospace; font-size:11px; color:#64748b">${dur}</td>
          <td style="padding:6px 10px; font-size:11px; color:#ef4444">${rule.replace(/</g, '&lt;')}</td>
        </tr>`;
    }).join('');

    const alertRows = alerts.map((a: any) => `
      <tr style="border-bottom:1px solid #1e293b">
        <td style="padding:6px 10px; font-size:11px; color:#94a3b8; font-family:monospace">${new Date(a.ts).toLocaleTimeString()}</td>
        <td style="padding:6px 10px">
          <span style="background:${severityBg(a.severity)};color:${severityColor(a.severity)};padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold">
            ${a.severity.toUpperCase()}
          </span>
        </td>
        <td style="padding:6px 10px; font-size:12px; color:#e2e8f0">${a.ruleLabel.replace(/</g, '&lt;')}</td>
        <td style="padding:6px 10px; font-family:monospace; font-size:11px; color:#64748b; word-break:break-all">${a.matchedText.replace(/</g, '&lt;')}</td>
        <td style="padding:6px 10px; font-size:11px; color:#64748b">${a.spanName.replace(/</g, '&lt;')}</td>
      </tr>`).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClaudeSec Report — ${session.name.replace(/</g, '&lt;')}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;padding:32px;line-height:1.5}
  h1{font-size:1.5rem;font-weight:800;margin-bottom:.25rem}
  h2{font-size:1rem;font-weight:700;margin:24px 0 12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;font-size:.75rem}
  .meta{color:#64748b;font-size:.8rem;margin-bottom:24px}
  .cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;min-width:130px}
  .card-val{font-size:1.6rem;font-weight:800;font-family:monospace}
  .card-label{font-size:.65rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
  table{width:100%;border-collapse:collapse;font-size:12px}
  thead tr{background:#1e293b;color:#64748b;font-size:.65rem;text-transform:uppercase;letter-spacing:.05em}
  th{padding:8px 10px;text-align:left;font-weight:600}
  tbody tr:hover{background:#1e293b44}
  .table-wrap{background:#0f172a;border:1px solid #1e293b;border-radius:10px;overflow:hidden;margin-bottom:24px}
  .badge{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold}
  .footer{margin-top:32px;color:#334155;font-size:.7rem;text-align:center}
  .harness-list{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px}
  .harness-badge{background:#1e293b;border:1px solid #334155;padding:4px 10px;border-radius:999px;font-size:.7rem;color:#94a3b8}
</style>
</head>
<body>
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <div style="width:36px;height:36px;background:#1d4ed822;border-radius:8px;display:flex;align-items:center;justify-content:center">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  </div>
  <div>
    <h1>ClaudeSec Session Report</h1>
    <p class="meta" style="margin:0">${session.name.replace(/</g, '&lt;')} · ${new Date(session.createdAt).toLocaleString()}</p>
  </div>
</div>

<div class="harness-list">
  ${[...harnessSet].map(h => `<span class="harness-badge">${h}</span>`).join('')}
</div>

<div class="cards">
  <div class="card"><div class="card-val" style="color:#e2e8f0">${spans.length}</div><div class="card-label">Total Spans</div></div>
  <div class="card"><div class="card-val" style="color:#ef4444">${threatCounts.high}</div><div class="card-label">HIGH Threats</div></div>
  <div class="card"><div class="card-val" style="color:#f97316">${threatCounts.medium}</div><div class="card-label">MEDIUM Threats</div></div>
  <div class="card"><div class="card-val" style="color:#eab308">${threatCounts.low}</div><div class="card-label">LOW Threats</div></div>
  <div class="card"><div class="card-val" style="color:#3b82f6">${totalTokensIn.toLocaleString()}</div><div class="card-label">Input Tokens</div></div>
  <div class="card"><div class="card-val" style="color:#a855f7">${totalTokensOut.toLocaleString()}</div><div class="card-label">Output Tokens</div></div>
</div>

${alerts.length > 0 ? `
<h2>Security Alerts (${alerts.length})</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Matched Text</th><th>Span</th></tr></thead>
<tbody>${alertRows}</tbody>
</table>
</div>` : ''}

<h2>Spans (${spans.length})</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Span ID</th><th>Name</th><th>Severity</th><th>Tool</th><th>Duration</th><th>Threat Rule</th></tr></thead>
<tbody>${spansRows}</tbody>
</table>
</div>

<div class="footer">
  Generated by <strong>ClaudeSec</strong> v1.0.0 &nbsp;·&nbsp;
  <a href="https://github.com/aanjaneyasinghdhoni/ClaudeSec" style="color:#3b82f6;text-decoration:none">github.com/aanjaneyasinghdhoni/ClaudeSec</a>
  &nbsp;·&nbsp; ${new Date().toUTCString()}
</div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${traceId.slice(0, 8)}-${Date.now()}.html"`);
    res.send(html);
  });

  // ── Health check ────────────────────────────────────────────────────────
  app.get('/api/health', (_req, res) => {
    const spansTotal    = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    const threatsTotal  = (db.prepare("SELECT COUNT(*) as c FROM spans WHERE severity != 'none'").get() as any).c as number;
    const sessionsTotal = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c as number;
    const alertsTotal   = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c as number;
    let dbSizeBytes = 0;
    try { dbSizeBytes = fs.statSync('spans.db').size; } catch {}
    res.json({
      status:      'ok',
      version:     '1.0.0',
      uptimeMs:    Date.now() - SERVER_START_MS,
      spansTotal,
      threatsTotal,
      sessionsTotal,
      alertsTotal,
      dbSizeBytes,
      webhookConfigured: !!getWebhookUrl(),
      webhookThreshold:  getWebhookThreshold(),
      retention: {
        maxSpans:      getMaxSpans(),
        retentionDays: getRetentionDays(),
      },
    });
  });

  // ── Prometheus metrics ───────────────────────────────────────────────────
  app.get('/metrics', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];

    // spans_total by harness
    const spansPerHarness = new Map<string, number>();
    const threatsPerHarnessSev = new Map<string, number>();
    const tokensIn  = new Map<string, number>();
    const tokensOut = new Map<string, number>();

    for (const span of allSpans) {
      spansPerHarness.set(span.harness, (spansPerHarness.get(span.harness) ?? 0) + 1);
      if (span.severity !== 'none') {
        const k = `${span.harness}::${span.severity}`;
        threatsPerHarnessSev.set(k, (threatsPerHarnessSev.get(k) ?? 0) + 1);
      }
      try {
        const attrs = JSON.parse(span.attributes);
        const ti = Number(attrs['gen_ai.usage.input_tokens']  ?? attrs['llm.usage.input_tokens']  ?? 0);
        const to = Number(attrs['gen_ai.usage.output_tokens'] ?? attrs['llm.usage.output_tokens'] ?? 0);
        if (ti) tokensIn.set(span.harness,  (tokensIn.get(span.harness)  ?? 0) + ti);
        if (to) tokensOut.set(span.harness, (tokensOut.get(span.harness) ?? 0) + to);
      } catch {}
    }

    const sessionsTotal = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c as number;
    const alertsTotal   = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c as number;
    const uptimeSec     = (Date.now() - SERVER_START_MS) / 1000;

    const lines: string[] = [
      '# HELP claudesec_spans_total Total spans recorded',
      '# TYPE claudesec_spans_total counter',
      ...[...spansPerHarness.entries()].map(([h, c]) => `claudesec_spans_total{harness="${h}"} ${c}`),

      '# HELP claudesec_threats_total Total threat detections',
      '# TYPE claudesec_threats_total counter',
      ...[...threatsPerHarnessSev.entries()].map(([k, c]) => {
        const [h, sev] = k.split('::');
        return `claudesec_threats_total{harness="${h}",severity="${sev}"} ${c}`;
      }),

      '# HELP claudesec_tokens_in_total Total input tokens processed',
      '# TYPE claudesec_tokens_in_total counter',
      ...[...tokensIn.entries()].map(([h, c]) => `claudesec_tokens_in_total{harness="${h}"} ${c}`),

      '# HELP claudesec_tokens_out_total Total output tokens processed',
      '# TYPE claudesec_tokens_out_total counter',
      ...[...tokensOut.entries()].map(([h, c]) => `claudesec_tokens_out_total{harness="${h}"} ${c}`),

      '# HELP claudesec_sessions_total Total sessions recorded',
      '# TYPE claudesec_sessions_total gauge',
      `claudesec_sessions_total ${sessionsTotal}`,

      '# HELP claudesec_alerts_total Total security alerts',
      '# TYPE claudesec_alerts_total gauge',
      `claudesec_alerts_total ${alertsTotal}`,

      '# HELP claudesec_uptime_seconds Server uptime in seconds',
      '# TYPE claudesec_uptime_seconds gauge',
      `claudesec_uptime_seconds ${uptimeSec.toFixed(1)}`,
    ];

    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(lines.join('\n') + '\n');
  });

  // ── Webhook config ───────────────────────────────────────────────────────
  app.get('/api/webhook', (_req, res) => {
    const url       = getWebhookUrl();
    const threshold = getWebhookThreshold();
    res.json({
      configured:  !!url,
      // Never expose full URL — only show redacted form for UI display
      urlPreview:  url ? url.replace(/\/[^/]{8,}$/, '/***') : null,
      threshold,
      envOverride: !!process.env.CLAUDESEC_WEBHOOK_URL,
    });
  });

  app.post('/api/webhook', (req, res) => {
    if (process.env.CLAUDESEC_WEBHOOK_URL) {
      return res.status(409).json({ error: 'CLAUDESEC_WEBHOOK_URL env var is set — remove it to manage via API' }) as any;
    }
    const { url, threshold } = req.body as { url?: string; threshold?: string };
    if (!url?.trim()) return res.status(400).json({ error: 'url is required' }) as any;
    try { new URL(url); } catch {
      return res.status(400).json({ error: 'invalid URL' }) as any;
    }
    setConfig.run('webhook.url', url.trim());
    if (threshold && ['low', 'medium', 'high'].includes(threshold)) {
      setConfig.run('webhook.threshold', threshold);
    }
    res.json({ status: 'ok', urlPreview: url.replace(/\/[^/]{8,}$/, '/***'), threshold: getWebhookThreshold() });
  });

  app.delete('/api/webhook', (_req, res) => {
    if (process.env.CLAUDESEC_WEBHOOK_URL) {
      return res.status(409).json({ error: 'CLAUDESEC_WEBHOOK_URL env var is set — unset it instead' }) as any;
    }
    delConfig.run('webhook.url');
    res.json({ status: 'ok' });
  });

  app.post('/api/webhook/test', async (_req, res) => {
    const url = getWebhookUrl();
    if (!url) return res.status(404).json({ error: 'No webhook URL configured' }) as any;
    await fireWebhook({
      ruleLabel:   'Webhook test',
      severity:    'high',
      harness:     'claudesec',
      spanName:    'test',
      matchedText: 'This is a test alert from ClaudeSec',
      traceId:     'test-' + Date.now().toString(16),
    });
    res.json({ status: 'ok', url: url.replace(/\/[^/]{8,}$/, '/***') });
  });

  // ── Token cost estimation ─────────────────────────────────────────────────
  app.get('/api/costs', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];
    const sessionRows = db.prepare('SELECT traceId, name FROM sessions').all() as { traceId: string; name: string }[];
    const sessionNames = new Map(sessionRows.map(s => [s.traceId, s.name]));

    // Aggregate by traceId × model
    interface CostRow {
      traceId:    string;
      sessionName: string;
      harness:    string;
      model:      string;
      modelLabel: string;
      tokensIn:   number;
      tokensOut:  number;
      costUsd:    number;
      knownPrice: boolean;
    }

    const key = (t: string, m: string) => `${t}::${m}`;
    const rowMap = new Map<string, CostRow>();
    let totalCostUsd = 0;
    let totalTokensIn = 0;
    let totalTokensOut = 0;

    for (const span of allSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const model = String(
          attrs['gen_ai.request.model'] ??
          attrs['gen_ai.response.model'] ??
          attrs['llm.request.model']    ?? ''
        ).toLowerCase().trim();
        const ti = Number(attrs['gen_ai.usage.input_tokens']  ?? attrs['llm.usage.input_tokens']  ?? 0);
        const to = Number(attrs['gen_ai.usage.output_tokens'] ?? attrs['llm.usage.output_tokens'] ?? 0);
        if (!model && ti === 0 && to === 0) continue;

        const k = key(span.traceId, model || 'unknown');
        if (!rowMap.has(k)) {
          const pricing = model ? lookupPricing(model) : null;
          rowMap.set(k, {
            traceId:    span.traceId,
            sessionName: sessionNames.get(span.traceId) ?? span.traceId.slice(0, 8),
            harness:    span.harness,
            model:      model || 'unknown',
            modelLabel: pricing?.label ?? (model || 'Unknown Model'),
            tokensIn:   0, tokensOut: 0, costUsd: 0,
            knownPrice: !!pricing,
          });
        }
        const row = rowMap.get(k)!;
        row.tokensIn  += ti;
        row.tokensOut += to;
        totalTokensIn  += ti;
        totalTokensOut += to;

        if (model) {
          const pricing = lookupPricing(model);
          if (pricing) {
            row.costUsd += (ti / 1_000_000) * pricing.inputPer1M + (to / 1_000_000) * pricing.outputPer1M;
          }
        }
      } catch {}
    }

    const rows = [...rowMap.values()].sort((a, b) => b.costUsd - a.costUsd);
    rows.forEach(r => { totalCostUsd += r.costUsd; });

    // Per-model summary (across all sessions)
    const modelSummary = new Map<string, { label: string; tokensIn: number; tokensOut: number; costUsd: number; knownPrice: boolean }>();
    for (const row of rows) {
      if (!modelSummary.has(row.model)) {
        modelSummary.set(row.model, { label: row.modelLabel, tokensIn: 0, tokensOut: 0, costUsd: 0, knownPrice: row.knownPrice });
      }
      const ms = modelSummary.get(row.model)!;
      ms.tokensIn  += row.tokensIn;
      ms.tokensOut += row.tokensOut;
      ms.costUsd   += row.costUsd;
    }

    res.json({
      sessions:      rows.map(r => ({ ...r, costUsd: Math.round(r.costUsd * 1_000_000) / 1_000_000 })),
      models:        [...modelSummary.entries()].map(([model, s]) => ({ model, ...s, costUsd: Math.round(s.costUsd * 1_000_000) / 1_000_000 })).sort((a, b) => b.costUsd - a.costUsd),
      totalCostUsd:  Math.round(totalCostUsd  * 1_000_000) / 1_000_000,
      totalTokensIn,
      totalTokensOut,
      pricingTable:  Object.entries(MODEL_PRICING).map(([model, p]) => ({ model, ...p })),
    });
  });

  // ── Dev / prod static ────────────────────────────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => res.sendFile(path.join(distPath, 'index.html')));
  }

  const PORT = Number(process.env.PORT ?? 3000);
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  ClaudeSec  http://localhost:${PORT}`);
    console.log(`  OTLP       http://localhost:${PORT}/v1/traces`);
    console.log(`  Setup      npm run init\n`);
    const n = (getAllSpans.all() as SpanRecord[]).length;
    if (n > 0) console.log(`  Loaded ${n} spans from database.\n`);
  });
}

startServer();
