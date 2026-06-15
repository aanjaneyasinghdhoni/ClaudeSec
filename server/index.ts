import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
// User-supplied custom-rule patterns are compiled with RE2 (Google's
// linear-time regex engine) rather than the native RegExp, so an operator
// cannot inject a catastrophic-backtracking pattern (ReDoS / regex injection).
import RE2 from 're2';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath, pathToFileURL } from 'url';
import { createServer as createViteServer } from 'vite';
import { db, DB_PATH, backupDatabase, checkpointAndClose } from './db.js';
import { scanAgentProcesses, type AgentProcess } from './processScan.js';
import { registerProcessRoutes } from './routes/processes.js';
import { registerBookmarkRoutes } from './routes/bookmarks.js';
import { registerSuppressionRoutes } from './routes/suppressions.js';
import { registerSpanMetaRoutes } from './routes/spanMeta.js';
import { registerDbStatsRoutes } from './routes/dbStats.js';
import { registerCostRoutes, dedupedTokenTotals } from './routes/costs.js';
import { registerHarnessRoutes } from './routes/harnesses.js';
import { registerFileAccessRoutes } from './routes/fileAccess.js';
import { registerCommandAuditRoutes } from './routes/commandAudit.js';
import { registerSearchRoutes } from './routes/search.js';
import { registerSessionRoutes } from './routes/sessions.js';
import { registerAlertRoutes } from './routes/alerts.js';
import { registerRuleRoutes } from './routes/rules.js';
import { registerProtectedPathRoutes } from './routes/protectedPaths.js';
import { registerThresholdRuleRoutes } from './routes/thresholdRules.js';
import { registerHoneytokenRoutes } from './routes/honeytokens.js';
import { registerExportRoutes } from './routes/exportData.js';
import { registerMcpScanRoutes } from './routes/mcpScan.js';
import { registerJudgeRoutes } from './routes/judge.js';
import { registerScrubRoutes } from './routes/scrub.js';
import { registerHeatmapRoutes } from './routes/heatmap.js';
import { registerOrchestrationRoutes } from './routes/orchestration.js';
import { registerLiveActivityRoutes } from './routes/liveActivity.js';
import { registerWebhookRoutes } from './routes/webhook.js';
import { registerEnforceRoutes } from './routes/enforce.js';
import { registerAuditLogRoutes } from './routes/auditLog.js';
import { registerAuditVerifyRoutes } from './routes/auditVerify.js';
import { registerRuleOverrideRoutes } from './routes/ruleOverrides.js';
import { makeAuditLogger } from './auditLog.js';
import {
  ENFORCE_LOG_MAX,
  appendEnforceLog as persistEnforceLog,
  readEnforceLog as readPersistedEnforceLog,
  enforceLogCount as persistedEnforceLogCount,
  enforceLogRecentCount,
} from './enforceLogStore.js';
import type { CustomRule, ProtectedPath, HealthBreakdown } from './routes/context.js';
import { detectHarness, HARNESSES } from '../src/harnesses.js';
import { loadScrubOptions, scrubAttributes, scrubText, type ScrubOptions } from './scrub.js';
import { resolveRepo, backfillRepos } from './repoIdentity.js';
import { startTranscriptWatcher, defaultRoots, type WatcherEvent, type IngestInput, type OffsetStore } from './transcriptWatcher.js';
import { SEVERITY_RULES, CATASTROPHIC_DETECTION_LABELS } from './detection.js';
import { buildEnforcementSnapshot } from './enforcementSnapshot.js';
import {
  normalizeAddr,
  isLoopbackAddr,
  isPublicAddress,
  assertSafeFetchUrl,
  SsrfBlockedError,
} from './ssrf.js';
import { getJudgeConfig } from './llmJudge.js';
import { seedDemoData } from './demoData.js';
import type { Severity } from '../src/shared/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ───────────────────────────────────────────────────────────────────────────
// Entry-point guard
// ───────────────────────────────────────────────────────────────────────────
// Importing this module (a test, a build tool, the CLI) must be side-effect
// free: NO HTTP listener, NO config-file mirror writes. Only when this file is
// the process entry point (the live service runs `tsx server/index.ts`, so
// argv[1] resolves to THIS file) do we autostart the server and write the boot-
// time config mirrors. CLAUDESEC_NO_AUTOSTART=1 is an explicit escape hatch a
// test can set to force import-only behaviour regardless of how it was invoked.
//
// Why the URL compare: under tsx/ESM there is no `require.main`. Comparing
// import.meta.url to the resolved argv[1] is the portable ESM equivalent — true
// for `tsx server/index.ts` (launchd, `pnpm dev`, `pnpm start`), false on import.
const IS_ENTRY_POINT = (() => {
  if (process.env.CLAUDESEC_NO_AUTOSTART === '1') return false;
  try {
    const argvEntry = process.argv[1];
    if (!argvEntry) return false;
    return import.meta.url === pathToFileURL(argvEntry).href;
  } catch {
    return false;
  }
})();

// ═══════════════════════════════════════════════════════════════════════════
// Loopback-exempt auth helpers
// ═══════════════════════════════════════════════════════════════════════════
// These back the API/MCP/OTLP auth gate, the Socket.io handshake check, and the
// startup bind guard.  Factored into one place so all three agree on what
// "loopback" means and how the token is compared.

/** Constant-time token comparison with a length guard (timingSafeEqual throws
 *  on unequal lengths, and the mismatched-length case is the attacker path). */
function tokenMatches(presented: string | undefined | null, expected: string): boolean {
  if (!expected) return false;            // fail closed: no server token configured
  if (!presented) return false;
  const a = Buffer.from(String(presented));
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * CLAUDESEC_TRUST_LOCAL opt-in trust mode.
 *
 * When CLAUDESEC_TRUST_LOCAL=1, all three auth checkpoints (HTTP auth gate,
 * Socket.io handshake, and the startup bind guard) treat every incoming
 * connection as trusted, regardless of the source IP.
 *
 * DEFAULT: unset / OFF — original loopback-exempt behavior is preserved.
 *
 * SECURITY: Only enable when the server is guaranteed not to be reachable from
 * untrusted networks.  The docker-compose.yml sets this and restricts the host
 * port to 127.0.0.1 so the container is only reachable from the local machine.
 * If you change the host binding away from 127.0.0.1, remove TRUST_LOCAL and
 * set CLAUDESEC_TOKEN instead.
 */
function trustLocalEnabled(): boolean {
  return process.env.CLAUDESEC_TRUST_LOCAL === '1';
}

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
  repo: string;
}

const insertSpan = db.prepare(`
  INSERT OR IGNORE INTO spans
    (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo)
  VALUES
    (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness, @attributes, @startNano, @endNano, @repo)
`);

const upsertSession = db.prepare(
  `INSERT OR IGNORE INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)`
);

const deleteAllSpans    = db.prepare(`DELETE FROM spans`);
const deleteAllSessions = db.prepare(`DELETE FROM sessions`);
const getAllSpans        = db.prepare(`SELECT * FROM spans`);

// How many of the most-recent spans the live graph renders. Older spans are NOT
// deleted — they remain fully available via Search, Sessions, and history. This
// only bounds how much the graph loads, relays out, and tracks as React node
// state, which is the dominant cost as the spans table grows. Override with
// CLAUDESEC_GRAPH_LIMIT (any positive integer).
const GRAPH_LIMIT = (() => {
  const n = parseInt(String(process.env.CLAUDESEC_GRAPH_LIMIT ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : 2000;
})();

// Select the most-recent N spans (by start time) but return them in ascending
// order, so downstream node ordering matches a full-table read of the window.
const getRecentSpans = db.prepare(`
  SELECT * FROM (
    SELECT * FROM spans ORDER BY startNano DESC LIMIT ?
  ) ORDER BY startNano ASC
`);

// Total span count — used only to decide whether the graph window is truncating.
const countSpans = db.prepare(`SELECT COUNT(*) AS c FROM spans`);

const getWatchOffset = db.prepare(`SELECT offset FROM watch_offsets WHERE path = ?`);
const setWatchOffset = db.prepare(`
  INSERT INTO watch_offsets (path, offset, updatedAt) VALUES (?, ?, ?)
  ON CONFLICT(path) DO UPDATE SET offset = excluded.offset, updatedAt = excluded.updatedAt
`);
const updateSpanEnd = db.prepare(`UPDATE spans SET endNano = ? WHERE spanId = ?`);

/**
 * Deduplication window: if the same rule fires in the same session within
 * DEDUP_WINDOW_MS, increment the existing alert's count rather than inserting
 * a new row.  Returns the affected alert id.
 */
const DEDUP_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function insertOrDedupeAlert(alert: {
  ts: string; ruleLabel: string; severity: string; spanId: string;
  traceId: string; harness: string; spanName: string; matchedText: string;
}): number | bigint {
  const fingerprint = `${alert.ruleLabel}::${alert.traceId}::${alert.harness}`;
  const windowStart = new Date(Date.now() - DEDUP_WINDOW_MS).toISOString();

  const existing = db.prepare(
    `SELECT id FROM alerts WHERE fingerprint = ? AND ts > ? AND dismissed = 0 LIMIT 1`
  ).get(fingerprint, windowStart) as { id: number } | undefined;

  if (existing) {
    db.prepare(`UPDATE alerts SET count = count + 1, ts = ?, spanId = ? WHERE id = ?`)
      .run(alert.ts, alert.spanId, existing.id);
    return existing.id;
  }

  const result = db.prepare(`
    INSERT INTO alerts (ts, ruleLabel, severity, spanId, traceId, harness, spanName, matchedText, fingerprint, count)
    VALUES (@ts, @ruleLabel, @severity, @spanId, @traceId, @harness, @spanName, @matchedText, @fingerprint, 1)
  `).run({ ...alert, fingerprint });
  return result.lastInsertRowid;
}

const deleteAllAlerts = db.prepare(`DELETE FROM alerts`);

const insertThresholdRule = db.prepare(`
  INSERT INTO threshold_rules (name, metric, operator, value, window_min, enabled, createdAt)
  VALUES (@name, @metric, @operator, @value, @window_min, @enabled, @createdAt)
`);
const deleteThresholdRule  = db.prepare(`DELETE FROM threshold_rules WHERE id = ?`);
const updateThresholdRule  = db.prepare(`UPDATE threshold_rules SET enabled = ? WHERE id = ?`);
const getAllThresholdRules  = db.prepare(`SELECT * FROM threshold_rules ORDER BY id ASC`);

// Dedup cache: traceId+ruleId → last fired ts
const thresholdFiredCache = new Map<string, number>();

type ThresholdMetric = 'tokens_in' | 'tokens_out' | 'threat_count' | 'span_count' | 'high_threat_count';

function evaluateThresholdRules(traceId: string, harness: string): void {
  const rules = getAllThresholdRules.all() as {
    id: number; name: string; metric: ThresholdMetric;
    operator: string; value: number; window_min: number; enabled: number;
  }[];
  if (rules.length === 0) return;

  const windowMs = (r: typeof rules[0]) => r.window_min * 60 * 1000;
  const cutoffNano = (r: typeof rules[0]) => {
    const ms = Date.now() - windowMs(r);
    return String(BigInt(ms) * 1_000_000n);
  };

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const cacheKey = `${traceId}::${rule.id}`;
    const lastFired = thresholdFiredCache.get(cacheKey) ?? 0;
    if (Date.now() - lastFired < windowMs(rule)) continue; // dedup within window

    const cutoff = cutoffNano(rule);
    let actual = 0;
    const spans = db.prepare(`SELECT attributes, severity FROM spans WHERE traceId = ? AND startNano > ?`).all(traceId, cutoff) as { attributes: string; severity: string }[];

    switch (rule.metric) {
      case 'span_count':       actual = spans.length; break;
      case 'threat_count':     actual = spans.filter(s => s.severity !== 'none').length; break;
      case 'high_threat_count': actual = spans.filter(s => s.severity === 'high').length; break;
      case 'tokens_in':
      case 'tokens_out': {
        const key = rule.metric === 'tokens_in' ? 'gen_ai.usage.input_tokens' : 'gen_ai.usage.output_tokens';
        const alt = rule.metric === 'tokens_in' ? 'llm.usage.input_tokens' : 'llm.usage.output_tokens';
        for (const s of spans) {
          try { const a = JSON.parse(s.attributes); actual += Number(a[key] ?? a[alt] ?? 0); } catch {}
        }
        break;
      }
    }

    const exceeded = rule.operator === '>' ? actual > rule.value
      : rule.operator === '>=' ? actual >= rule.value
      : rule.operator === '<'  ? actual < rule.value
      : rule.operator === '<=' ? actual <= rule.value
      : actual === rule.value;

    if (exceeded) {
      thresholdFiredCache.set(cacheKey, Date.now());
      const label = `Threshold: ${rule.name} (${rule.metric} ${rule.operator} ${rule.value})`;
      insertOrDedupeAlert({
        ts: new Date().toISOString(), ruleLabel: label, severity: 'medium',
        spanId: 'threshold', traceId, harness, spanName: 'threshold-check',
        matchedText: `actual=${actual}`,
      });
      fireWebhook({ ruleLabel: label, severity: 'medium', harness, spanName: 'threshold-check', matchedText: `actual=${actual}, threshold=${rule.operator}${rule.value}`, traceId }).catch(() => {});
    }
  }
}

// ---------------------------------------------------------------------------
// Annotations table — user investigation notes on spans
// ---------------------------------------------------------------------------

// Annotation read/write statements moved to server/routes/spanMeta.ts alongside
// their handlers. Only the bulk-delete (used by /api/reset) remains here.
const deleteAllAnnotations = db.prepare(`DELETE FROM annotations`);

// ---------------------------------------------------------------------------
// FTS5 full-text search — spans_fts mirrors spans(name, attributes)
// ---------------------------------------------------------------------------

// One-time backfill: index any spans that pre-date the trigger
{
  const indexed = new Set(
    (db.prepare('SELECT spanId FROM spans_fts').all() as { spanId: string }[]).map(r => r.spanId),
  );
  const toIndex = (db.prepare('SELECT spanId, name, attributes FROM spans').all() as
    { spanId: string; name: string; attributes: string }[])
    .filter(s => !indexed.has(s.spanId));
  if (toIndex.length > 0) {
    const ftsInsert = db.prepare('INSERT OR IGNORE INTO spans_fts(spanId, name, attributes) VALUES (?, ?, ?)');
    const tx = db.transaction(() => { for (const s of toIndex) ftsInsert.run(s.spanId, s.name, s.attributes); });
    tx();
  }
}

// ---------------------------------------------------------------------------
// Webhook delivery log — tracks every attempt with retry support
// ---------------------------------------------------------------------------

const insertDelivery = db.prepare(`
  INSERT INTO webhook_deliveries (ruleLabel, severity, urlPreview, status, createdAt)
  VALUES (@ruleLabel, @severity, @urlPreview, 'pending', @createdAt)
`);
const updateDelivery = db.prepare(`
  UPDATE webhook_deliveries
  SET status = ?, httpCode = ?, latencyMs = ?, error = ?, attempts = attempts + 1, lastAttemptAt = ?
  WHERE id = ?
`);

// Keep delivery log to last 500 rows
function pruneDeliveryLog() {
  const count = (db.prepare('SELECT COUNT(*) as c FROM webhook_deliveries').get() as any).c as number;
  if (count > 500) {
    db.prepare('DELETE FROM webhook_deliveries WHERE id IN (SELECT id FROM webhook_deliveries ORDER BY id ASC LIMIT ?)').run(count - 500);
  }
}

// ---------------------------------------------------------------------------
// Session health score
// ---------------------------------------------------------------------------

// Pure health formula — the SINGLE source of truth for session health scoring.
// Both the per-session endpoint (computeHealthScore → /api/sessions/:id/health,
// used by the CLI `report` command) and the session list (/api/sessions) call
// this so the two paths can never diverge again.
// `h` folds in the `critical` exfiltration tier (counted upstream as high), so a
// confirmed exfil is penalized at least as hard as a high — never as a free pass.
function healthFromCounts(h: number, m: number, l: number, alertCount: number): HealthBreakdown {
  const raw   = 100 - h * 15 - m * 8 - l * 3 - Math.min(alertCount * 10, 30);
  const score = Math.max(0, raw);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, threatHigh: h, threatMedium: m, threatLow: l, alertCount };
}

function computeHealthScore(traceId: string): HealthBreakdown {
  const sev = db.prepare(`
    SELECT
      SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS h,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS m,
      SUM(CASE WHEN severity = 'low'    THEN 1 ELSE 0 END) AS l
    FROM spans WHERE traceId = ?
  `).get(traceId) as { h: number; m: number; l: number };

  const alertCount = (db.prepare('SELECT COUNT(*) as c FROM alerts WHERE traceId = ?').get(traceId) as any).c as number;

  return healthFromCounts(sev?.h ?? 0, sev?.m ?? 0, sev?.l ?? 0, alertCount);
}

// ---------------------------------------------------------------------------
// Config table (webhook URL, thresholds, etc.)
// ---------------------------------------------------------------------------

const getConfig = db.prepare<[string], { value: string }>(`SELECT value FROM config WHERE key = ?`);
const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);
const delConfig = db.prepare(`DELETE FROM config WHERE key = ?`);

// ---------------------------------------------------------------------------
// Honeytokens — operator-planted canary strings that must never appear in
// legitimate span attributes.  Any match is an exfiltration signal and fires
// a dedicated HIGH-severity alert regardless of the scrubber's state.
// ---------------------------------------------------------------------------

function loadHoneytokens(): string[] {
  const fromDb = (getConfig.get('honeytokens')?.value ?? '')
    .split('\n').map(s => s.trim()).filter(Boolean);
  const fromEnv = (process.env.CLAUDESEC_HONEYTOKENS ?? '')
    .split(',').map(s => s.trim()).filter(Boolean);
  return [...new Set([...fromDb, ...fromEnv])];
}

function saveHoneytokens(tokens: string[]): void {
  const clean = [...new Set(tokens.map(t => t.trim()).filter(t => t.length >= 6))];
  setConfig.run('honeytokens', clean.join('\n'));
  scrubOptions = loadScrubOptions(clean);
}

// Scrub options are rebuilt whenever honeytokens change.  Default: enabled,
// with the current process's $HOME and OS username masked inline.
let scrubOptions: ScrubOptions = loadScrubOptions(loadHoneytokens());

// ---------------------------------------------------------------------------
// Suppressed-rule cache — short-lived so ingest doesn't round-trip SQLite per
// rule per span.  TTL is intentionally small so UI changes propagate fast.
// ---------------------------------------------------------------------------

let _suppressedCache: { keys: Set<string>; at: number } | null = null;
const SUPPRESSED_TTL_MS = 2_000;

function getSuppressedKeysCached(): Set<string> {
  const now = Date.now();
  if (_suppressedCache && now - _suppressedCache.at < SUPPRESSED_TTL_MS) {
    return _suppressedCache.keys;
  }
  const rows = db.prepare(
    `SELECT ruleKey FROM suppressions WHERE suppressUntil > ?`
  ).all(new Date().toISOString()) as { ruleKey: string }[];
  const keys = new Set(rows.map(r => r.ruleKey));
  _suppressedCache = { keys, at: now };
  return keys;
}

function invalidateSuppressedCache() { _suppressedCache = null; }

// ---------------------------------------------------------------------------
// Disabled-rule cache — operator-set per-rule enable/disable overrides.
// Same short-lived (~2s) cache shape as suppressions so ingest never round-
// trips SQLite per rule per span, and UI changes still propagate fast.
// The catastrophic-floor labels are dropped here defensively: even if a stale
// override row somehow existed, a catastrophic rule can never be silenced.
// ---------------------------------------------------------------------------

let _disabledRulesCache: { labels: Set<string>; at: number } | null = null;
const DISABLED_RULES_TTL_MS = 2_000;

function getDisabledRuleLabelsCached(): Set<string> {
  const now = Date.now();
  if (_disabledRulesCache && now - _disabledRulesCache.at < DISABLED_RULES_TTL_MS) {
    return _disabledRulesCache.labels;
  }
  const rows = db.prepare(
    `SELECT ruleLabel FROM rule_overrides WHERE enabled = 0`,
  ).all() as { ruleLabel: string }[];
  const labels = new Set(
    rows.map(r => r.ruleLabel).filter(l => !CATASTROPHIC_DETECTION_LABELS.has(l)),
  );
  _disabledRulesCache = { labels, at: now };
  return labels;
}

function invalidateDisabledRulesCache() { _disabledRulesCache = null; }

// ---------------------------------------------------------------------------
// Operator audit log writer
// ---------------------------------------------------------------------------
// A request is "local" (actor = 'local') when it comes from loopback or runs
// under CLAUDESEC_TRUST_LOCAL — exactly the cases the HTTP auth gate lets
// through without a token. Anything else reached the handler only by presenting
// a valid CLAUDESEC_TOKEN, so it's attributed to 'token'. detail is scrubbed
// inside the writer; sourceIp uses req.socket.remoteAddress (never the
// spoofable X-Forwarded-For), matching the auth gate's choice.
const auditLog = makeAuditLogger(
  () => scrubOptions,
  (req) => isLoopbackAddr(req.socket?.remoteAddress) || trustLocalEnabled(),
);

// ---------------------------------------------------------------------------
// Custom rules persistence
// ---------------------------------------------------------------------------

const REPO_ROOT = path.resolve(__dirname, '..');
const RULES_FILE = path.join(REPO_ROOT, 'rules.json');
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
// Protected paths (user-defined, always-on block list)
//
// A protected path is a per-user floor: any agent tool call that targets it is
// BLOCKED before it runs, in EVERY mode (a user-controlled mirror of the hook's
// hardcoded catastrophic floor). The list is persisted server-side in
// protected-paths.json (same mechanism as customRules) and mirrored to a file
// the PreToolUse hook reads fresh per invocation, so changes take effect LIVE
// with no Claude Code restart.
//
// SAFETY: the hook fails OPEN if the mirror file is missing/unreadable, so a
// failed write here can never block the user.
// ---------------------------------------------------------------------------

const PROTECTED_PATHS_FILE = path.join(REPO_ROOT, 'protected-paths.json');
let protectedPaths: ProtectedPath[] = [];

function loadProtectedPaths() {
  try {
    if (fs.existsSync(PROTECTED_PATHS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(PROTECTED_PATHS_FILE, 'utf-8'));
      protectedPaths = Array.isArray(raw) ? raw : [];
    }
  } catch { protectedPaths = []; }
}

function saveProtectedPaths() {
  // Atomic write (temp + rename) so a crash mid-write can never leave a
  // truncated/empty file that silently wipes the user's protected paths.
  // Mode 0o600 — this list is private to the user. Mirrors the artifact writer.
  const tmp = `${PROTECTED_PATHS_FILE}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify(protectedPaths, null, 2), { mode: 0o600 });
  fs.chmodSync(tmp, 0o600); // mode only applies on create; enforce on a pre-existing tmp too
  fs.renameSync(tmp, PROTECTED_PATHS_FILE);
  fs.chmodSync(PROTECTED_PATHS_FILE, 0o600);
}

/**
 * Resolve ~/.claudesec/hooks — where the installed hook + its artifacts live.
 *
 * Intentionally duplicates cli/installHook.ts installPaths(): the server must
 * NOT import from cli/ (keeps the runtime dependency graph clean), so the path
 * resolution is mirrored here by hand. Honors CLAUDESEC_HOME exactly as the
 * installer does. Keep these two in sync if the layout ever changes.
 */
function hookArtifactsDir(): string {
  const homeDir = process.env.CLAUDESEC_HOME ?? path.join(os.homedir(), '.claudesec');
  return path.join(homeDir, 'hooks');
}

/**
 * Mirror the protected-paths list to <hooksDir>/protected-paths.json so the
 * PreToolUse hook can enforce it. Written atomically (temp + rename) with 0600.
 * Fail-safe: if the hooks dir doesn't exist (hook not installed) we skip the
 * write without error — never throws, so a mirror failure can't gate anything.
 * File shape: [{ "path": "<literal path>", "label": "<label>" }].
 */
function writeProtectedPathsArtifact(): void {
  try {
    const dir = hookArtifactsDir();
    if (!fs.existsSync(dir)) {
      // Hook not installed → nothing to mirror to. If the user has configured
      // protected paths but the hook isn't installed, those paths will NOT block
      // anything — warn loudly so the silent gap is visible (directly addresses
      // the silent-breakage fear). Otherwise (no paths) stay quiet.
      if (protectedPaths.length > 0) {
        console.warn(
          `[protected-paths] ${protectedPaths.length} protected path(s) are configured but the ` +
          `PreToolUse hook is NOT installed (${dir} missing), so they will NOT block any tool ` +
          `call. Run \`claudesec install-hook\` to activate them.`,
        );
      }
      return;
    }
    const target = path.join(dir, 'protected-paths.json');
    const payload = protectedPaths.map(p => ({ path: p.path, label: p.label }));
    const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
    fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(tmp, 0o600); // mode only applies on create; enforce on a pre-existing tmp too
    fs.renameSync(tmp, target);
    fs.chmodSync(target, 0o600);
  } catch (err) {
    console.warn('[protected-paths] could not write protected-paths.json:', (err as Error)?.message);
  }
}

loadProtectedPaths();
// The startup mirror write now lives in the guarded boot sequence
// (mirrorConfigOnBoot, called only when this file is the entry point) so that
// merely importing the module never touches the user's installed hook config.

// ---------------------------------------------------------------------------
// Enforcement snapshot (built-in rules + user custom rules)
//
// The PreToolUse hook and the MCP-proxy sibling (enforceEval.ts) block on
// rules-enforcement.json — a flat snapshot where high/critical rules carry
// action:'block'. The install-time generator writes only the BUILT-IN rules; it
// has no knowledge of the user's custom rules (those live server-side). So the
// running server regenerates the FULL snapshot (built-ins + custom) and mirrors
// it to both locations the readers use:
//   • <hooksDir>/rules-enforcement.json  — the installed Claude Code hook
//   • <repo>/rules-enforcement.json       — enforceEval / in-repo hook fallback
// This is what makes a high/critical CUSTOM rule actually block in enforce mode,
// instead of only being detected. Always rebuilt from scratch (never appended),
// so the built-in floor can never be clobbered.
//
// SAFETY: fail-open. A failed write logs a warning and returns; the hook treats
// a missing/unreadable snapshot as "no block rules", so a write failure can only
// ever UNDER-block, never wrongly block.
// ---------------------------------------------------------------------------

/** Atomically write `text` to `target` with 0600. Throws on failure (caller guards). */
function atomicWrite0600(target: string, text: string): void {
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.chmodSync(tmp, 0o600); // mode only applies on create; enforce on a pre-existing tmp too
  fs.renameSync(tmp, target);
  fs.chmodSync(target, 0o600);
}

/**
 * Regenerate rules-enforcement.json (built-ins + custom) and mirror it to every
 * location a reader consumes. Never throws — each destination is guarded so one
 * unwritable path can't gate the others or the request that triggered the write.
 */
function writeEnforcementSnapshot(): void {
  const snapshot = JSON.stringify(buildEnforcementSnapshot(customRules), null, 2) + '\n';

  // 1. The repo-root artifact — read by enforceEval (MCP proxy) and the in-repo
  //    hook fallback. Always writable (it is the generator's output location).
  try {
    atomicWrite0600(path.join(REPO_ROOT, 'rules-enforcement.json'), snapshot);
  } catch (err) {
    console.warn('[enforce-rules] could not write repo-root snapshot:', (err as Error)?.message);
  }

  // 2. The installed hook's copy — only if the hook is installed. Mirrors the
  //    protected-paths warn-if-missing behaviour so a custom block rule that
  //    silently won't fire (no hook) is visible.
  try {
    const dir = hookArtifactsDir();
    if (!fs.existsSync(dir)) {
      const blockCustom = customRules.filter(r => r.severity === 'high' || r.severity === 'critical').length;
      if (blockCustom > 0) {
        console.warn(
          `[enforce-rules] ${blockCustom} high/critical custom rule(s) are configured but the ` +
          `PreToolUse hook is NOT installed (${dir} missing), so they will NOT block any tool ` +
          `call. Run \`claudesec install-hook\` to activate enforce-mode blocking.`,
        );
      }
      return;
    }
    atomicWrite0600(path.join(dir, 'rules-enforcement.json'), snapshot);
  } catch (err) {
    console.warn('[enforce-rules] could not write hook snapshot:', (err as Error)?.message);
  }
}

// The startup mirror write is deferred to the guarded boot sequence
// (mirrorConfigOnBoot) so importing this module is side-effect free.

// ---------------------------------------------------------------------------
// Enforcement config (server-controlled mode + per-rule action overrides)
//
// The PreToolUse hook (.claude/hooks/claudesec-enforce.cjs) reads the effective
// mode from a LOCAL FILE (enforce-config.json) — no per-call network. The
// server is the source of truth: mode + overrides live in the `config` SQLite
// table and are mirrored to that file whenever they change (and once at start).
//
// SAFETY: the hook fails OPEN / monitor-by-default if this file is missing or
// unreadable, so a write failure here NEVER blocks the user. We only ever write
// a strictly-validated 'monitor' | 'enforce' string.
// ---------------------------------------------------------------------------

type EnforceMode = 'monitor' | 'enforce';
// Per-rule action override: rule label → 'alert' | 'block'. Lets the operator
// promote/demote individual rules without rebuilding the snapshot.
type EnforceAction = 'alert' | 'block';

const ENFORCE_CONFIG_FILE =
  process.env.CLAUDESEC_ENFORCE_CONFIG
    ? path.resolve(process.env.CLAUDESEC_ENFORCE_CONFIG)
    : path.join(REPO_ROOT, 'enforce-config.json');

function getEnforceMode(): EnforceMode {
  const v = getConfig.get('enforce.mode')?.value;
  return v === 'enforce' ? 'enforce' : 'monitor'; // default + sanitize
}

function getEnforceOverrides(): Record<string, EnforceAction> {
  try {
    const raw = getConfig.get('enforce.overrides')?.value;
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: Record<string, EnforceAction> = {};
    for (const [k, val] of Object.entries(parsed)) {
      if (val === 'alert' || val === 'block') out[k] = val;
    }
    return out;
  } catch {
    return {};
  }
}

// Mirror the effective config to enforce-config.json so the hook can read it.
// Written to BOTH locations the rules/protected-paths snapshots use:
//   • <repo>/enforce-config.json       — enforceEval / in-repo hook fallback
//   • <hooksDir>/enforce-config.json   — the INSTALLED Claude Code hook, which
//     resolves its config beside itself (~/.claudesec/hooks). Without this the
//     installed hook never sees the mode and silently stays on monitor.
// Best-effort: never throws (a failed write just leaves the hook on its prior
// file / env / monitor default — all fail-open).
function writeEnforceConfigFile(): void {
  const payload = JSON.stringify(
    { mode: getEnforceMode(), overrides: getEnforceOverrides(), updatedAt: new Date().toISOString() },
    null,
    2,
  ) + '\n';
  // 1. Repo-root copy (in-repo hook / enforceEval fallback). Harmless for tests:
  //    enforce-config.json is gitignored, and the in-repo hook is not the one a
  //    real session runs.
  try {
    fs.writeFileSync(ENFORCE_CONFIG_FILE, payload, 'utf8');
  } catch (err) {
    console.warn('[enforce] could not write enforce-config.json:', (err as Error)?.message);
  }
  // 2. Mirror beside the INSTALLED hook (the one real sessions run) — but ONLY when
  //    this server's own DB has an explicit enforce.mode row. A test or build tool
  //    that imports this module runs against a sandboxed, empty DB (no such row);
  //    it must NEVER overwrite the user's live installed config with its default
  //    'monitor'. This is the load-bearing guard against silently disabling a
  //    user's enforcement when the test suite runs.
  if (getConfig.get('enforce.mode')?.value === undefined) return;
  try {
    const dir = hookArtifactsDir();
    if (fs.existsSync(dir)) {
      fs.writeFileSync(path.join(dir, 'enforce-config.json'), payload, 'utf8');
    } else if (getEnforceMode() === 'enforce') {
      // Enforce is ON but the hook isn't installed → it cannot block. Warn loudly
      // rather than let the gap stay silent (mirrors the protected-paths warning).
      console.warn(
        `[enforce] mode is 'enforce' but the PreToolUse hook is NOT installed (${dir} missing), ` +
        `so nothing will block. Run \`claudesec install-hook\` to activate enforcement.`,
      );
    }
  } catch (err) {
    console.warn('[enforce] could not mirror enforce-config.json to the hooks dir:', (err as Error)?.message);
  }
}

// The startup derive/mirror is deferred to the guarded boot sequence
// (mirrorConfigOnBoot) so a module import never rewrites the hook's config.

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
        insertOrDedupeAlert({
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
      insertOrDedupeAlert({
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
  // The old `toolCallCount % 50 === 1` guard almost never matched: OTLP arrives
  // in batches, so the running total skips the exact trigger values and the
  // alert silently never fired. Fire on any count > 100 and rely solely on the
  // 30-minute dedup window below to prevent flooding.
  if (toolCallCount > 100) {
    const alreadyFlagged = db.prepare(
      `SELECT 1 FROM alerts WHERE traceId = ? AND ruleLabel = 'Excessive tool calls' AND ts > datetime('now', '-30 minutes')`
    ).get(traceId);
    if (!alreadyFlagged) {
      insertOrDedupeAlert({
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
      insertOrDedupeAlert({
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

// Single source of truth for the version surfaced over HTTP/MCP. Read from
// package.json at startup so a release bump can't drift from what the server
// reports. Falls back to '0.0.0' if the file can't be located (e.g. an unusual
// packaging layout) rather than crashing the boot.
const APP_VERSION = (() => {
  for (const candidate of [
    path.join(__dirname, '..', 'package.json'),
    path.join(__dirname, '..', '..', 'package.json'),
  ]) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, 'utf8')) as { version?: string };
      if (pkg.version) return pkg.version;
    } catch {}
  }
  return '0.0.0';
})();

// ── OTLP forwarding stats ────────────────────────────────────────────────
const forwardStats = { total: 0, success: 0, failed: 0, lastError: '', lastSuccessAt: '' };

// ── Auto-export (hourly) ─────────────────────────────────────────────────
const EXPORT_DIR = process.env.CLAUDESEC_AUTO_EXPORT_DIR || path.join(REPO_ROOT, 'exports');
let lastAutoExportAt = '';

function autoExport() {
  try {
    if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });
    const spans = getAllSpans.all() as SpanRecord[];
    const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC').all();
    const sessions = db.prepare('SELECT * FROM sessions ORDER BY createdAt DESC').all();
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const filePath = path.join(EXPORT_DIR, `claudesec-${ts}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      exportedAt: new Date().toISOString(),
      spanCount: spans.length,
      alertCount: (alerts as unknown[]).length,
      sessionCount: (sessions as unknown[]).length,
      spans, alerts, sessions,
      // Owner-only, matching the database the data came from — an export must
      // never be more readable than its source.
    }), { mode: 0o600 });
    lastAutoExportAt = new Date().toISOString();
    console.log(`[ClaudeSec] Auto-export → ${filePath}`);

    // Retain only last 24 exports
    const files = fs.readdirSync(EXPORT_DIR)
      .filter(f => f.startsWith('claudesec-') && f.endsWith('.json'))
      .sort().reverse();
    for (const old of files.slice(24)) {
      fs.unlinkSync(path.join(EXPORT_DIR, old));
    }
  } catch (err) {
    console.error('[ClaudeSec] Auto-export failed:', (err as Error).message);
  }
}

// Schedule auto-export only when running as the entry point — an import (test /
// build tool) must not leave a live timer running or write export files.
if (IS_ENTRY_POINT) {
  // Run auto-export every hour
  setInterval(autoExport, 60 * 60 * 1000);
  // Initial export after 30s (let server initialize)
  setTimeout(autoExport, 30_000);
}

function getWebhookUrl(): string {
  // Env var takes precedence over DB config
  return process.env.CLAUDESEC_WEBHOOK_URL
    ?? (getConfig.get('webhook.url')?.value ?? '');
}

function getWebhookThreshold(): Severity {
  const t = process.env.CLAUDESEC_WEBHOOK_THRESHOLD
    ?? (getConfig.get('webhook.threshold')?.value ?? 'high');
  return (['low', 'medium', 'high', 'critical'].includes(t) ? t : 'high') as Severity;
}

function maskWebhookUrl(url: string): string {
  try {
    return `${new URL(url).origin}/***`;
  } catch {
    return '***';
  }
}

// SSRF guard (assertSafeFetchUrl / isPublicAddress / SsrfBlockedError) and the
// loopback helpers (normalizeAddr / isLoopbackAddr) are imported from ./ssrf.js
// so every outbound-fetch sink — webhook sender/retry, OTLP forward, and the
// optional LLM-as-judge — shares ONE copy of the security control.

const SEV_RANK_MAP: Record<Severity, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

async function fireWebhook(alert: {
  ruleLabel: string; severity: Severity; harness: string;
  spanName: string; matchedText: string; traceId: string;
}) {
  const url = getWebhookUrl();
  if (!url) return;

  const threshold = getWebhookThreshold();
  if (SEV_RANK_MAP[alert.severity] < SEV_RANK_MAP[threshold]) return;

  // Parse the host instead of substring-matching the URL: a check like
  // url.includes('hooks.slack.com') would also accept https://evil.com/hooks.slack.com.
  let webhookHost = '';
  try { webhookHost = new URL(url).hostname.toLowerCase(); } catch { /* invalid URL → neither */ }
  const isSlack   = webhookHost === 'hooks.slack.com';
  const isDiscord = webhookHost === 'discord.com' || webhookHost === 'discordapp.com';

  const sevEmoji = alert.severity === 'critical' ? '🚨' : alert.severity === 'high' ? '🔴' : alert.severity === 'medium' ? '🟠' : '🟡';

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
    const color = alert.severity === 'critical' ? 0xf43f5e : alert.severity === 'high' ? 0xef4444 : alert.severity === 'medium' ? 0xf97316 : 0xeab308;
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

  const urlPreview = maskWebhookUrl(url);
  const deliveryRow = insertDelivery.run({
    ruleLabel: alert.ruleLabel, severity: alert.severity,
    urlPreview, createdAt: new Date().toISOString(),
  });
  const deliveryId = (deliveryRow as any).lastInsertRowid as number;
  pruneDeliveryLog();

  async function attempt(maxRetries: number, delayMs = 0): Promise<void> {
    if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));
    const t0 = Date.now();
    // Re-resolve and SSRF-check on EVERY attempt so DNS rebinding can't slip a
    // host inward between retries. A blocked host is terminal — never retried.
    try {
      await assertSafeFetchUrl(url);
    } catch (err) {
      const errMsg = (err as Error).message;
      updateDelivery.run('failed', null, Date.now() - t0, errMsg, new Date().toISOString(), deliveryId);
      console.error('[ClaudeSec] Webhook blocked (SSRF guard):', errMsg);
      return;
    }
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const latencyMs = Date.now() - t0;
      if (res.ok) {
        updateDelivery.run('success', res.status, latencyMs, null, new Date().toISOString(), deliveryId);
      } else {
        const errMsg = `HTTP ${res.status}`;
        if (maxRetries > 0) {
          updateDelivery.run('retrying', res.status, latencyMs, errMsg, new Date().toISOString(), deliveryId);
          attempt(maxRetries - 1, delayMs === 0 ? 1000 : delayMs * 3).catch(() => {});
        } else {
          updateDelivery.run('failed', res.status, latencyMs, errMsg, new Date().toISOString(), deliveryId);
          console.error(`[ClaudeSec] Webhook failed after retries: ${errMsg}`);
        }
      }
    } catch (err) {
      const latencyMs = Date.now() - t0;
      const errMsg = (err as Error).message;
      if (maxRetries > 0) {
        updateDelivery.run('retrying', null, latencyMs, errMsg, new Date().toISOString(), deliveryId);
        attempt(maxRetries - 1, delayMs === 0 ? 1000 : delayMs * 3).catch(() => {});
      } else {
        updateDelivery.run('failed', null, latencyMs, errMsg, new Date().toISOString(), deliveryId);
        console.error('[ClaudeSec] Webhook delivery failed:', errMsg);
      }
    }
  }
  attempt(2).catch(() => {}); // up to 3 total attempts (1 + 2 retries)
}

// ---------------------------------------------------------------------------
// Token cost estimation — per-1M prices (input / output USD)
// ---------------------------------------------------------------------------

const MODEL_PRICING: Record<string, { inputPer1M: number; outputPer1M: number; label: string }> = {
  // Claude
  'claude-fable-5':       { inputPer1M: 10,    outputPer1M: 50,    label: 'Claude Fable 5' },
  'claude-opus-4-8':      { inputPer1M: 5,     outputPer1M: 25,    label: 'Claude Opus 4.8' },
  'claude-opus-4-7':      { inputPer1M: 5,     outputPer1M: 25,    label: 'Claude Opus 4.7' },
  'claude-opus-4-6':      { inputPer1M: 5,     outputPer1M: 25,    label: 'Claude Opus 4.6' },
  'claude-opus-4-5':      { inputPer1M: 5,     outputPer1M: 25,    label: 'Claude Opus 4.5' },
  'claude-opus-4-1':      { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude Opus 4.1' },
  'claude-opus-4':        { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude Opus 4' },
  'claude-sonnet-4-6':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 4.6' },
  'claude-sonnet-4-5':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 4.5' },
  'claude-sonnet-4':      { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 4' },
  'claude-sonnet-3-7':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 3.7' },
  'claude-sonnet-3-5':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude Sonnet 3.5' },
  'claude-haiku-4-5':     { inputPer1M: 1,     outputPer1M: 5,     label: 'Claude Haiku 4.5' },
  'claude-haiku-3-5':     { inputPer1M: 0.8,   outputPer1M: 4,     label: 'Claude Haiku 3.5' },
  'claude-3-haiku':       { inputPer1M: 0.25,  outputPer1M: 1.25,  label: 'Claude 3 Haiku' },
  'claude-3-5-sonnet':    { inputPer1M: 3,     outputPer1M: 15,    label: 'Claude 3.5 Sonnet' },
  'claude-3-5-haiku':     { inputPer1M: 0.8,   outputPer1M: 4,     label: 'Claude 3.5 Haiku' },
  'claude-3-opus':        { inputPer1M: 15,    outputPer1M: 75,    label: 'Claude 3 Opus' },
  // OpenAI (Codex / Copilot). Output rates follow the current published per-1M
  // model card; mini/nano variants are listed so dated suffixes price correctly.
  'gpt-5.5':              { inputPer1M: 5,     outputPer1M: 30,    label: 'GPT-5.5' },
  'gpt-5.4-mini':         { inputPer1M: 0.75,  outputPer1M: 4.5,   label: 'GPT-5.4 mini' },
  'gpt-5.4-nano':         { inputPer1M: 0.2,   outputPer1M: 1.25,  label: 'GPT-5.4 nano' },
  'gpt-5.4':              { inputPer1M: 2.5,   outputPer1M: 15,    label: 'GPT-5.4' },
  'gpt-5.3-codex':        { inputPer1M: 1.75,  outputPer1M: 14,    label: 'GPT-5.3 Codex' },
  'gpt-5.3':              { inputPer1M: 0.88,  outputPer1M: 7,     label: 'GPT-5.3' },
  'gpt-5.2-codex':        { inputPer1M: 1.75,  outputPer1M: 14,    label: 'GPT-5.2 Codex' },
  'gpt-5.2':              { inputPer1M: 0.88,  outputPer1M: 7,     label: 'GPT-5.2' },
  'gpt-5-mini':           { inputPer1M: 0.25,  outputPer1M: 2,     label: 'GPT-5 mini' },
  'gpt-5':                { inputPer1M: 0.88,  outputPer1M: 7,     label: 'GPT-5' },
  'gpt-4o-mini':          { inputPer1M: 0.15,  outputPer1M: 0.6,   label: 'GPT-4o mini' },
  'gpt-4o':               { inputPer1M: 5,     outputPer1M: 15,    label: 'GPT-4o' },
  'gpt-4-turbo':          { inputPer1M: 10,    outputPer1M: 30,    label: 'GPT-4 Turbo' },
  'gpt-4':                { inputPer1M: 30,    outputPer1M: 60,    label: 'GPT-4' },
  'gpt-3.5-turbo':        { inputPer1M: 0.5,   outputPer1M: 1.5,   label: 'GPT-3.5 Turbo' },
  // Google (Copilot). Current Gemini 2.5 / 3.x rates plus legacy 1.5/2.0 entries
  // for historical sessions.
  'gemini-3.5-flash':     { inputPer1M: 1.5,   outputPer1M: 9,     label: 'Gemini 3.5 Flash' },
  'gemini-3.1-pro':       { inputPer1M: 2,     outputPer1M: 12,    label: 'Gemini 3.1 Pro' },
  'gemini-3-flash':       { inputPer1M: 0.5,   outputPer1M: 3,     label: 'Gemini 3 Flash' },
  'gemini-2.5-pro':       { inputPer1M: 1.25,  outputPer1M: 10,    label: 'Gemini 2.5 Pro' },
  'gemini-1.5-pro':       { inputPer1M: 3.5,   outputPer1M: 10.5,  label: 'Gemini 1.5 Pro' },
  'gemini-1.5-flash':     { inputPer1M: 0.075, outputPer1M: 0.3,   label: 'Gemini 1.5 Flash' },
  'gemini-2.0-flash':     { inputPer1M: 0.1,   outputPer1M: 0.4,   label: 'Gemini 2.0 Flash' },
  'gemini-pro':           { inputPer1M: 0.5,   outputPer1M: 1.5,   label: 'Gemini Pro' },
  'unknown':              { inputPer1M: 0,     outputPer1M: 0,     label: 'Unknown Model' },
};

function lookupPricing(model: string) {
  if (!model) return null;
  const lower = model.toLowerCase();
  // Direct match
  if (MODEL_PRICING[lower]) return MODEL_PRICING[lower];
  // LONGEST-prefix match (e.g. "claude-opus-4-6-20250514" → "claude-opus-4-6").
  // Longest wins so a dated variant like "gpt-4o-mini-2024-07-18" resolves to
  // "gpt-4o-mini" and never to the shorter "gpt-4o" that may be listed first.
  let best: string | null = null;
  for (const key of Object.keys(MODEL_PRICING)) {
    if (key === 'unknown') continue;
    if (lower.startsWith(key) && (best === null || key.length > best.length)) best = key;
  }
  return best ? MODEL_PRICING[best] : null;
}

// ---------------------------------------------------------------------------
// Security detection
// ---------------------------------------------------------------------------
// SEVERITY_RULES is imported from server/detection.ts (side-effect-free module).

interface DetectHit {
  severity: Severity;
  matchedLabel: string;
  matchedText: string;
  matchStart: number;
  matchEnd:   number;
  ruleKey:    string;
}

// ── Enforcement event log (PreToolUse hook → /api/enforce-log) ──────────────
// The last N enforcement decisions reported by the opt-in claudesec-enforce.cjs
// PreToolUse hook, so the dashboard can show "what would be / was blocked". Now
// PERSISTED to SQLite (server/enforceLogStore.ts) with the same tamper-evident
// hash chain as the operator audit log, so the feed survives a restart. Capped
// + pruned on insert; the live Socket.io broadcast is unchanged.

function detectSeverity(text: string): DetectHit {
  // SECURITY: batch the suppression + disabled-rule lookups — both cached for
  // ~2s, so ingest never round-trips SQLite per rule per span under load.
  const suppressed = getSuppressedKeysCached();
  const disabled   = getDisabledRuleLabelsCached();

  // Custom rules first — user overrides beat built-ins.
  for (const rule of customRules) {
    const key = `custom:${rule.id}`;
    if (suppressed.has(key)) continue;
    if (disabled.has(rule.label)) continue; // operator-disabled rule
    // Skip patterns that exceed the ReDoS-mitigation cap (e.g. rules persisted
    // before the limit was enforced at creation time).
    if (rule.pattern.length > MAX_RULE_PATTERN_LEN) continue;
    try {
      const re = new RE2(rule.pattern, rule.flags);
      const m = re.exec(text);
      if (m) {
        return {
          severity: rule.severity,
          matchedLabel: rule.label,
          matchedText: m[0].slice(0, 100),
          matchStart: m.index,
          matchEnd:   m.index + m[0].length,
          ruleKey:    key,
        };
      }
    } catch { /* invalid regex — skip */ }
  }

  for (let i = 0; i < SEVERITY_RULES.length; i++) {
    const key = `builtin-${i}`;
    if (suppressed.has(key)) continue;
    const rule = SEVERITY_RULES[i];
    // Operator-disabled built-in rule. The catastrophic-floor labels are never
    // in the disabled set (filtered at cache build), so they always run.
    if (disabled.has(rule.label)) continue;
    const m = rule.pattern.exec(text);
    if (m) {
      return {
        severity: rule.severity,
        matchedLabel: rule.label,
        matchedText: m[0].slice(0, 100),
        matchStart: m.index,
        matchEnd:   m.index + m[0].length,
        ruleKey:    key,
      };
    }
  }

  return {
    severity: 'none', matchedLabel: '', matchedText: '',
    matchStart: -1, matchEnd: -1, ruleKey: '',
  };
}

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<Severity, { bg: string; border: string }> = {
  none:     { bg: '',        border: '' },
  low:      { bg: '#fefce8', border: '#eab308' },
  medium:   { bg: '#fff7ed', border: '#f97316' },
  high:     { bg: '#fee2e2', border: '#ef4444' },
  critical: { bg: '#4c0519', border: '#f43f5e' },
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
    style: style.border
      ? { backgroundColor: style.bg, border: `2px solid ${style.border}`, color: '#1e293b' }
      : { backgroundColor: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border-soft)', color: 'var(--cs-text-base)' },
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
  // A single session is already bounded, so it loads in full. The unscoped graph
  // loads only the most-recent N spans (see GRAPH_LIMIT) to keep both the server
  // build and the frontend relayout fast. `windowed` tells the UI when older
  // spans exist beyond the window — they are still searchable, never deleted.
  let records: SpanRecord[];
  let windowed = false;
  let total = 0;
  if (sessionFilter) {
    records = db.prepare('SELECT * FROM spans WHERE traceId = ?').all(sessionFilter) as SpanRecord[];
  } else {
    total   = (countSpans.get() as { c: number }).c;
    records = getRecentSpans.all(GRAPH_LIMIT) as SpanRecord[];
    windowed = total > records.length;
  }

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
        style: { backgroundColor: h.color + '22', border: `2px solid ${h.color}`, color: 'var(--cs-text-base)' },
      };
    });
  }

  return {
    nodes: [...rootNodes, ...records.map(recordToNode)],
    edges: records.map(recordToEdge),
    // Graph windowing metadata — backward compatible (consumers may ignore it).
    windowed,
    shown: records.length,
    total: sessionFilter ? records.length : total,
    limit: GRAPH_LIMIT,
  };
}

// ---------------------------------------------------------------------------
// SSE live tail — registry of active streaming clients
// ---------------------------------------------------------------------------

interface SseClient {
  id: string;
  res: import('express').Response;
  harnessFilter: string | null;
  severityFilter: string | null;
}

const sseClients = new Map<string, SseClient>();

function pushToSse(spanRecord: SpanRecord) {
  if (sseClients.size === 0) return;
  const payload = JSON.stringify(spanRecord) + '\n';
  for (const client of sseClients.values()) {
    if (client.harnessFilter && client.harnessFilter !== spanRecord.harness) continue;
    if (client.severityFilter && client.severityFilter !== spanRecord.severity) continue;
    try {
      client.res.write(`data: ${payload}\n`);
    } catch {
      sseClients.delete(client.id);
    }
  }
}

// ---------------------------------------------------------------------------
// Rate limiting — token bucket per IP for /v1/traces
// ---------------------------------------------------------------------------

const MAX_RULE_PATTERN_LEN = 1000; // cap user regex length to mitigate ReDoS
const RATE_LIMIT_RPS     = Number(process.env.CLAUDESEC_RATE_LIMIT_RPS ?? 50);
const RATE_LIMIT_BURST   = Number(process.env.CLAUDESEC_RATE_LIMIT_BURST ?? 200);
const MAX_SPANS_PER_BATCH = Number(process.env.CLAUDESEC_MAX_SPANS_BATCH ?? 500);

interface TokenBucket { tokens: number; lastRefill: number }
const ipBuckets = new Map<string, TokenBucket>();

function allowRequest(ip: string): { allowed: boolean; retryAfterMs: number } {
  const now = Date.now();
  let bucket = ipBuckets.get(ip);
  if (!bucket) {
    bucket = { tokens: RATE_LIMIT_BURST, lastRefill: now };
    ipBuckets.set(ip, bucket);
  }
  // Refill tokens based on elapsed time
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(RATE_LIMIT_BURST, bucket.tokens + elapsed * RATE_LIMIT_RPS);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return { allowed: true, retryAfterMs: 0 };
  }
  const retryAfterMs = Math.ceil((1 - bucket.tokens) / RATE_LIMIT_RPS * 1000);
  return { allowed: false, retryAfterMs };
}

// Periodically evict stale buckets (> 5 min idle)
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [ip, b] of ipBuckets) if (b.lastRefill < cutoff) ipBuckets.delete(ip);
}, 60_000).unref();


// ---------------------------------------------------------------------------
// Activity ring-buffer — 60 one-second buckets for sparkline
// ---------------------------------------------------------------------------

interface ActivityBucket { ts: number; spans: number; tokensIn: number; tokensOut: number }
const ACTIVITY_WINDOW = 60;
const activityRing: ActivityBucket[] = Array.from({ length: ACTIVITY_WINDOW }, (_, i) => ({
  ts: Date.now() - (ACTIVITY_WINDOW - 1 - i) * 1000,
  spans: 0, tokensIn: 0, tokensOut: 0,
}));

function recordActivity(spans: number, tokensIn: number, tokensOut: number) {
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  const last = activityRing[activityRing.length - 1];
  const lastSec = Math.floor(last.ts / 1000);

  if (nowSec > lastSec) {
    // Advance ring buffer, filling gaps with zeros
    const gap = Math.min(nowSec - lastSec, ACTIVITY_WINDOW);
    for (let i = 0; i < gap; i++) {
      activityRing.shift();
      activityRing.push({ ts: (lastSec + i + 1) * 1000, spans: 0, tokensIn: 0, tokensOut: 0 });
    }
  }
  const cur = activityRing[activityRing.length - 1];
  cur.spans    += spans;
  cur.tokensIn  += tokensIn;
  cur.tokensOut += tokensOut;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function startServer() {
  const app        = express();
  const httpServer = createServer(app);

  // SECURITY: Restrict CORS to localhost origins only (prevents cross-site request forgery)
  const ALLOWED_ORIGINS = (process.env.CLAUDESEC_CORS_ORIGINS ?? '').split(',').filter(Boolean);
  // CLAUDESEC_PORT wins over the generic PORT so a colocated dev server that
  // also reads PORT (Next.js, CRA, …) can't steer or collide with the dashboard.
  // Same resolution order as the CLI and the enforcement hook.
  const PORT = Number(process.env.CLAUDESEC_PORT ?? process.env.PORT ?? 3000);
  const defaultOrigins = [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];
  const corsOrigins = ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : defaultOrigins;

  const io = new Server(httpServer, { cors: { origin: corsOrigins } });

  // SECURITY: Loopback-exempt Socket.io handshake gate (mirrors the HTTP auth
  // middleware below).  Local clients (the dashboard) connect untouched; a
  // non-loopback client must present CLAUDESEC_TOKEN via handshake auth or
  // ?token=.  Uses the raw connection address, not spoofable proxy headers.
  // CLAUDESEC_TRUST_LOCAL=1 bypasses the address check (opt-in, default off).
  io.use((socket, next) => {
    const addr = socket.conn?.remoteAddress ?? socket.handshake.address;
    if (isLoopbackAddr(addr) || trustLocalEnabled()) { next(); return; }
    const token =
      (socket.handshake.auth && (socket.handshake.auth as any).token) ??
      (socket.handshake.query && (socket.handshake.query as any).token);
    if (tokenMatches(typeof token === 'string' ? token : undefined, process.env.CLAUDESEC_TOKEN ?? '')) {
      next();
      return;
    }
    next(new Error('unauthorized'));
  });

  function ingestSpan(input: IngestInput): { newSession: boolean; alertChanged: boolean } {
    const rawAttrs: Record<string, any> = { ...input.rawAttrs };
    const searchText = JSON.stringify(rawAttrs) + ' ' + input.name;
    const hit = detectSeverity(searchText);
    if (hit.matchedLabel) rawAttrs['claudesec.threat.rule'] = hit.matchedLabel;

    const { attrs, honeytokenHits } = scrubAttributes(rawAttrs, scrubOptions);
    const scrubbedName    = scrubText(input.name, scrubOptions);
    const scrubbedMatched = scrubText(hit.matchedText, scrubOptions);

    const traceId  = input.traceId  || 'unknown';
    const parentId = input.parentId || input.harnessId;

    let newSession = false;
    if (!db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(traceId)) {
      const sessionName = `${input.harnessName} · ${new Date().toLocaleTimeString()}`;
      upsertSession.run(traceId, sessionName, new Date().toISOString());
      newSession = true;
    }

    const finalSeverity: Severity = honeytokenHits.length > 0 ? 'high' : hit.severity;
    const finalLabel =
      honeytokenHits.length > 0
        ? `Honeytoken exfiltration (${honeytokenHits[0].key})`
        : hit.matchedLabel;

    // Repository identity for the Per-Repository Dashboard. Derived from the
    // agent's cwd (walk up to the nearest .git root), scrubbed the same way as
    // every other stored path. Falls back to 'unknown' when no cwd was recorded.
    const repo = resolveRepo(
      typeof rawAttrs['cwd'] === 'string' ? (rawAttrs['cwd'] as string) : undefined,
      scrubOptions,
    );

    const spanRecord: SpanRecord = {
      spanId:     input.spanId,
      traceId,
      parentId,
      name:       scrubbedName,
      protocol:   String(attrs['protocol'] ?? 'HTTPS'),
      reason:     String(attrs['reason']   ?? 'Processing step'),
      severity:   finalSeverity,
      harness:    input.harnessId,
      attributes: JSON.stringify(attrs),
      startNano:  input.startNano || '0',
      endNano:    input.endNano   || '0',
      repo,
    };
    insertSpan.run(spanRecord);
    pushToSse(spanRecord);
    io.emit('span-added', {
      spanId:   spanRecord.spanId,
      name:     spanRecord.name,
      harness:  spanRecord.harness,
      severity: spanRecord.severity,
      ts:       new Date().toISOString(),
    });

    let alertChanged = false;
    if (finalLabel) {
      insertOrDedupeAlert({
        ts:          new Date().toISOString(),
        ruleLabel:   finalLabel,
        severity:    finalSeverity,
        spanId:      input.spanId,
        traceId,
        harness:     input.harnessId,
        spanName:    scrubbedName,
        matchedText: scrubbedMatched || '(honeytoken)',
      });
      alertChanged = true;
      fireWebhook({
        ruleLabel:   finalLabel,
        severity:    finalSeverity,
        harness:     input.harnessId,
        spanName:    scrubbedName,
        matchedText: scrubbedMatched || '(honeytoken)',
        traceId,
      }).catch(() => {});
    }

    return { newSession, alertChanged };
  }

  // ── Demo-container seeding ────────────────────────────────────────────────
  // The isolated demo container (docker-compose profile `demo`, on :3001) runs
  // ClaudeSec against its OWN database volume that should hold nothing but
  // synthetic data. When CLAUDESEC_SEED_DEMO=1, populate that empty DB once with
  // the synthetic scenarios in server/demoData.ts, feeding each span through the
  // same `ingestSpan` the OTLP/transcript paths use so the real detection engine
  // classifies them.
  //
  // TWO GUARDS keep this from ever touching real data:
  //   1. The env var must be exactly "1" (opt-in; the prod compose service and
  //      every local/pnpm run leave it unset).
  //   2. The spans table must be empty. A populated DB — real OR a previously
  //      seeded demo — is left untouched, so this is idempotent and can never
  //      duplicate or overwrite existing telemetry.
  // (seedDemoData re-checks the empty-table condition internally as a backstop.)
  if (process.env.CLAUDESEC_SEED_DEMO === '1') {
    const spanCount = () =>
      (db.prepare('SELECT COUNT(*) AS c FROM spans').get() as { c: number }).c;
    if (spanCount() === 0) {
      seedDemoData({
        ingestSpan,
        spanCount,
        upsertSession: (traceId, name, createdAt) => { upsertSession.run(traceId, name, createdAt); },
        harnessName: (id) => (HARNESSES.find(h => h.id === id) ?? HARNESSES[HARNESSES.length - 1]).name,
        log: (msg) => console.log(msg),
      });
    }
  }

  // One-time, idempotent backfill of the per-span `repo` column for rows ingested
  // before that column existed. Writes ONLY `repo` (see backfillRepos for the full
  // data-safety contract); fail-open so it can never block startup.
  backfillRepos(db, scrubOptions, (msg) => console.log(msg));

  // Security headers.  The dashboard uses inline event handlers, dynamic
  // Tailwind classes, and a live Socket.io websocket, so the CSP is configured
  // permissively (it allows inline/eval and ws/wss) rather than disabled — this
  // keeps a baseline policy in place while not breaking the UI.  All other
  // helmet defaults (X-Content-Type-Options, Referrer-Policy, frame-ancestors,
  // etc.) apply.
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src':  ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src':   ["'self'", "'unsafe-inline'"],
        'img-src':     ["'self'", 'data:', 'blob:'],
        'connect-src': ["'self'", 'ws:', 'wss:'],
        'font-src':    ["'self'", 'data:'],
        // The dashboard is served over plain HTTP on localhost; do not force
        // sub-resource requests to upgrade to HTTPS (would break asset loads).
        'upgrade-insecure-requests': null,
      },
    },
    crossOriginEmbedderPolicy: false,
  }));
  app.use(cors({ origin: corsOrigins }));
  app.use(bodyParser.json({ limit: '10mb' }));

  // Global rate limiter — caps abusive request volume on every API/UI route to
  // mitigate denial-of-service.  The high-volume OTLP ingest endpoint is skipped
  // here because it has its own dedicated token-bucket limiter (allowRequest).
  app.use(rateLimit({
    windowMs: 60_000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/v1/traces',
  }));

  // ═══════════════════════════════════════════════════════════════════════════
  // ROUTE EXPOSURE AUDIT
  // ═══════════════════════════════════════════════════════════════════════════
  // The auth middleware below enforces a LOOPBACK-EXEMPT token gate. Protection
  // status of every route group:
  //
  //   DATA routes — GATED (loopback-open + token-required-for-remote):
  //     • /api/*    — all dashboard data, config, search, exports, mutations
  //     • /mcp      — POST /mcp AI-to-AI tool surface (esp. `search_spans`,
  //                   which can read arbitrary span content)
  //     • /v1/traces — OTLP ingest. STAYS LOOPBACK-REACHABLE: local Claude Code
  //                   agents POST here with no token; only remote ingest needs one.
  //
  //   STATIC / SPA — OPEN (no data in the app shell):
  //     • Vite middleware (dev) and express.static + app.get('*') (prod) are
  //       registered AFTER this middleware and are NOT gated. A remote attacker
  //       may load the empty HTML/JS shell but receives 401 on every data call,
  //       so no span data leaks. Gating the shell would create a bootstrap
  //       chicken-and-egg for the legitimate local dashboard.
  //
  //   OPERATIONAL — OPEN (no span data):
  //     • GET /metrics — Prometheus counters only (no span content). Not gated.
  //
  //   Mutating / sensitive routes to be aware of (all under the GATED /api or
  //   /mcp prefix above, so all loopback-only or token-protected):
  //     • POST   /api/import                       (bulk span ingest)
  //     • POST   /api/reset                        (wipe all data)
  //     • POST/PATCH/DELETE /api/threshold-rules*  (threshold rule mutation)
  //     • POST/DELETE       /api/rules*            (custom rule mutation)
  //     • DELETE /api/processes/:pid               (kill a process)
  //     • POST   /api/processes/kill-all|pause-all|resume-all
  //     • GET    /api/export, /api/export/csv, /api/alerts/export,
  //              /api/search/export                (data exfil surface)
  //     • POST   /mcp                              (esp. tool `search_spans`)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // SECURITY: Loopback-exempt auth gate for sensitive routes. The dashboard SPA
  // and the Socket.io client call /api/* from the SAME origin over loopback, so
  // a blanket token gate would break local use. Loopback → allow (no token).
  // Non-loopback → require CLAUDESEC_TOKEN. The real client address comes from
  // req.socket.remoteAddress (NOT X-Forwarded-For, which is spoofable). Fail
  // closed: if CLAUDESEC_TOKEN is unset, all non-loopback data requests are 401.
  // CLAUDESEC_TRUST_LOCAL=1 bypasses the address check (opt-in, default off):
  // used in Docker where the container sees a bridge IP instead of loopback.
  app.use((req, res, next) => {
    const isGated =
      req.path === '/api' ||
      req.path.startsWith('/api/') ||
      req.path === '/mcp' ||
      req.path.startsWith('/mcp/') ||
      req.path.startsWith('/v1/traces');
    if (!isGated) { next(); return; }

    if (isLoopbackAddr(req.socket.remoteAddress) || trustLocalEnabled()) { next(); return; }

    const expected = process.env.CLAUDESEC_TOKEN ?? '';
    if (!expected) { res.status(401).json({ error: 'unauthorized' }); return; }

    const bearer = req.headers['authorization'];
    const fromBearer =
      typeof bearer === 'string' && /^bearer\s+/i.test(bearer)
        ? bearer.replace(/^bearer\s+/i, '').trim()
        : undefined;
    const apiKeyHeader = req.headers['x-api-key'];
    const fromApiKey = typeof apiKeyHeader === 'string' ? apiKeyHeader.trim() : undefined;
    const queryToken = typeof req.query.token === 'string' ? req.query.token : undefined;
    const presented = fromBearer || fromApiKey || queryToken;

    if (tokenMatches(presented, expected)) { next(); return; }
    res.status(401).json({ error: 'unauthorized' });
  });

  // ── Graph-broadcast throttle ────────────────────────────────────────────
  // Coalesce full-graph broadcasts to at most one every 250ms.  High-volume
  // OTLP batches were triggering a full rebuild + emit per request before
  // this; browser-side React Flow could not keep up.
  let _pendingGraphEmit: NodeJS.Timeout | null = null;
  function emitGraphUpdateThrottled(sessionFilter?: string): void {
    if (_pendingGraphEmit) return;
    _pendingGraphEmit = setTimeout(() => {
      _pendingGraphEmit = null;
      io.emit('graph-update', buildGraph(sessionFilter));
    }, 250);
  }

  // ── OTLP ingestion ──────────────────────────────────────────────────────
  app.post('/v1/traces', (req, res) => {
    // --- Rate limiting ---
    // SECURITY: Use socket address by default — X-Forwarded-For is trivially spoofable
    // Set CLAUDESEC_TRUST_PROXY=1 to trust proxy headers (only behind a reverse proxy)
    const trustProxy = process.env.CLAUDESEC_TRUST_PROXY === '1';
    const clientIp = trustProxy
      ? String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'unknown').split(',')[0].trim()
      : String(req.socket.remoteAddress ?? 'unknown');
    const { allowed, retryAfterMs } = allowRequest(clientIp);
    if (!allowed) {
      res.setHeader('Retry-After', String(Math.ceil(retryAfterMs / 1000)));
      res.status(429).json({ error: 'Too Many Requests', retryAfterMs });
      return;
    }

    // --- Circuit breaker: pause ingestion when DB is ≥ 90% full ---
    const maxSpans = getMaxSpans();
    const currentSpans = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    if (currentSpans >= maxSpans * 0.9) {
      res.status(503).json({ error: 'Service Unavailable', detail: 'Span buffer near capacity. Try again after pruning.' });
      return;
    }

    const traceData: TraceData = req.body;

    // --- Span count guard per batch ---
    let batchSpanCount = 0;
    traceData.resourceSpans?.forEach(rs => rs.scopeSpans?.forEach(ss => { batchSpanCount += ss.spans?.length ?? 0; }));
    if (batchSpanCount > MAX_SPANS_PER_BATCH) {
      res.status(400).json({ error: 'Bad Request', detail: `Batch exceeds max ${MAX_SPANS_PER_BATCH} spans. Got ${batchSpanCount}.` });
      return;
    }
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
          if (process.env.CLAUDESEC_WATCH !== '0' && span.name === 'tool_call/unknown') return;
          const rawAttrs: Record<string, any> = {};
          (span.attributes || []).forEach(attr => {
            rawAttrs[attr.key] =
              attr.value?.stringValue ??
              attr.value?.intValue    ??
              attr.value?.boolValue   ??
              JSON.stringify(attr.value);
          });

          const result = ingestSpan({
            spanId:      span.spanId,
            traceId:     span.traceId || 'unknown',
            parentId:    span.parentSpanId || '',
            name:        span.name,
            rawAttrs,
            harnessId:   harness.id,
            harnessName: harness.name,
            startNano:   String(span.startTimeUnixNano ?? '0'),
            endNano:     String(span.endTimeUnixNano ?? '0'),
          });
          if (result.newSession)   newSessions   = true;
          if (result.alertChanged) alertsChanged = true;
        });
      });
    });

    // Activity ring-buffer update
    {
      let batchTokensIn = 0, batchTokensOut = 0, batchCount = 0;
      traceData.resourceSpans?.forEach(rs => rs.scopeSpans?.forEach(ss => ss.spans?.forEach(span => {
        batchCount++;
        (span.attributes || []).forEach(attr => {
          if (attr.key === 'gen_ai.usage.input_tokens'  || attr.key === 'llm.usage.input_tokens')  batchTokensIn  += Number(attr.value?.intValue ?? 0);
          if (attr.key === 'gen_ai.usage.output_tokens' || attr.key === 'llm.usage.output_tokens') batchTokensOut += Number(attr.value?.intValue ?? 0);
        });
      })));
      recordActivity(batchCount, batchTokensIn, batchTokensOut);
    }

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
      evaluateThresholdRules(traceId, traceHarness);
    }

    // Retention pruning (async — don't block response)
    setImmediate(() => {
      const { prunedByAge, prunedByCount } = pruneSpans();
      if (prunedByAge + prunedByCount > 0) {
        console.log(`[ClaudeSec] Pruned ${prunedByAge} aged + ${prunedByCount} excess spans`);
        io.emit('sessions-update');
      }
    });

    emitGraphUpdateThrottled();
    if (newSessions)   io.emit('sessions-update');
    if (alertsChanged) io.emit('alerts-update');

    // ── OTLP Trace Forwarding (Phase 16 / s72) ──
    // Shares the same DNS-resolving SSRF guard as the webhook sender so the
    // forward target can't be pointed at loopback/metadata/private ranges via
    // integer/hex literals, IPv6 forms, or DNS rebinding. Runs in a detached
    // async IIFE so the resolution does not block the ingest response.
    const forwardUrl = process.env.OTEL_FORWARD_URL ?? getConfig.get('otel.forward.url')?.value ?? '';
    if (forwardUrl) {
      void (async () => {
        try {
          await assertSafeFetchUrl(forwardUrl);
        } catch (err) {
          forwardStats.total++;
          forwardStats.failed++;
          forwardStats.lastError = `blocked (SSRF guard): ${(err as Error).message}`;
          return;
        }
        try {
          const r = await fetch(forwardUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(traceData),
            signal: AbortSignal.timeout(5000),
          });
          forwardStats.total++;
          if (r.ok) { forwardStats.success++; forwardStats.lastSuccessAt = new Date().toISOString(); }
          else      { forwardStats.failed++; forwardStats.lastError = `HTTP ${r.status}`; }
        } catch (err) {
          forwardStats.total++;
          forwardStats.failed++;
          forwardStats.lastError = (err as Error).message;
        }
      })();
    }

    res.status(200).json({ status: 'ok' });
  });

  // ── Activity sparkline data ──────────────────────────────────────────────
  app.get('/api/activity', (_req, res) => {
    // Return a fresh snapshot: advance ring buffer to now first
    recordActivity(0, 0, 0);
    res.json({ buckets: activityRing.map(b => ({ ts: b.ts, spans: b.spans, tokensIn: b.tokensIn, tokensOut: b.tokensOut })) });
  });

  // ── Threat heatmap — 7×24 day-of-week × hour matrix ─────────────────────
  registerHeatmapRoutes(app, { io });

  // ── Trace import ─────────────────────────────────────────────────────────
  app.post('/api/import', (req, res) => {
    const body = req.body;
    let imported = 0;
    let alertsAdded = 0;
    let newSessions = false;

    // SECURITY: Limit import batch size (same as /v1/traces)
    const importSpanCount = Array.isArray(body?.spans) ? body.spans.length : 0;
    if (importSpanCount > MAX_SPANS_PER_BATCH) {
      return res.status(400).json({ error: `Import exceeds max ${MAX_SPANS_PER_BATCH} spans. Got ${importSpanCount}.` }) as any;
    }
    // Circuit breaker
    const currentSpans = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    if (currentSpans >= getMaxSpans() * 0.9) {
      return res.status(503).json({ error: 'Span buffer near capacity. Prune before importing.' }) as any;
    }

    // Detect format: ClaudeSec export ({ spans: SpanRecord[] }) or raw OTLP ({ resourceSpans: [...] })
    if (Array.isArray(body?.spans)) {
      // ClaudeSec JSON export format
      for (const span of body.spans as SpanRecord[]) {
        try {
          if (!span.spanId || !span.traceId) continue;
          if (!db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(span.traceId)) {
            upsertSession.run(span.traceId, `Import · ${new Date().toLocaleTimeString()}`, new Date().toISOString());
            newSessions = true;
          }
          const rawAttrs = typeof span.attributes === 'string' ? JSON.parse(span.attributes) : span.attributes;
          const searchText = JSON.stringify(rawAttrs) + ' ' + span.name;
          const hit = detectSeverity(searchText);
          const { attrs, honeytokenHits } = scrubAttributes(rawAttrs, scrubOptions);
          const scrubbedName    = scrubText(span.name, scrubOptions);
          const scrubbedMatched = scrubText(hit.matchedText, scrubOptions);
          const severity: Severity = honeytokenHits.length > 0 ? 'high' : hit.severity;
          const label = honeytokenHits.length > 0
            ? `Honeytoken exfiltration (${honeytokenHits[0].key})`
            : hit.matchedLabel;
          const importRepo = span.repo || resolveRepo(typeof rawAttrs['cwd'] === 'string' ? rawAttrs['cwd'] : undefined, scrubOptions);
          insertSpan.run({ ...span, severity, name: scrubbedName, attributes: JSON.stringify(attrs), repo: importRepo } satisfies SpanRecord);
          if (label) {
            insertOrDedupeAlert({ ts: new Date().toISOString(), ruleLabel: label, severity, spanId: span.spanId, traceId: span.traceId, harness: span.harness, spanName: scrubbedName, matchedText: scrubbedMatched || '(honeytoken)' });
            alertsAdded++;
          }
          imported++;
        } catch {}
      }
    } else if (Array.isArray(body?.resourceSpans)) {
      // Raw OTLP format — re-use ingestion logic
      const traceData: TraceData = body;
      traceData.resourceSpans?.forEach(rs => {
        const serviceName = String(rs.resource?.attributes?.find?.((a: any) => a.key === 'service.name')?.value?.stringValue ?? '');
        const sdkName     = String(rs.resource?.attributes?.find?.((a: any) => a.key === 'telemetry.sdk.name')?.value?.stringValue ?? '');
        const harness = detectHarness(serviceName, sdkName);
        rs.scopeSpans?.forEach(ss => {
          ss.spans?.forEach(span => {
            const rawAttrs: Record<string, any> = {};
            (span.attributes || []).forEach(attr => {
              rawAttrs[attr.key] = attr.value?.stringValue ?? attr.value?.intValue ?? attr.value?.boolValue ?? JSON.stringify(attr.value);
            });
            const traceId  = span.traceId  || 'unknown';
            const parentId = span.parentSpanId || harness.id;
            if (!db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(traceId)) {
              upsertSession.run(traceId, `Import · ${new Date().toLocaleTimeString()}`, new Date().toISOString());
              newSessions = true;
            }
            const searchText = JSON.stringify(rawAttrs) + ' ' + span.name;
            const hit = detectSeverity(searchText);
            const { attrs, honeytokenHits } = scrubAttributes(rawAttrs, scrubOptions);
            const scrubbedName    = scrubText(span.name, scrubOptions);
            const scrubbedMatched = scrubText(hit.matchedText, scrubOptions);
            const severity: Severity = honeytokenHits.length > 0 ? 'high' : hit.severity;
            const label = honeytokenHits.length > 0
              ? `Honeytoken exfiltration (${honeytokenHits[0].key})`
              : hit.matchedLabel;
            const otlpRepo = resolveRepo(typeof rawAttrs['cwd'] === 'string' ? rawAttrs['cwd'] : undefined, scrubOptions);
            insertSpan.run({ spanId: span.spanId, traceId, parentId, name: scrubbedName, protocol: String(attrs['protocol'] ?? 'HTTPS'), reason: String(attrs['reason'] ?? 'Processing step'), severity, harness: harness.id, attributes: JSON.stringify(attrs), startNano: String(span.startTimeUnixNano ?? '0'), endNano: String(span.endTimeUnixNano ?? '0'), repo: otlpRepo } satisfies SpanRecord);
            if (label) {
              insertOrDedupeAlert({ ts: new Date().toISOString(), ruleLabel: label, severity, spanId: span.spanId, traceId, harness: harness.id, spanName: scrubbedName, matchedText: scrubbedMatched || '(honeytoken)' });
              alertsAdded++;
            }
            imported++;
          });
        });
      });
    } else {
      res.status(400).json({ error: 'Unrecognized format. Expected { spans: [...] } or { resourceSpans: [...] }' });
      return;
    }

    io.emit('graph-update', buildGraph());
    if (newSessions) io.emit('sessions-update');
    if (alertsAdded) io.emit('alerts-update');
    res.json({ status: 'ok', imported, alertsAdded });
  });

  // ── Graph ────────────────────────────────────────────────────────────────
  app.get('/api/graph', (req, res) => {
    const session = req.query.session ? String(req.query.session) : undefined;
    res.json(buildGraph(session));
  });

  // ── Sessions ─────────────────────────────────────────────────────────────
  registerSessionRoutes(app, { io, healthFromCounts, computeHealthScore, appVersion: APP_VERSION });

  // ── Span search ──────────────────────────────────────────────────────────
  app.get('/api/spans', (req, res) => {
    const q       = String(req.query.q       ?? '').trim();
    const session = String(req.query.session ?? '').trim();
    const offset  = Math.max(0, parseInt(String(req.query.offset ?? '0'), 10) || 0);

    let sql = 'SELECT s.* FROM spans s WHERE 1=1';
    const params: unknown[] = [];

    if (session) { sql += ' AND s.traceId = ?'; params.push(session); }

    if (q) {
      if (q.includes('=')) {
        // Structured key=value lookup. FTS tokenizes the JSON and loses the
        // key↔value association, so this targeted match stays on LIKE.
        const eqIdx = q.indexOf('=');
        const key   = q.slice(0, eqIdx).trim();
        const val   = q.slice(eqIdx + 1).trim();
        sql += ' AND (s.attributes LIKE ? OR s.name LIKE ?)';
        params.push(`%"${key}":"${val}%`, `%${val}%`);
      } else {
        // Free-text search routes through the FTS5 index instead of a leading-
        // wildcard LIKE (which forces a full table scan). Mirrors the proven
        // /api/search/fts pattern: split on whitespace, prefix-match each term.
        const terms = q.replace(/["']/g, ' ').split(/\s+/).filter(Boolean);
        if (terms.length === 0) {
          res.json({ spans: [], offset, hasMore: false });
          return;
        }
        const ftsQuery = terms.map(t => `"${t}"*`).join(' ');
        sql += ' AND s.spanId IN (SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?)';
        params.push(ftsQuery);
      }
    }

    sql += ' ORDER BY s.startNano ASC LIMIT 500 OFFSET ?';
    params.push(offset);
    let spans: SpanRecord[];
    try {
      spans = db.prepare(sql).all(...params) as SpanRecord[];
    } catch {
      // Malformed FTS expression → return empty rather than 500.
      spans = [];
    }
    res.json({ spans, offset, hasMore: spans.length === 500 });
  });

  // ── Export ───────────────────────────────────────────────────────────────
  registerExportRoutes(app, { io, appVersion: APP_VERSION });

  // ── Harness profiles (full per-agent stats) ──────────────────────────────
  registerHarnessRoutes(app, { io });

  // ── SSE live tail ────────────────────────────────────────────────────────
  app.get('/api/tail', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const clientId       = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const harnessFilter  = req.query.harness  ? String(req.query.harness)  : null;
    const severityFilter = req.query.severity ? String(req.query.severity) : null;

    sseClients.set(clientId, { id: clientId, res, harnessFilter, severityFilter });

    // Send a comment heartbeat every 15s to keep connection alive
    const heartbeat = setInterval(() => {
      try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); sseClients.delete(clientId); }
    }, 15_000);

    req.on('close', () => {
      clearInterval(heartbeat);
      sseClients.delete(clientId);
    });
  });

  // ── MCP server (Model Context Protocol JSON-RPC 2.0 over HTTP) ───────────
  app.post('/mcp', async (req, res) => {
    const { jsonrpc, id, method, params } = req.body as {
      jsonrpc: string; id: unknown; method: string; params?: Record<string, unknown>;
    };

    if (jsonrpc !== '2.0') {
      res.json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
      return;
    }

    const ok = (result: unknown) => res.json({ jsonrpc: '2.0', id, result });
    const err = (code: number, message: string) => res.json({ jsonrpc: '2.0', id, error: { code, message } });

    try {
      switch (method) {
        case 'tools/list': {
          ok({
            tools: [
              { name: 'get_health',           description: 'Server health, span/session/alert counts, DB size', inputSchema: { type: 'object', properties: {} } },
              { name: 'get_sessions',         description: 'List all recorded sessions', inputSchema: { type: 'object', properties: { label: { type: 'string', description: 'Filter by label: normal|incident|investigation|automated|other' } } } },
              { name: 'get_spans',            description: 'Get spans for a session by traceId', inputSchema: { type: 'object', properties: { traceId: { type: 'string' } }, required: ['traceId'] } },
              { name: 'get_alerts',           description: 'Get recent security alerts', inputSchema: { type: 'object', properties: { limit: { type: 'number' }, severity: { type: 'string' } } } },
              { name: 'search_spans',         description: 'Full-text search across all spans', inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'number' } }, required: ['query'] } },
              // Phase 15 / s68 — expanded tool coverage
              { name: 'tag_span',             description: 'Add a tag to a span', inputSchema: { type: 'object', properties: { spanId: { type: 'string' }, tag: { type: 'string' } }, required: ['spanId', 'tag'] } },
              { name: 'suppress_rule',        description: 'Snooze a detection rule for a duration', inputSchema: { type: 'object', properties: { ruleKey: { type: 'string', description: 'e.g. builtin-0 or custom:<id>' }, durationMs: { type: 'number', description: 'Snooze duration in milliseconds' } }, required: ['ruleKey', 'durationMs'] } },
              { name: 'bookmark_span',        description: 'Bookmark a span with an optional note', inputSchema: { type: 'object', properties: { spanId: { type: 'string' }, traceId: { type: 'string' }, note: { type: 'string' } }, required: ['spanId'] } },
              { name: 'get_processes',        description: 'List running AI agent processes on the local machine', inputSchema: { type: 'object', properties: {} } },
              { name: 'get_incident_summary', description: 'Summarise a session: spans, alerts, top threats, tags', inputSchema: { type: 'object', properties: { traceId: { type: 'string' } }, required: ['traceId'] } },
              { name: 'list_bookmarks',       description: 'List saved span bookmarks', inputSchema: { type: 'object', properties: { traceId: { type: 'string', description: 'Optional: filter by session traceId' } } } },
            ],
          });
          break;
        }
        case 'tools/call': {
          const toolName = String(params?.name ?? '');
          const args     = (params?.arguments ?? {}) as Record<string, unknown>;
          switch (toolName) {
            case 'get_health': {
              const spanCount    = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c;
              const sessionCount = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c;
              const alertCount2  = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c;
              const threatCount  = (db.prepare("SELECT COUNT(*) as c FROM spans WHERE severity != 'none'").get() as any).c;
              let dbSizeBytes = 0;
              try { dbSizeBytes = fs.statSync(DB_PATH).size; } catch {}
              ok({ content: [{ type: 'text', text: JSON.stringify({ status: 'ok', version: APP_VERSION, uptime: Date.now() - SERVER_START_MS, spanCount, sessionCount, alertCount: alertCount2, threatCount, dbSizeBytes }) }] });
              break;
            }
            case 'get_sessions': {
              // SECURITY: Use parameterized queries — never interpolate user input into SQL
              const labelFilter2 = args.label ? String(args.label) : null;
              const sessions = labelFilter2
                ? db.prepare(`
                    SELECT se.traceId, se.name, se.createdAt, se.label, se.notes,
                      COUNT(s.spanId) AS spanCount,
                      SUM(CASE WHEN s.severity != 'none' THEN 1 ELSE 0 END) AS threatCount,
                      GROUP_CONCAT(DISTINCT s.harness) AS harnesses
                    FROM sessions se LEFT JOIN spans s ON s.traceId = se.traceId
                    WHERE se.label = ?
                    GROUP BY se.traceId ORDER BY se.createdAt DESC LIMIT 50
                  `).all(labelFilter2)
                : db.prepare(`
                    SELECT se.traceId, se.name, se.createdAt, se.label, se.notes,
                      COUNT(s.spanId) AS spanCount,
                      SUM(CASE WHEN s.severity != 'none' THEN 1 ELSE 0 END) AS threatCount,
                      GROUP_CONCAT(DISTINCT s.harness) AS harnesses
                    FROM sessions se LEFT JOIN spans s ON s.traceId = se.traceId
                    GROUP BY se.traceId ORDER BY se.createdAt DESC LIMIT 50
                  `).all();
              ok({ content: [{ type: 'text', text: JSON.stringify(sessions) }] });
              break;
            }
            case 'get_spans': {
              const traceId = String(args.traceId ?? '');
              if (!traceId) { err(-32602, 'traceId required'); break; }
              const spans = db.prepare('SELECT spanId, name, severity, harness, startNano, endNano FROM spans WHERE traceId = ? ORDER BY startNano ASC LIMIT 200').all(traceId);
              ok({ content: [{ type: 'text', text: JSON.stringify(spans) }] });
              break;
            }
            case 'get_alerts': {
              const limit    = Math.min(Number(args.limit ?? 50), 200);
              const severity = args.severity ? String(args.severity) : null;
              const alertRows = severity
                ? db.prepare('SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ?').all(severity, limit)
                : db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT ?').all(limit);
              ok({ content: [{ type: 'text', text: JSON.stringify(alertRows) }] });
              break;
            }
            case 'search_spans': {
              const query = String(args.query ?? '').trim();
              const limit = Math.min(Number(args.limit ?? 50), 200);
              if (!query) { err(-32602, 'query required'); break; }
              // Push the filter into SQLite instead of loading every span and
              // matching in JS. Free text routes through the FTS5 index (split on
              // whitespace, prefix-match each term); a malformed FTS expression
              // falls back to a scoped LIKE rather than erroring.
              const terms = query.replace(/["']/g, ' ').split(/\s+/).filter(Boolean);
              let results: { spanId: string; traceId: string; name: string; severity: string; harness: string }[] = [];
              if (terms.length > 0) {
                const ftsQuery = terms.map(t => `"${t}"*`).join(' ');
                try {
                  results = db.prepare(
                    `SELECT spanId, traceId, name, severity, harness FROM spans
                     WHERE spanId IN (SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?)
                     ORDER BY startNano DESC LIMIT ?`
                  ).all(ftsQuery, limit) as typeof results;
                } catch {
                  const like = `%${query.replace(/[%_]/g, m => '\\' + m)}%`;
                  results = db.prepare(
                    `SELECT spanId, traceId, name, severity, harness FROM spans
                     WHERE name LIKE ? ESCAPE '\\' OR attributes LIKE ? ESCAPE '\\'
                     ORDER BY startNano DESC LIMIT ?`
                  ).all(like, like, limit) as typeof results;
                }
              }
              ok({ content: [{ type: 'text', text: JSON.stringify(results) }] });
              break;
            }

            // ── Phase 15 / s68 — expanded MCP tools ──────────────────────────

            case 'tag_span': {
              const spanId = String(args.spanId ?? '').trim();
              const tag    = String(args.tag    ?? '').trim();
              if (!spanId || !tag) { err(-32602, 'spanId and tag required'); break; }
              const span = db.prepare('SELECT spanId FROM spans WHERE spanId = ?').get(spanId);
              if (!span) { err(-32602, `Span not found: ${spanId}`); break; }
              try {
                db.prepare('INSERT OR IGNORE INTO span_tags (spanId, tag, createdAt) VALUES (?, ?, ?)').run(spanId, tag, new Date().toISOString());
                ok({ content: [{ type: 'text', text: JSON.stringify({ ok: true, spanId, tag }) }] });
              } catch (e: unknown) {
                err(-32603, e instanceof Error ? e.message : 'Insert failed');
              }
              break;
            }

            case 'suppress_rule': {
              const ruleKey    = String(args.ruleKey    ?? '').trim();
              const durationMs = Number(args.durationMs ?? 0);
              if (!ruleKey || durationMs <= 0) { err(-32602, 'ruleKey and positive durationMs required'); break; }
              const suppressUntil = new Date(Date.now() + durationMs).toISOString();
              db.prepare(
                `INSERT INTO suppressions (ruleKey, suppressUntil, createdAt) VALUES (?, ?, ?)
                 ON CONFLICT(ruleKey) DO UPDATE SET suppressUntil = excluded.suppressUntil, createdAt = excluded.createdAt`
              ).run(ruleKey, suppressUntil, new Date().toISOString());
              io.emit('suppressions-update');
              ok({ content: [{ type: 'text', text: JSON.stringify({ ok: true, ruleKey, suppressUntil }) }] });
              break;
            }

            case 'bookmark_span': {
              const spanId  = String(args.spanId  ?? '').trim();
              const traceId = String(args.traceId ?? '');
              const note    = String(args.note    ?? '');
              if (!spanId) { err(-32602, 'spanId required'); break; }
              const result2 = db.prepare(
                'INSERT INTO span_bookmarks (spanId, traceId, note, createdAt) VALUES (?, ?, ?, ?)'
              ).run(spanId, traceId, note, new Date().toISOString());
              io.emit('bookmarks-update');
              ok({ content: [{ type: 'text', text: JSON.stringify({ ok: true, id: result2.lastInsertRowid, spanId, traceId, note }) }] });
              break;
            }

            case 'get_processes': {
              const procData = scanAgentProcesses();
              ok({ content: [{ type: 'text', text: JSON.stringify(procData) }] });
              break;
            }

            case 'get_incident_summary': {
              const traceId2 = String(args.traceId ?? '').trim();
              if (!traceId2) { err(-32602, 'traceId required'); break; }
              const session3 = db.prepare('SELECT * FROM sessions WHERE traceId = ?').get(traceId2) as any;
              if (!session3) { err(-32602, `Session not found: ${traceId2}`); break; }
              const spans3   = db.prepare('SELECT * FROM spans WHERE traceId = ? ORDER BY startNano ASC').all(traceId2) as SpanRecord[];
              const alerts3  = db.prepare('SELECT * FROM alerts WHERE traceId = ? ORDER BY id DESC').all(traceId2) as any[];
              const tags3    = db.prepare('SELECT DISTINCT tag FROM span_tags WHERE spanId IN (SELECT spanId FROM spans WHERE traceId = ?)').all(traceId2) as any[];
              const bmarks3  = db.prepare('SELECT * FROM span_bookmarks WHERE traceId = ?').all(traceId2) as any[];

              const threatsByRule: Record<string, number> = {};
              for (const a of alerts3) { threatsByRule[a.ruleLabel] = (threatsByRule[a.ruleLabel] ?? 0) + 1; }
              const topThreats = Object.entries(threatsByRule).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([rule, count]) => ({ rule, count }));

              const harnesses = [...new Set(spans3.map(s => s.harness))];
              const severity = alerts3.some(a => a.severity === 'critical') ? 'critical'
                : alerts3.some(a => a.severity === 'high') ? 'high'
                : alerts3.some(a => a.severity === 'medium') ? 'medium'
                : alerts3.some(a => a.severity === 'low') ? 'low'
                : 'none';

              ok({ content: [{ type: 'text', text: JSON.stringify({
                traceId:   traceId2,
                name:      session3.name,
                label:     session3.label,
                notes:     session3.notes,
                severity,
                spanCount: spans3.length,
                alertCount: alerts3.length,
                harnesses,
                topThreats,
                tags:       tags3.map((t: any) => t.tag),
                bookmarks:  bmarks3.length,
                startTime:  spans3[0]?.startNano ? new Date(Number(BigInt(spans3[0].startNano) / 1_000_000n)).toISOString() : null,
              }) }] });
              break;
            }

            case 'list_bookmarks': {
              const filterTraceId = args.traceId ? String(args.traceId) : null;
              const bmarks = filterTraceId
                ? db.prepare('SELECT * FROM span_bookmarks WHERE traceId = ? ORDER BY id DESC').all(filterTraceId)
                : db.prepare('SELECT * FROM span_bookmarks ORDER BY id DESC LIMIT 100').all();
              ok({ content: [{ type: 'text', text: JSON.stringify(bmarks) }] });
              break;
            }

            default:
              err(-32601, `Unknown tool: ${toolName}`);
          }
          break;
        }
        // MCP initialize handshake
        case 'initialize': {
          ok({
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'claudesec', version: APP_VERSION },
          });
          break;
        }
        default:
          err(-32601, `Method not found: ${method}`);
      }
    } catch (e: unknown) {
      err(-32603, e instanceof Error ? e.message : 'Internal error');
    }
  });

  // ── Threshold alert rules ────────────────────────────────────────────────
  registerThresholdRuleRoutes(app, { io, auditLog });

  // ── OTEL Collector config generator ─────────────────────────────────────
  app.get('/api/collector-config', (_req, res) => {
    const yaml = `# OpenTelemetry Collector configuration for ClaudeSec
# Generated by ClaudeSec v${APP_VERSION} — https://github.com/aanjaneyasinghdhoni/ClaudeSec
#
# Usage:
#   docker run --rm -p 4317:4317 -p 4318:4318 \\
#     -v $(pwd)/otel-collector-config.yaml:/etc/otelcol/config.yaml \\
#     otel/opentelemetry-collector-contrib:latest
#
# Then point your agent to the collector instead of ClaudeSec directly:
#   OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 64
  batch:
    timeout: 200ms
    send_batch_size: 100
    send_batch_max_size: 500

exporters:
  otlphttp:
    endpoint: http://host.docker.internal:${PORT}
    tls:
      insecure: true
  debug:
    verbosity: basic

service:
  pipelines:
    traces:
      receivers:  [otlp]
      processors: [memory_limiter, batch]
      exporters:  [otlphttp, debug]
`;
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="otel-collector-config.yaml"');
    res.send(yaml);
  });

  // ── Config read/write ─────────────────────────────────────────────────────
  app.get('/api/config', (_req, res) => {
    res.json({
      maxSpans:       getMaxSpans(),
      retentionDays:  getRetentionDays(),
      rateLimitRps:   RATE_LIMIT_RPS,
      rateLimitBurst: RATE_LIMIT_BURST,
      maxSpansBatch:  MAX_SPANS_PER_BATCH,
      webhookUrl:     getWebhookUrl() ? '***' : null,
      webhookThreshold: getWebhookThreshold(),
    });
  });

  app.get('/api/config/env-reference', (_req, res) => {
    const envVars = [
      // Agent telemetry — Claude Code
      { key: 'CLAUDE_CODE_ENABLE_TELEMETRY',         description: 'Enable Claude Code OTLP trace export',                          default: '',   category: 'Agent Setup' },
      { key: 'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA',  description: 'Enable LLM request spans with model name + token counts',       default: '',   category: 'Agent Setup' },
      { key: 'OTEL_LOG_TOOL_DETAILS',                description: 'Include tool names and input arguments in spans',               default: '',   category: 'Agent Setup' },
      { key: 'OTEL_LOG_TOOL_CONTENT',                description: 'Include full tool input/output bodies (up to 60KB)',             default: '',   category: 'Agent Setup' },
      { key: 'OTEL_LOG_RAW_API_BODIES',              description: 'Include raw Anthropic Messages API request/response JSON',      default: '',   category: 'Agent Setup' },
      // ClaudeSec server
      { key: 'CLAUDESEC_RATE_LIMIT_RPS',    description: 'Max OTLP requests per second per IP',     default: '50',     category: 'Performance' },
      { key: 'CLAUDESEC_RATE_LIMIT_BURST',   description: 'Token bucket burst capacity',              default: '200',    category: 'Performance' },
      { key: 'CLAUDESEC_MAX_SPANS_BATCH',    description: 'Max spans allowed per OTLP batch',         default: '500',    category: 'Performance' },
      { key: 'CLAUDESEC_GRAPH_LIMIT',        description: 'How many of the most-recent spans the live graph renders (older spans stay available via Search/Sessions)', default: '2000', category: 'Performance' },
      { key: 'CLAUDESEC_MAX_SPANS',          description: 'Total span capacity before pruning',       default: '50000',  category: 'Retention' },
      { key: 'CLAUDESEC_RETENTION_DAYS',     description: 'Days to keep data before age-based prune', default: '30',     category: 'Retention' },
      { key: 'CLAUDESEC_WEBHOOK_URL',        description: 'Webhook endpoint for alert delivery',      default: '',       category: 'Alerts',   sensitive: true },
      { key: 'CLAUDESEC_WEBHOOK_THRESHOLD',  description: 'Minimum severity to trigger webhook',      default: 'high',   category: 'Alerts' },
      { key: 'CLAUDESEC_CORS_ORIGINS',       description: 'Comma-separated allowed CORS origins',     default: 'localhost', category: 'Security' },
      { key: 'CLAUDESEC_TOKEN',              description: 'Bearer token required for non-loopback API/MCP access; required to bind a non-loopback host', default: '', category: 'Security', sensitive: true },
      { key: 'CLAUDESEC_TRUST_LOCAL',        description: 'Set to "1" to disable the loopback-address auth check and trust all clients (opt-in; default off). Use ONLY when host exposure is restricted, e.g. Docker with 127.0.0.1-only port binding.', default: '', category: 'Security' },
      { key: 'CLAUDESEC_MODE',               description: 'Enforcement mode for the opt-in PreToolUse hook: "monitor" logs would-block events (default), "enforce" actually blocks high-severity matches', default: 'monitor', category: 'Security' },
      { key: 'CLAUDESEC_TRUST_PROXY',        description: 'Trust X-Forwarded-For headers (set to 1)', default: '',       category: 'Security' },
      { key: 'CLAUDESEC_HONEYTOKENS',        description: 'Comma-separated canary strings for exfiltration detection', default: '', category: 'Security', sensitive: true },
      { key: 'CLAUDESEC_AUTO_EXPORT_DIR',    description: 'Directory for hourly auto-export JSON snapshots',           default: './exports', category: 'Export' },
      { key: 'OTEL_FORWARD_URL',             description: 'Forward OTLP traces to upstream collector', default: '',      category: 'Integration' },
      // Optional LLM-as-judge semantic detection (OFF by default — no URL = no egress)
      { key: 'CLAUDESEC_JUDGE_URL',          description: 'Optional LLM-as-judge endpoint (OpenAI-compatible /chat/completions; recommended: local Ollama http://localhost:11434/v1). OFF by default.', default: '', category: 'Detection' },
      { key: 'CLAUDESEC_JUDGE_MODEL',        description: 'Model name for the LLM-as-judge (e.g. llama3.1)',           default: 'llama3.1', category: 'Detection' },
      { key: 'CLAUDESEC_JUDGE_KEY',          description: 'Optional bearer key for the judge endpoint (not needed for local Ollama)', default: '', category: 'Detection', sensitive: true },
      { key: 'CLAUDESEC_JUDGE_TIMEOUT_MS',   description: 'Per-request LLM-as-judge timeout in milliseconds (capped at 60000)', default: '8000', category: 'Detection' },
    ];

    const enriched = envVars.map(v => ({
      ...v,
      currentValue: (v as any).sensitive
        ? (process.env[v.key] ? '***' : '')
        : (process.env[v.key] ?? ''),
      isSet: !!process.env[v.key],
    }));

    res.json({ envVars: enriched });
  });

  // ── Live config / enablement status ───────────────────────────────────────
  // Reports the RUNTIME state of each setting — not just whether the env var is
  // present, but whether the feature it controls is actually active vs. its
  // default/off state, plus a UI-friendly state label. Computed server-side
  // from process.env + derived signals (recent enforce events, token-bearing
  // telemetry spans). Secrets are masked. Poll this to live-refresh the UI.
  app.get('/api/config/status', (_req, res) => {
    type StateLabel = 'active' | 'default' | 'off' | 'caution';
    interface SettingStatus {
      key: string;
      category: string;
      description: string;
      isSet: boolean;          // env var present
      effectiveValue: string;  // actual runtime value or default (secrets masked)
      enabled: boolean;        // feature active vs default/off
      state: StateLabel;       // active | default | off | caution
      detail?: string;         // extra human-readable context
    }
    const settings: SettingStatus[] = [];

    // — Enforcement —
    const mode = (process.env.CLAUDESEC_MODE ?? 'monitor').toLowerCase();
    const isEnforce = mode === 'enforce';
    settings.push({
      key: 'CLAUDESEC_MODE',
      category: 'Enforcement',
      description: 'PreToolUse hook mode: "enforce" actively blocks high-severity tool calls; "monitor" (default) only logs would-block events.',
      isSet: !!process.env.CLAUDESEC_MODE,
      effectiveValue: isEnforce ? 'enforce' : 'monitor',
      enabled: isEnforce,
      state: isEnforce ? 'active' : 'default',
      detail: isEnforce ? 'High-severity tool calls are blocked.' : 'Logging only — nothing is blocked.',
    });

    // Recent enforcement activity (persisted to SQLite; survives restart)
    const ENFORCE_WINDOW_MS = 24 * 60 * 60 * 1000;
    const recentEnforce = enforceLogRecentCount(ENFORCE_WINDOW_MS);
    const totalEnforce = persistedEnforceLogCount();
    settings.push({
      key: 'enforce-log',
      category: 'Enforcement',
      description: 'Enforcement events reported by the PreToolUse hook in the last 24h (persisted, tamper-evident; survives restart).',
      isSet: totalEnforce > 0,
      effectiveValue: recentEnforce > 0 ? `${recentEnforce} event${recentEnforce === 1 ? '' : 's'} (24h)` : 'no recent events',
      enabled: recentEnforce > 0,
      state: recentEnforce > 0 ? 'active' : 'off',
      detail: totalEnforce > 0 ? `${totalEnforce} total persisted.` : 'No hook events received yet.',
    });

    // — Security —
    const token = process.env.CLAUDESEC_TOKEN ?? '';
    const tokenSet = !!token;
    const host = process.env.CLAUDESEC_HOST ?? '127.0.0.1';
    const hostLoopback = host === 'localhost' || isLoopbackAddr(host);
    // Token: set → remote auth required (active). Unset + non-loopback host →
    // caution (data exposed). Unset + loopback → default (safe local-only).
    settings.push({
      key: 'CLAUDESEC_TOKEN',
      category: 'Security',
      description: 'Bearer token required for non-loopback API/MCP access. When set, remote requests must authenticate.',
      isSet: tokenSet,
      effectiveValue: tokenSet ? '••• (set)' : 'unset',
      enabled: tokenSet,
      state: tokenSet ? 'active' : (hostLoopback ? 'default' : 'caution'),
      detail: tokenSet
        ? 'Remote API/MCP requests require this token.'
        : (hostLoopback ? 'Not needed — server is loopback-only.' : 'Host is non-loopback but no token is set — data is exposed.'),
    });

    const resetEnabled = process.env.CLAUDESEC_ALLOW_RESET === '1';
    settings.push({
      key: 'CLAUDESEC_ALLOW_RESET',
      category: 'Security',
      description: 'When "1", POST /api/reset can wipe the entire spans database. Disabled by default to prevent accidental data loss.',
      isSet: !!process.env.CLAUDESEC_ALLOW_RESET,
      effectiveValue: resetEnabled ? '1 (reset enabled)' : 'disabled',
      enabled: resetEnabled,
      state: resetEnabled ? 'caution' : 'off',
      detail: resetEnabled ? 'Destructive reset endpoint is ENABLED.' : 'Data-wipe endpoint is disabled (safe).',
    });

    settings.push({
      key: 'CLAUDESEC_HOST',
      category: 'Security',
      description: 'Network interface the server binds to. 127.0.0.1 (default) is local-only; 0.0.0.0 exposes the dashboard to the network.',
      isSet: !!process.env.CLAUDESEC_HOST,
      effectiveValue: host,
      enabled: !hostLoopback,
      state: hostLoopback ? 'default' : 'caution',
      detail: hostLoopback ? 'Loopback-only — not reachable from the network.' : 'Bound to a non-loopback interface — reachable from the network.',
    });

    const scrubEnabled = scrubOptions.enabled;
    const scrubDisabledByEnv = process.env.CLAUDESEC_DISABLE_SCRUB === '1';
    settings.push({
      key: 'CLAUDESEC_DISABLE_SCRUB',
      category: 'Security',
      description: 'Report scrubbing redacts home paths, usernames, emails and sensitive attribute keys from captured spans. "1" turns it OFF.',
      isSet: !!process.env.CLAUDESEC_DISABLE_SCRUB,
      effectiveValue: scrubEnabled ? 'scrubbing ON' : 'scrubbing OFF',
      enabled: scrubEnabled,
      state: scrubEnabled ? 'active' : 'caution',
      detail: scrubDisabledByEnv ? 'Scrubbing disabled via env — raw PII may be stored.' : (scrubEnabled ? 'PII is redacted from captured spans.' : 'Scrubbing is off.'),
    });

    // — Telemetry —
    // Enhanced telemetry (CLAUDE_CODE_ENHANCED_TELEMETRY_BETA) lives in the
    // agent's process — we can't read its env. Derive it from the data: if any
    // recent span carries token-usage attributes, enhanced llm_request spans are
    // arriving. Bounded query (most recent 200 spans) so this stays cheap; an
    // empty DB simply yields "off".
    let enhancedActive = false;
    try {
      const recentSpans = db.prepare(
        `SELECT attributes FROM spans ORDER BY CAST(startNano AS INTEGER) DESC LIMIT 200`
      ).all() as { attributes: string }[];
      for (const row of recentSpans) {
        let a: Record<string, unknown> = {};
        try { a = JSON.parse(row.attributes); } catch { continue; }
        const ti = Number(a['gen_ai.usage.input_tokens'] ?? a['llm.usage.input_tokens'] ?? 0);
        const to = Number(a['gen_ai.usage.output_tokens'] ?? a['llm.usage.output_tokens'] ?? 0);
        if (ti > 0 || to > 0) { enhancedActive = true; break; }
      }
    } catch { enhancedActive = false; }
    settings.push({
      key: 'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA',
      category: 'Telemetry',
      description: 'Enables llm_request spans with model name + token counts on the connected agent. Derived from incoming data (token-bearing spans), not this process’s env.',
      isSet: enhancedActive,
      effectiveValue: enhancedActive ? 'active (token spans arriving)' : 'no token spans seen',
      enabled: enhancedActive,
      state: enhancedActive ? 'active' : 'off',
      detail: enhancedActive ? 'Recent spans include token counts — enhanced telemetry is on.' : 'No recent spans carry token counts.',
    });

    const watchEnabled = process.env.CLAUDESEC_WATCH !== '0';
    settings.push({
      key: 'CLAUDESEC_WATCH',
      category: 'Telemetry',
      description: 'Zero-config filesystem watcher that auto-captures Claude Code & Codex transcripts. On by default; set "0" to disable.',
      isSet: !!process.env.CLAUDESEC_WATCH,
      effectiveValue: watchEnabled ? 'on' : 'off (CLAUDESEC_WATCH=0)',
      enabled: watchEnabled,
      state: watchEnabled ? 'active' : 'off',
      detail: watchEnabled ? 'Auto-capturing local agent transcripts.' : 'Filesystem watcher disabled.',
    });

    const forwardUrl = process.env.OTEL_FORWARD_URL ?? (getConfig.get('otel.forward.url')?.value ?? '');
    const forwardSet = !!forwardUrl;
    settings.push({
      key: 'OTEL_FORWARD_URL',
      category: 'Telemetry',
      description: 'Transparently forwards every received OTLP batch to an upstream collector.',
      isSet: !!process.env.OTEL_FORWARD_URL,
      effectiveValue: forwardSet ? maskWebhookUrl(forwardUrl) : 'not configured',
      enabled: forwardSet,
      state: forwardSet ? 'active' : 'off',
      detail: forwardSet ? 'OTLP traces are forwarded upstream.' : 'No upstream forwarding.',
    });

    // — Detection: optional LLM-as-judge —
    // OFF by default. Reports whether a semantic judge endpoint is configured.
    // The endpoint is masked (origin only) and the API key is NEVER echoed.
    const judgeCfg = getJudgeConfig();
    const judgeOn = judgeCfg !== null;
    const judgeLoopback = judgeOn ? isLoopbackAddr(
      (() => { try { return new URL(judgeCfg!.url).hostname.replace(/^\[|\]$/g, ''); } catch { return ''; } })()
    ) || (() => { try { return new URL(judgeCfg!.url).hostname.toLowerCase() === 'localhost'; } catch { return false; } })()
      : false;
    settings.push({
      key: 'CLAUDESEC_JUDGE_URL',
      category: 'Detection',
      description: 'Optional LLM-as-judge semantic detector. When set to an OpenAI-compatible /chat/completions endpoint (recommended: a LOCAL Ollama), spans can be classified as prompt-injection / jailbreak / exfiltration on demand. OFF by default — no judge URL means no outbound calls.',
      isSet: !!process.env.CLAUDESEC_JUDGE_URL,
      effectiveValue: judgeOn ? maskWebhookUrl(judgeCfg!.url) : 'not configured',
      enabled: judgeOn,
      state: judgeOn ? 'active' : 'off',
      detail: judgeOn
        ? `Judge active (model: ${judgeCfg!.model}${judgeCfg!.key ? ', key set' : ''})${judgeLoopback ? ' — loopback/no-egress.' : ' — non-loopback, SSRF-guarded.'}`
        : 'No semantic judge — regex rules only. Set CLAUDESEC_JUDGE_URL (e.g. a local Ollama) to enable.',
    });

    // — Retention —
    const maxSpansEnv = Number(process.env.CLAUDESEC_MAX_SPANS) > 0;
    const maxSpans = getMaxSpans();
    settings.push({
      key: 'CLAUDESEC_MAX_SPANS',
      category: 'Retention',
      description: 'Total span capacity before the oldest spans are pruned.',
      isSet: maxSpansEnv,
      effectiveValue: `${maxSpans.toLocaleString()} spans`,
      enabled: true,
      state: 'active',
      detail: maxSpansEnv ? 'Limit set via env.' : 'Using configured/default limit.',
    });

    const retentionEnv = Number(process.env.CLAUDESEC_RETENTION_DAYS) > 0;
    const retentionDays = getRetentionDays();
    settings.push({
      key: 'CLAUDESEC_RETENTION_DAYS',
      category: 'Retention',
      description: 'Age-based pruning — spans older than this many days are removed.',
      isSet: retentionEnv,
      effectiveValue: `${retentionDays} day${retentionDays === 1 ? '' : 's'}`,
      enabled: true,
      state: 'active',
      detail: retentionEnv ? 'Window set via env.' : 'Using configured/default window.',
    });

    // — Integrations —
    const webhookUrl = getWebhookUrl();
    const webhookSet = !!webhookUrl;
    settings.push({
      key: 'CLAUDESEC_WEBHOOK_URL',
      category: 'Integrations',
      description: 'Webhook endpoint that receives alert deliveries (Slack, Discord, or generic JSON).',
      isSet: !!process.env.CLAUDESEC_WEBHOOK_URL,
      effectiveValue: webhookSet ? maskWebhookUrl(webhookUrl) : 'not configured',
      enabled: webhookSet,
      state: webhookSet ? 'active' : 'off',
      detail: webhookSet ? `Alerts ≥ ${getWebhookThreshold()} are delivered.` : 'No webhook configured.',
    });

    const honeytokenCount = loadHoneytokens().length;
    settings.push({
      key: 'CLAUDESEC_HONEYTOKENS',
      category: 'Integrations',
      description: 'Canary strings that raise a high-severity alert if they ever appear in captured agent output (exfiltration tripwire).',
      isSet: honeytokenCount > 0,
      effectiveValue: honeytokenCount > 0 ? `${honeytokenCount} token${honeytokenCount === 1 ? '' : 's'} • •••` : 'none set',
      enabled: honeytokenCount > 0,
      state: honeytokenCount > 0 ? 'active' : 'off',
      detail: honeytokenCount > 0 ? 'Exfiltration tripwire armed.' : 'No honeytokens configured.',
    });

    // Summary counts for header chips
    const summary = {
      active:  settings.filter(s => s.state === 'active').length,
      caution: settings.filter(s => s.state === 'caution').length,
      off:     settings.filter(s => s.state === 'off').length,
      default: settings.filter(s => s.state === 'default').length,
    };

    const categoryOrder = ['Enforcement', 'Security', 'Detection', 'Telemetry', 'Retention', 'Integrations'];
    res.json({ settings, summary, categoryOrder, generatedAt: new Date().toISOString() });
  });

  // ── Span metadata: annotations + custom tags (s62) ────────────────────────
  registerSpanMetaRoutes(app, { io });

  // ── Reset ────────────────────────────────────────────────────────────────
  app.post('/api/reset', (req, res) => {
    // SAFETY: data wipe is DISABLED by default — prevents accidental destruction
    // of the spans database. Set CLAUDESEC_ALLOW_RESET=1 to explicitly permit it.
    if (process.env.CLAUDESEC_ALLOW_RESET !== '1') {
      res.status(403).json({ error: 'reset disabled', hint: 'Set CLAUDESEC_ALLOW_RESET=1 to enable /api/reset' });
      return;
    }
    auditLog(req, 'data.reset', 'all', {});
    deleteAllSpans.run();
    deleteAllSessions.run();
    deleteAllAlerts.run();
    deleteAllAnnotations.run();
    db.prepare('DELETE FROM spans_fts').run();
    db.prepare('DELETE FROM webhook_deliveries').run();
    db.prepare('DELETE FROM span_tags').run();
    db.prepare('DELETE FROM span_bookmarks').run();
    io.emit('graph-update', buildGraph());
    io.emit('sessions-update');
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });

  // ── Clear demo data ──────────────────────────────────────────────────────
  // Removes ONLY the synthetic demo rows (traceId / spanId prefixed "demo-").
  // Safe by construction — it can never match real telemetry — so unlike
  // /api/reset it needs no CLAUDESEC_ALLOW_RESET gate. It still sits behind the
  // general /api auth gate above (loopback-open, token-required for remote), so
  // a non-loopback caller without CLAUDESEC_TOKEN cannot reach it. This backs the
  // in-app "Clear demo data" button for anyone who launched the demo and wants a
  // clean slate. Demo seeding only creates spans, sessions, and alerts, so those
  // (plus the FTS mirror) are the only tables to touch.
  app.post('/api/demo/clear', (req, res) => {
    const demoSpans    = (db.prepare("SELECT COUNT(*) AS c FROM spans    WHERE traceId LIKE 'demo-%'").get() as { c: number }).c;
    const demoSessions = (db.prepare("SELECT COUNT(*) AS c FROM sessions WHERE traceId LIKE 'demo-%'").get() as { c: number }).c;
    auditLog(req, 'data.demo-clear', 'demo-*', { demoSpans, demoSessions });
    db.transaction(() => {
      db.prepare("DELETE FROM spans_fts WHERE spanId IN (SELECT spanId FROM spans WHERE traceId LIKE 'demo-%')").run();
      db.prepare("DELETE FROM spans    WHERE traceId LIKE 'demo-%'").run();
      db.prepare("DELETE FROM sessions WHERE traceId LIKE 'demo-%'").run();
      db.prepare("DELETE FROM alerts   WHERE traceId LIKE 'demo-%'").run();
    })();
    io.emit('graph-update', buildGraph());
    io.emit('sessions-update');
    io.emit('alerts-update');
    res.json({ status: 'ok', clearedSpans: demoSpans, clearedSessions: demoSessions });
  });

  // ── Enforcement event log + config (PreToolUse hook feed) ──────────────────
  registerEnforceRoutes(app, {
    io,
    // Scrub free-form enforcement-log text the same way span text is scrubbed
    // before insert: the PreToolUse hook forwards the matched command/content
    // verbatim (home paths, secrets included), so it must pass through the live
    // scrubOptions — honouring CLAUDESEC_DISABLE_SCRUB — before it is stored or
    // broadcast.
    scrubEnforceText: (s: string) => scrubText(s, scrubOptions),
    // Persisted, tamper-evident enforce feed (server/enforceLogStore.ts) —
    // survives restart. The route + Socket.io broadcast are unchanged.
    appendEnforceLog: persistEnforceLog,
    readEnforceLog: readPersistedEnforceLog, // most-recent first
    enforceLogCount: persistedEnforceLogCount,
    enforceLogMax: ENFORCE_LOG_MAX,
    getEnforceMode,
    getEnforceOverrides,
    writeEnforceConfigFile,
    enforceConfigFile: ENFORCE_CONFIG_FILE,
    auditLog,
  });

  // ── MCP / skill static scanner ───────────────────────────────────────────
  registerMcpScanRoutes(app, { io, detectSeverity });

  // ── Rules CRUD ───────────────────────────────────────────────────────────
  registerRuleRoutes(app, {
    io,
    getCustomRules: () => customRules,
    addCustomRule: (rule) => {
      customRules.push(rule);
      saveCustomRules();
      writeEnforcementSnapshot(); // mirror live so a high/critical rule blocks in enforce
    },
    removeCustomRule: (id) => {
      const idx = customRules.findIndex(r => r.id === id);
      if (idx === -1) return false;
      customRules.splice(idx, 1);
      saveCustomRules();
      writeEnforcementSnapshot();
      return true;
    },
    auditLog,
  });

  // ── Protected paths (user-defined always-on block list) ───────────────────
  registerProtectedPathRoutes(app, {
    io,
    getProtectedPaths: () => protectedPaths,
    addProtectedPath: (entry) => {
      protectedPaths.push(entry);
      saveProtectedPaths();
      writeProtectedPathsArtifact(); // mirror live so the hook picks it up immediately
    },
    removeProtectedPath: (id) => {
      const idx = protectedPaths.findIndex(p => p.id === id);
      if (idx === -1) return false;
      protectedPaths.splice(idx, 1);
      saveProtectedPaths();
      writeProtectedPathsArtifact();
      return true;
    },
    auditLog,
  });

  // ── Per-rule enable/disable overrides ─────────────────────────────────────
  registerRuleOverrideRoutes(app, {
    io,
    invalidateDisabledRulesCache,
    getCustomRules: () => customRules,
    auditLog,
  });

  // ── Operator audit log (read-only) ────────────────────────────────────────
  registerAuditLogRoutes(app, { io });
  // ── Tamper-evidence: verify the audit + enforce hash chains (read-only) ────
  registerAuditVerifyRoutes(app, { io });

  // ── Alerts ───────────────────────────────────────────────────────────────
  registerAlertRoutes(app, { io });

  // ── Orchestration ────────────────────────────────────────────────────────
  registerOrchestrationRoutes(app, { io });

  // ── DB stats + retention config ──────────────────────────────────────────
  registerDbStatsRoutes(app, { io, getMaxSpans, getRetentionDays, pruneSpans, buildGraph, auditLog });

  // ── Health check ────────────────────────────────────────────────────────
  // ── Command audit trail — all tool executions with risk scores ────────
  registerCommandAuditRoutes(app, { io });

  registerFileAccessRoutes(app, { io });

  // ── Live agent activity — what each agent is doing right now ──────────
  registerLiveActivityRoutes(app, { io });

  app.get('/api/health', (_req, res) => {
    const spansTotal    = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    const threatsTotal  = (db.prepare("SELECT COUNT(*) as c FROM spans WHERE severity != 'none'").get() as any).c as number;
    const sessionsTotal = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c as number;
    const alertsTotal   = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c as number;
    // Count of synthetic demo sessions (traceId prefixed "demo-"). Lets the UI
    // show a "this is demo data" banner and an ungated one-click clear.
    const demoSessions  = (db.prepare("SELECT COUNT(*) as c FROM sessions WHERE traceId LIKE 'demo-%'").get() as any).c as number;
    let dbSizeBytes = 0;
    try { dbSizeBytes = fs.statSync(DB_PATH).size; } catch {}
    const annotationsTotal = (db.prepare('SELECT COUNT(*) as c FROM annotations').get() as any).c as number;
    res.json({
      status:      'ok',
      version:     APP_VERSION,
      uptimeMs:    Date.now() - SERVER_START_MS,
      uptime:      (Date.now() - SERVER_START_MS) / 1000,
      spans:       spansTotal,
      spansTotal,
      threats:     threatsTotal,
      threatsTotal,
      sessions:    sessionsTotal,
      sessionsTotal,
      alerts:      alertsTotal,
      alertsTotal,
      annotations: annotationsTotal,
      demoSessions,
      resetEnabled: process.env.CLAUDESEC_ALLOW_RESET === '1',
      dbSizeBytes,
      webhookConfigured: !!getWebhookUrl(),
      webhookThreshold:  getWebhookThreshold(),
      retention: {
        maxSpans:      getMaxSpans(),
        retentionDays: getRetentionDays(),
      },
      rateLimiting: {
        rps:           RATE_LIMIT_RPS,
        burst:         RATE_LIMIT_BURST,
        maxSpansBatch: MAX_SPANS_PER_BATCH,
      },
      otelForwarding: {
        configured: !!(process.env.OTEL_FORWARD_URL ?? getConfig.get('otel.forward.url')?.value),
        ...forwardStats,
      },
      autoExport: {
        enabled:     true,
        dir:         '[redacted]',
        lastExportAt: lastAutoExportAt || null,
      },
      builtInRules: SEVERITY_RULES.length,
    });
  });

  // ── Prometheus metrics ───────────────────────────────────────────────────
  app.get('/metrics', (_req, res) => {
    // Aggregate in SQL (GROUP BY harness / severity, json_extract for tokens)
    // so /metrics stays O(distinct harnesses) instead of scanning every span.
    const spansPerHarness = new Map<string, number>();
    const threatsPerHarnessSev = new Map<string, number>();
    const tokensIn  = new Map<string, number>();
    const tokensOut = new Map<string, number>();

    for (const row of db.prepare(`SELECT harness, COUNT(*) AS c FROM spans GROUP BY harness`).all() as { harness: string; c: number }[]) {
      spansPerHarness.set(row.harness, row.c);
    }
    for (const row of db.prepare(`SELECT harness, severity, COUNT(*) AS c FROM spans WHERE severity != 'none' GROUP BY harness, severity`).all() as { harness: string; severity: string; c: number }[]) {
      threatsPerHarnessSev.set(`${row.harness}::${row.severity}`, row.c);
    }
    // Token counters on the deduped, cache-aware, demo-excluded basis shared with
    // the Cost tab — so a Prometheus dashboard built on these counters matches the
    // UI instead of double-counting duplicate transcript lines or synthetic data.
    for (const [harness, t] of dedupedTokenTotals('harness')) {
      if (t.tokensIn)  tokensIn.set(harness,  t.tokensIn);
      if (t.tokensOut) tokensOut.set(harness, t.tokensOut);
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

  // ── Webhook config + delivery log ──────────────────────────────────────────
  registerWebhookRoutes(app, {
    io,
    getWebhookUrl,
    getWebhookThreshold,
    maskWebhookUrl,
    fireWebhook,
    auditLog,
  });

  // ── Token cost estimation + cost trend ────────────────────────────────────
  registerCostRoutes(app, { io, lookupPricing, MODEL_PRICING });

  // ── Full-text search (s54) ───────────────────────────────────────────────
  registerSearchRoutes(app, { io });

  // ── Match ranges — byte offsets of the first matching rule per span ────
  // Lets the UI highlight exactly what triggered a severity flag instead of
  // making the analyst re-scan the whole attributes blob.
  app.get('/api/spans/:spanId/match', (req, res) => {
    const row = db.prepare('SELECT * FROM spans WHERE spanId = ?').get(req.params.spanId) as SpanRecord | undefined;
    if (!row) {
      res.status(404).json({ error: 'span not found' });
      return;
    }
    const searchText = row.attributes + ' ' + row.name;
    const hit = detectSeverity(searchText);
    res.json({
      spanId:       row.spanId,
      severity:     hit.severity,
      matchedLabel: hit.matchedLabel,
      matchedText:  hit.matchedText,
      matchStart:   hit.matchStart,
      matchEnd:     hit.matchEnd,
      ruleKey:      hit.ruleKey,
    });
  });

  // ── LLM-as-judge (optional, opt-in, local-first) ─────────────────────────
  registerJudgeRoutes(app, { io });

  // ── Honeytokens ────────────────────────────────────────────────────────
  // Operator-planted canary strings that should never appear in legitimate
  // telemetry.  Any match fires a HIGH-severity "Honeytoken exfiltration"
  // alert regardless of other rules.  The scrubOptions mutation stays in these
  // index.ts closures so the binding the ingest hot path reads stays in sync.
  registerHoneytokenRoutes(app, {
    io,
    getHoneytokens: () => loadHoneytokens(),
    saveHoneytokens: (tokens) => saveHoneytokens(tokens),
    clearHoneytokens: () => {
      delConfig.run('honeytokens');
      scrubOptions = loadScrubOptions([]);
    },
    auditLog,
  });

  // ── Scrub status (read-only) ───────────────────────────────────────────
  registerScrubRoutes(app, {
    io,
    getScrubEnabled: () => scrubOptions.enabled,
    getHoneytokens: () => loadHoneytokens(),
  });

  // ── Local agent process scanner / kill switch (s64, s71) ──────────────────
  registerProcessRoutes(app, { io });

  // ── Span bookmarks (s67) ──────────────────────────────────────────────────
  registerBookmarkRoutes(app, { io });

  // ── Graph export — Mermaid & Graphviz DOT (s59) ──────────────────────────
  app.get('/api/graph/mermaid', (req, res) => {
    const session = req.query.session ? String(req.query.session) : undefined;
    const records: SpanRecord[] = session
      ? (db.prepare('SELECT * FROM spans WHERE traceId = ?').all(session) as SpanRecord[])
      : (getAllSpans.all() as SpanRecord[]);

    const lines: string[] = ['flowchart TD'];
    const seen = new Set<string>();

    for (const r of records) {
      const nodeId  = r.spanId.replace(/[^a-zA-Z0-9_]/g, '_');
      const label   = r.name.replace(/"/g, "'").slice(0, 60);
      const style   = r.severity === 'high'   ? ':::high'
                    : r.severity === 'medium' ? ':::medium'
                    : r.severity === 'low'    ? ':::low' : '';
      if (!seen.has(nodeId)) {
        lines.push(`    ${nodeId}["${label}"]${style}`);
        seen.add(nodeId);
      }
      // Edge
      const parentId = r.parentId.replace(/[^a-zA-Z0-9_]/g, '_');
      if (r.parentId && r.parentId !== r.spanId) {
        lines.push(`    ${parentId} --> ${nodeId}`);
      }
    }

    // Severity class definitions
    lines.push(
      '    classDef high   fill:#450a0a,stroke:#ef4444,color:#fca5a5',
      '    classDef medium fill:#431407,stroke:#f97316,color:#fdba74',
      '    classDef low    fill:#422006,stroke:#eab308,color:#fde047',
    );

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(lines.join('\n'));
  });

  app.get('/api/graph/dot', (req, res) => {
    const session = req.query.session ? String(req.query.session) : undefined;
    const records: SpanRecord[] = session
      ? (db.prepare('SELECT * FROM spans WHERE traceId = ?').all(session) as SpanRecord[])
      : (getAllSpans.all() as SpanRecord[]);

    const lines: string[] = [
      'digraph ClaudeSec {',
      '  graph [rankdir=TB bgcolor="#0f172a" fontname="system-ui"]',
      '  node  [shape=box style="filled,rounded" fontname="system-ui" fontsize=11 fontcolor="#e2e8f0"]',
      '  edge  [color="#64748b" fontname="system-ui" fontsize=9]',
    ];

    const seen = new Set<string>();
    const colorMap: Record<Severity, string> = {
      critical: '#4c0519', high: '#450a0a', medium: '#431407', low: '#422006', none: '#1e293b',
    };
    const borderMap: Record<Severity, string> = {
      critical: '#f43f5e', high: '#ef4444', medium: '#f97316', low: '#eab308', none: '#334155',
    };

    for (const r of records) {
      const nodeId = `"${r.spanId}"`;
      const label  = r.name.replace(/\\/g, '\\\\').replace(/"/g, '\\"').slice(0, 60);
      const bg     = colorMap[r.severity as Severity] ?? colorMap.none;
      const border = borderMap[r.severity as Severity] ?? borderMap.none;
      if (!seen.has(r.spanId)) {
        lines.push(`  ${nodeId} [label="${label}" fillcolor="${bg}" color="${border}"]`);
        seen.add(r.spanId);
      }
      if (r.parentId && r.parentId !== r.spanId) {
        lines.push(`  "${r.parentId}" -> ${nodeId} [label="${r.protocol}"]`);
      }
    }

    lines.push('}');
    res.setHeader('Content-Type', 'text/vnd.graphviz; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${Date.now()}.dot"`);
    res.send(lines.join('\n'));
  });

  // ── Suppressions CRUD (s61) ───────────────────────────────────────────────
  registerSuppressionRoutes(app, { io, invalidateSuppressedCache, auditLog });

  // ── Auto-discovery: scan running agent processes and create live spans ───
  // This makes the dashboard "just work" — start `pnpm dev`, open the
  // browser, and any running AI agents appear in the graph automatically.

  const AUTO_SCAN_INTERVAL = 30_000; // 30 seconds
  const discoveredPids = new Set<number>();

  function autoDiscoverAgents() {
    try {
      const procs = scanAgentProcesses();
      if (procs.length === 0) return;

      // Deduplicate: only pick the primary process per harness (highest CPU)
      const byHarness = new Map<string, AgentProcess>();
      for (const p of procs) {
        const existing = byHarness.get(p.harness);
        if (!existing || p.cpuPct > existing.cpuPct) {
          byHarness.set(p.harness, p);
        }
      }

      let changed = false;

      for (const [harnessId, proc] of byHarness) {
        // Skip if we already discovered this PID
        if (discoveredPids.has(proc.pid)) continue;
        discoveredPids.add(proc.pid);

        const h = HARNESSES.find(h => h.id === harnessId) ?? HARNESSES[HARNESSES.length - 1];
        const traceId  = `auto-${harnessId}-${proc.pid}`;
        const nowNs    = String(BigInt(Date.now()) * 1_000_000n);
        const endNs    = String(BigInt(Date.now()) * 1_000_000n + 1_000_000n);

        // Create session if it doesn't exist
        if (!db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(traceId)) {
          upsertSession.run(traceId, `${h.name} · PID ${proc.pid} (auto-detected)`, new Date().toISOString());
        }

        // Create a discovery span
        const spanId = `disc-${proc.pid}-${Date.now().toString(36)}`;
        const attrs: Record<string, unknown> = {
          'discovery.pid':     proc.pid,
          'discovery.cpu':     proc.cpuPct,
          'discovery.mem_mb':  proc.memMb,
          'discovery.cmd':     proc.cmd.replace(/\/Users\/[^/]+/g, '/Users/***').replace(/\/home\/[^/]+/g, '/home/***').slice(0, 200),
          'gen_ai.system':     harnessId,
          'auto_discovered':   true,
        };

        const searchText = `${proc.cmd} ${JSON.stringify(attrs)}`;
        const { severity, matchedLabel, matchedText } = detectSeverity(searchText);

        const spanRecord: SpanRecord = {
          spanId,
          traceId,
          parentId: harnessId,
          name:     `process/${h.name}`,
          protocol: 'local',
          reason:   `Auto-detected running process (PID ${proc.pid}, ${proc.cpuPct}% CPU, ${proc.memMb}MB)`,
          severity,
          harness:  harnessId,
          attributes: JSON.stringify(attrs),
          startNano: nowNs,
          endNano:   endNs,
          // Auto-discovered process spans carry no cwd, so they group under 'unknown'.
          repo:      'unknown',
        };

        insertSpan.run(spanRecord);
        pushToSse(spanRecord);
        io.emit('span-added', {
          spanId:   spanRecord.spanId,
          name:     spanRecord.name,
          harness:  spanRecord.harness,
          severity: spanRecord.severity,
          ts:       new Date().toISOString(),
        });

        if (matchedLabel) {
          insertOrDedupeAlert({
            ts:          new Date().toISOString(),
            ruleLabel:   matchedLabel,
            severity,
            spanId,
            traceId,
            harness:     harnessId,
            spanName:    `process/${h.name}`,
            matchedText,
          });
          io.emit('alerts-update');
        }

        changed = true;
        console.log(`[ClaudeSec] Auto-discovered ${h.name} (PID ${proc.pid}, ${proc.cpuPct}% CPU)`);
      }

      if (changed) {
        io.emit('graph-update', buildGraph());
        io.emit('sessions-update');
      }
    } catch (err) {
      // Don't crash the server if process scanning fails
    }
  }

  // Run immediately on startup, then every 30s
  autoDiscoverAgents();
  const autoScanTimer = setInterval(autoDiscoverAgents, AUTO_SCAN_INTERVAL);
  autoScanTimer.unref();

  // ── Dev / prod static ────────────────────────────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(REPO_ROOT, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => res.sendFile(path.join(distPath, 'index.html')));
  }

  const offsetStore: OffsetStore = {
    get: (filePath) => (getWatchOffset.get(filePath) as { offset: number } | undefined)?.offset,
    set: (filePath, offset) => { setWatchOffset.run(filePath, offset, new Date().toISOString()); },
  };

  const watchEnabled = process.env.CLAUDESEC_WATCH !== '0';
  const watchRoots = defaultRoots();
  if (watchEnabled) {
    const dirtyTraces = new Set<string>();
    const sweep = setInterval(() => {
      if (dirtyTraces.size === 0) return;
      const traces = [...dirtyTraces];
      dirtyTraces.clear();
      for (const traceId of traces) {
        const harnessId = (db.prepare('SELECT harness FROM spans WHERE traceId = ? LIMIT 1').get(traceId) as { harness: string } | undefined)?.harness ?? 'unknown';
        try { detectBehavioralAnomalies(traceId, harnessId); } catch {}
        try { evaluateThresholdRules(traceId, harnessId); } catch {}
      }
      io.emit('sessions-update');
    }, 2500);
    if (typeof sweep.unref === 'function') sweep.unref();

    startTranscriptWatcher({
      roots: watchRoots,
      backfill: process.env.CLAUDESEC_BACKFILL === '1',
      offsets: offsetStore,
      onError: () => {},
      onEvent: (event: WatcherEvent) => {
        if (event.kind === 'span') {
          const { newSession, alertChanged } = ingestSpan(event.span);
          dirtyTraces.add(event.span.traceId);
          recordActivity(1, 0, 0);
          if (newSession)   io.emit('sessions-update');
          if (alertChanged) io.emit('alerts-update');
          emitGraphUpdateThrottled();
        } else if (event.kind === 'end') {
          updateSpanEnd.run(event.endNano, event.spanId);
        } else if (event.kind === 'usage') {
          recordActivity(0, event.tokensIn, event.tokensOut);
        }
      },
    });
  }

  // SECURITY: Bind to localhost by default — set CLAUDESEC_HOST=0.0.0.0 to expose to network
  const HOST = process.env.CLAUDESEC_HOST ?? '127.0.0.1';

  // SECURITY: Bind guard. Refuse to listen on a non-loopback host unless a
  // token is configured OR CLAUDESEC_TRUST_LOCAL=1 is explicitly set.
  // Without either, /api, /mcp, and /v1/traces would be fully unauthenticated
  // to any network client.
  //
  // CLAUDESEC_TRUST_LOCAL=1: opt-in escape hatch for Docker's port-forwarding
  // path (the container sees a non-loopback bridge IP even when the host port
  // is published on 127.0.0.1 only).  Default OFF — existing behavior preserved.
  const hostIsLoopback = HOST === 'localhost' || isLoopbackAddr(HOST);
  const hasToken       = !!(process.env.CLAUDESEC_TOKEN ?? '');

  if (!hostIsLoopback && !hasToken && !trustLocalEnabled()) {
    console.error(
      `\n  [ClaudeSec] SECURITY: refusing to bind to non-loopback host "${HOST}" ` +
      `without CLAUDESEC_TOKEN set.\n` +
      `  Binding a non-loopback host exposes spans.db to the network with the\n` +
      `  /api, /mcp and /v1/traces routes unauthenticated. Set CLAUDESEC_TOKEN to\n` +
      `  a strong secret, or bind to 127.0.0.1 (the default).\n` +
      `  Alternatively, set CLAUDESEC_TRUST_LOCAL=1 ONLY when host exposure is\n` +
      `  restricted (e.g. Docker publishing on 127.0.0.1 only).\n`
    );
    process.exit(1);
  }

  // ⚠  LOUD WARNING: TRUST_LOCAL with a non-loopback bind means the auth gate
  // is DISABLED regardless of whether a token is also set — TRUST_LOCAL
  // short-circuits before the token check.  Only safe when host exposure is
  // tightly restricted (e.g. Docker with the published port bound to 127.0.0.1).
  if (!hostIsLoopback && trustLocalEnabled()) {
    console.warn(
      `\n` +
      `  ╔══════════════════════════════════════════════════════════════════╗\n` +
      `  ║  [ClaudeSec] WARNING: CLAUDESEC_TRUST_LOCAL=1 is ACTIVE         ║\n` +
      `  ║                                                                  ║\n` +
      `  ║  The authentication gate is DISABLED.  Every client that can    ║\n` +
      `  ║  reach port ${String(PORT).padEnd(5)} is treated as fully trusted.         ║\n` +
      `  ║                                                                  ║\n` +
      `  ║  This is ONLY safe when host exposure is strictly restricted     ║\n` +
      `  ║  (e.g. Docker publishing on 127.0.0.1 only — the default        ║\n` +
      `  ║  docker-compose.yml setup).                                      ║\n` +
      `  ║                                                                  ║\n` +
      `  ║  If you change the host binding to a network interface, you      ║\n` +
      `  ║  MUST remove CLAUDESEC_TRUST_LOCAL and set CLAUDESEC_TOKEN.      ║\n` +
      `  ╚══════════════════════════════════════════════════════════════════╝\n`
    );
    if (hasToken) {
      console.warn(
        `  Note: CLAUDESEC_TOKEN is set but is NOT enforced while TRUST_LOCAL is active.\n`
      );
    }
  }

  // Boot-time config mirror — derive the hook artifacts (protected paths, rules
  // snapshot, enforce mode) from the live DB once, now that we're booting as the
  // entry point. Deferred here from module load so a plain import never rewrites
  // the user's installed hook config. Each function is individually fail-open.
  writeProtectedPathsArtifact();
  writeEnforcementSnapshot();
  writeEnforceConfigFile();

  // Boot-loud DB path — log the resolved absolute database file once, so a
  // misconfigured CLAUDESEC_DB (or an unexpected default) is obvious in
  // service.log instead of silently writing to the wrong place.
  console.log(`[ClaudeSec] database: ${path.resolve(DB_PATH)}`);

  // Real online binary backups — a consistent .db snapshot under
  // ~/.claudesec/backups, distinct from the hourly JSON export. Fail-open: a
  // backup error logs and is swallowed so it can never crash the server.
  const runBackup = () => {
    backupDatabase()
      .then(p => console.log(`[ClaudeSec] backup → ${p}`))
      .catch(err => console.error('[ClaudeSec] backup failed:', (err as Error).message));
  };
  setTimeout(runBackup, 60_000);          // once shortly after boot
  setInterval(runBackup, 24 * 60 * 60_000); // and daily thereafter

  // Graceful shutdown — on SIGINT/SIGTERM (launchd/Docker stop, Ctrl-C) stop
  // accepting connections, checkpoint the WAL back into the main DB file, close
  // the handle, then exit 0. This prevents a half-applied WAL / corruption on an
  // abrupt stop. Idempotent: a second signal while we're already shutting down
  // is ignored so we can't double-close or double-exit.
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[ClaudeSec] ${signal} received — shutting down…`);
    httpServer.close(() => {
      checkpointAndClose();
      console.log('[ClaudeSec] database checkpointed and closed. Bye.');
      process.exit(0);
    });
    // Safety net: if connections never drain, force the checkpoint + exit so a
    // hung socket can't block a clean DB close indefinitely.
    setTimeout(() => {
      checkpointAndClose();
      process.exit(0);
    }, 5_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  httpServer.listen(PORT, HOST, () => {
    console.log(`\n  ClaudeSec  http://localhost:${PORT}`);
    console.log(`  OTLP       http://localhost:${PORT}/v1/traces`);
    console.log(`  Auto-scan  Every ${AUTO_SCAN_INTERVAL / 1000}s for running agents`);
    console.log(`  Watcher    ${watchEnabled ? `on — zero-config capture of Claude Code & Codex (${watchRoots.length} roots)` : 'off (CLAUDESEC_WATCH=0)'}\n`);
    const n = (getAllSpans.all() as SpanRecord[]).length;
    if (n > 0) console.log(`  Loaded ${n} spans from database.\n`);
  });
}

// Autostart ONLY when this file is the process entry point (the live service
// runs `tsx server/index.ts`). Importing the module — a test, a build tool, the
// CLI — leaves it inert: no listener, no timers, no config-mirror writes.
if (IS_ENTRY_POINT) {
  startServer();
}
