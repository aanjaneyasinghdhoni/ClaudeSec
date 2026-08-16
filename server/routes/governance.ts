// server/routes/governance.ts
//
// Read-only API for the AI Governance layer (see server/governance.ts for the
// policy data and docs/govern/policies.mdx for what each policy claims). Two
// endpoints:
//
//   GET /api/governance/policies  — the coverage strip + twelve policy rows,
//                                    for the Govern tab.
//   GET /api/governance/evidence  — the dated, signed evidence pack download.
//
// Both are pure reads over tables that already exist (alerts, enforce_log,
// rule_overrides, suppressions, operator_audit_log, spans) plus the same
// hook-status and chain-verify calls the Enforce and Audit surfaces already
// use. Nothing here writes to the database, mutates config, or evaluates a
// new detection — the whole point of this layer is that it adds no new
// matcher, only a reading of what already exists.
import fs from 'node:fs';
import crypto from 'node:crypto';
import type { Express } from 'express';
import { db, DB_PATH } from '../db.js';
import { detectHookStatus, resolveEffectiveMode } from '../enforceStatus.js';
import { resolveRetention } from '../retentionProfiles.js';
import { verifyAuditChain } from '../auditLog.js';
import { verifyEnforceChain } from '../enforceLogStore.js';
import { verifySpanChain } from '../db.js';
import { signWithExistingAuditKey } from '../auditChain.js';
import {
  POLICIES, validatePolicyLabels, derivePolicyStatus, deriveRetentionStatus, deriveLocalOnlyStatus,
  HELD_MEANS, NOT_A_SCORE, NOT_CERTIFICATION, BIGGEST_GAP, NIST_GOVERN_GAP,
  NIST_SUBCATEGORIES_CLAIMED, NIST_SUBCATEGORIES_TOTAL,
  ISO_ANNEX_A_CONTROLS_CLAIMED, ISO_ANNEX_A_CONTROLS_TOTAL,
  ISO_MANDATORY_CLAUSES_CLAIMED, ISO_MANDATORY_CLAUSES_TOTAL,
  type Policy, type PolicyStatus, type StatusResult,
} from '../governance.js';
import type { RouteContext } from './context.js';

// Fail loudly at import time if a rule got renamed out from under a policy —
// this is the same integrity gate tests/governancePolicyLabelsTest.ts runs,
// repeated here so a bad deploy can never silently ship a hollow policy.
// Logged, not thrown: a monitoring tool that refuses to boot over its own
// governance view being stale is a worse failure than the view being stale.
const labelProblems = validatePolicyLabels();
if (labelProblems.length > 0) {
  console.error(
    '[governance] one or more policies reference rule labels that no longer exist — see tests/governancePolicyLabelsTest.ts:',
    JSON.stringify(labelProblems),
  );
}

const DEFAULT_WINDOW_DAYS = 90;
const MAX_WINDOW_DAYS = 3650; // ten years — generous ceiling against a pathological ?days= value

function parseWindowDays(raw: unknown): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_WINDOW_DAYS;
  return Math.min(Math.floor(n), MAX_WINDOW_DAYS);
}

// ── Prepared statements ─────────────────────────────────────────────────────

const disabledLabelsStmt = db.prepare(`SELECT ruleLabel FROM rule_overrides WHERE enabled = 0`);
const suppressedKeysStmt = db.prepare(`SELECT ruleKey FROM suppressions WHERE suppressUntil > ?`);
const oldestSpanStmt = db.prepare(`SELECT MIN(startNano) as n FROM spans`);
const agentsSeenStmt = db.prepare(`
  SELECT harness, COUNT(DISTINCT traceId) as sessions, COUNT(*) as spans
  FROM spans WHERE startNano >= ? GROUP BY harness ORDER BY sessions DESC
`);

function alertsCountStmt(labelCount: number) {
  const placeholders = Array(labelCount).fill('?').join(',');
  // fp = 0: a confirmed false positive is not evidence of a violation. dismissed
  // rows still count — dismissing only means "acknowledged", not "did not happen".
  return db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE fp = 0 AND ts >= ? AND ruleLabel IN (${placeholders})`);
}

function blockedCountStmt(labelCount: number) {
  const placeholders = Array(labelCount).fill('?').join(',');
  return db.prepare(`SELECT COUNT(*) as c FROM enforce_log WHERE blocked = 1 AND ts >= ? AND label IN (${placeholders})`);
}

/** Age in whole days of the oldest surviving span, or null when the DB holds none. */
function effectiveCoverageDays(): number | null {
  const row = oldestSpanStmt.get() as { n: string | null };
  if (!row.n) return null;
  try {
    const oldestMs = Number(BigInt(row.n) / 1_000_000n);
    return Math.floor((Date.now() - oldestMs) / 86_400_000);
  } catch {
    return null;
  }
}

// ── Per-policy evidence + status ────────────────────────────────────────────

interface PolicyRow {
  id: string;
  sentence: string;
  status: PolicyStatus;
  reasons: string[];
  severityFloor: Policy['severityFloor'];
  enforcement: Policy['enforcement'];
  enforcementNote: string;
  ruleLabels: string[];
  ruleLabelCount: number;
  evidence: { alerts: number; blocked: number; disabledCount: number; suppressedCount: number };
  evidenceDescription: string;
  doesNotProve: string[];
  frameworks: { nist: string[]; iso: string[] };
  configPolicy: boolean;
}

interface Snapshot {
  generatedAt: string;
  period: { days: number; from: string; to: string };
  coverage: {
    dataHeld: { configuredDays: number; effectiveDays: number | null; cappedByMaxSpans: boolean; warning: string | null };
    mode: string;
    effectiveMode: string;
    modeSource: string;
    hook: { installed: string; scopes: string[] };
    chain: { ok: boolean; audit: unknown; enforce: unknown; spans: unknown };
    agentsSeen: { harness: string; sessions: number; spans: number }[];
  };
  policies: PolicyRow[];
  frameworkCoverage: {
    nist: { claimed: string[]; claimedCount: number; total: number };
    iso: {
      claimed: string[]; claimedCount: number; total: number;
      mandatoryClauses: { claimed: number; total: number };
    };
  };
  honesty: {
    heldMeans: string;
    notAScore: string;
    notCertification: string;
    biggestGap: string;
    governGap: string;
  };
}

async function buildSnapshot(ctx: RouteContext, days: number): Promise<Snapshot> {
  const now = Date.now();
  const windowStartMs = now - days * 86_400_000;
  const windowStartIso = new Date(windowStartMs).toISOString();

  const disabledSet = new Set((disabledLabelsStmt.all() as { ruleLabel: string }[]).map(r => r.ruleLabel));
  const suppressedSet = new Set((suppressedKeysStmt.all(new Date(now).toISOString()) as { ruleKey: string }[]).map(r => r.ruleKey));
  const effectiveDays = effectiveCoverageDays();
  const hookStatus = detectHookStatus();
  const { effectiveMode, modeSource } = resolveEffectiveMode();
  const mode = ctx.getEnforceMode?.() ?? 'monitor';

  const [auditVerify, enforceVerify, spansVerify] = [
    verifyAuditChain(),
    verifyEnforceChain(),
    await verifySpanChain({ deep: false }),
  ];

  const agentsSeen = (agentsSeenStmt.all(String(BigInt(windowStartMs) * 1_000_000n)) as { harness: string; sessions: number; spans: number }[]);

  const retention = resolveRetention({
    env: process.env,
    readConfig: (key: string) => (db.prepare(`SELECT value FROM config WHERE key = ?`).get(key) as { value: string } | undefined)?.value,
    db,
  });

  const policies: PolicyRow[] = POLICIES.map(policy => {
    if (policy.configPolicy) {
      let result: StatusResult;
      if (policy.id === 'P11') {
        result = deriveRetentionStatus({ configuredDays: retention.effectiveWindowDays ?? 0, effectiveDays });
      } else {
        // P12 — local-only + scrubbing.
        const sinks: string[] = [];
        if (process.env.OTEL_FORWARD_URL) sinks.push('OTEL_FORWARD_URL');
        const webhookUrl = ctx.getWebhookUrl?.() ?? '';
        if (webhookUrl) sinks.push('CLAUDESEC_WEBHOOK_URL');
        if (process.env.CLAUDESEC_JUDGE_URL) sinks.push('CLAUDESEC_JUDGE_URL');
        let dbFileMode: number | null = null;
        try { dbFileMode = fs.statSync(DB_PATH).mode; } catch { /* not on disk (e.g. :memory:) */ }
        result = deriveLocalOnlyStatus({
          scrubEnabled: ctx.getScrubEnabled?.() ?? true,
          configuredSinks: sinks,
          dbFileMode,
        });
      }
      return {
        id: policy.id, sentence: policy.sentence, status: result.status, reasons: result.reasons,
        severityFloor: policy.severityFloor, enforcement: policy.enforcement, enforcementNote: policy.enforcementNote,
        ruleLabels: [], ruleLabelCount: 0,
        evidence: { alerts: 0, blocked: 0, disabledCount: 0, suppressedCount: 0 },
        evidenceDescription: policy.evidenceDescription, doesNotProve: policy.doesNotProve,
        frameworks: policy.frameworks, configPolicy: true,
      };
    }

    const disabledRuleLabels = policy.ruleLabels.filter(l => disabledSet.has(l));
    const suppressedRuleLabels = policy.ruleLabels.filter(l => suppressedSet.has(l));
    const alerts = policy.ruleLabels.length > 0
      ? ((alertsCountStmt(policy.ruleLabels.length).get(windowStartIso, ...policy.ruleLabels) as { c: number }).c)
      : 0;
    const blocked = policy.ruleLabels.length > 0
      ? ((blockedCountStmt(policy.ruleLabels.length).get(windowStartMs, ...policy.ruleLabels) as { c: number }).c)
      : 0;

    const result = derivePolicyStatus(
      policy,
      { alerts, blocked, disabledRuleLabels, suppressedRuleLabels },
      { hookInstalled: hookStatus.installed, effectiveWindowDays: effectiveDays, requestedWindowDays: days },
    );

    return {
      id: policy.id, sentence: policy.sentence, status: result.status, reasons: result.reasons,
      severityFloor: policy.severityFloor, enforcement: policy.enforcement, enforcementNote: policy.enforcementNote,
      ruleLabels: policy.ruleLabels, ruleLabelCount: policy.ruleLabels.length,
      evidence: { alerts, blocked, disabledCount: disabledRuleLabels.length, suppressedCount: suppressedRuleLabels.length },
      evidenceDescription: policy.evidenceDescription, doesNotProve: policy.doesNotProve,
      frameworks: policy.frameworks, configPolicy: false,
    };
  });

  return {
    generatedAt: new Date(now).toISOString(),
    period: { days, from: windowStartIso, to: new Date(now).toISOString() },
    coverage: {
      dataHeld: {
        configuredDays: retention.effectiveWindowDays ?? 0,
        effectiveDays,
        // The retention module calls the span-ceiling case 'capacity'.
        cappedByMaxSpans: retention.limitingFactor === 'capacity',
        warning: retention.warning,
      },
      mode, effectiveMode, modeSource,
      hook: { installed: hookStatus.installed, scopes: hookStatus.scopes },
      chain: {
        ok: auditVerify.ok && enforceVerify.ok && spansVerify.ok,
        audit: auditVerify, enforce: enforceVerify, spans: spansVerify,
      },
      agentsSeen,
    },
    policies,
    frameworkCoverage: {
      nist: {
        claimed: [...NIST_SUBCATEGORIES_CLAIMED], claimedCount: NIST_SUBCATEGORIES_CLAIMED.length,
        total: NIST_SUBCATEGORIES_TOTAL,
      },
      iso: {
        claimed: [...ISO_ANNEX_A_CONTROLS_CLAIMED], claimedCount: ISO_ANNEX_A_CONTROLS_CLAIMED.length,
        total: ISO_ANNEX_A_CONTROLS_TOTAL,
        mandatoryClauses: { claimed: ISO_MANDATORY_CLAUSES_CLAIMED, total: ISO_MANDATORY_CLAUSES_TOTAL },
      },
    },
    honesty: {
      heldMeans: HELD_MEANS, notAScore: NOT_A_SCORE, notCertification: NOT_CERTIFICATION,
      biggestGap: BIGGEST_GAP, governGap: NIST_GOVERN_GAP,
    },
  };
}

// ── Evidence pack: canonicalization + Ed25519 signing ──────────────────────

/** Deterministic JSON: object keys sorted recursively, so the same snapshot always serializes to the same bytes — a prerequisite for a signature a third party can recompute. */
function canonicalize(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) out[k] = sort((v as Record<string, unknown>)[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sort(value));
}

/**
 * Sign the pack with the install's Ed25519 key — the SAME key
 * GET /api/audit/public-key already exposes.
 *
 * Asymmetric, never the legacy HMAC, and the reason is the whole purpose of the
 * artifact. An HMAC verifier necessarily holds the secret, so anyone able to
 * check a pack could also mint one that checks out. The pack exists to be handed
 * to a party that does not trust the exporter, which is exactly the party a
 * shared secret cannot be given.
 *
 * Signs only with a key that already exists — an export must never be the thing
 * that founds a signing identity, or a deliberately removed key would return
 * under a new keyId and the pack would claim a signature no recorded key
 * matches. With no key available the pack still exports and says plainly that it
 * is unsigned: an unsigned pack the auditor is told is unsigned is honest; one
 * that quietly claims a signature is not.
 */
function signPack(canonicalPayload: string): { signed: true; algorithm: 'ed25519'; keyId: string; signature: string } | { signed: false; reason: string } {
  const result = signWithExistingAuditKey(Buffer.from(canonicalPayload, 'utf8'));
  if (!result) return { signed: false, reason: 'no Ed25519 signing key available on this install' };
  return { signed: true, algorithm: 'ed25519', keyId: result.keyId, signature: result.signature.toString('base64') };
}

function csvEscape(s: string): string {
  return `"${String(s ?? '').replace(/"/g, '""')}"`;
}

// ── Routes ───────────────────────────────────────────────────────────────

export function registerGovernanceRoutes(app: Express, ctx: RouteContext): void {
  app.get('/api/governance/policies', (req, res) => {
    const days = parseWindowDays(req.query.days);
    void buildSnapshot(ctx, days)
      .then(snapshot => res.json(snapshot))
      .catch((e: Error) => res.status(500).json({ error: `governance snapshot failed: ${e.message}` }));
  });

  app.get('/api/governance/evidence', (req, res) => {
    const days = parseWindowDays(req.query.days);
    void buildSnapshot(ctx, days).then(snapshot => {
      const windowStartMs = Date.now() - days * 86_400_000;
      const windowStartIso = new Date(windowStartMs).toISOString();

      const alertRows = db.prepare(
        `SELECT id, ts, ruleLabel, severity, harness, spanName, matchedText, dismissed, fp FROM alerts WHERE ts >= ? ORDER BY id ASC`,
      ).all(windowStartIso) as { id: number; ts: string; ruleLabel: string; severity: string; harness: string; spanName: string; matchedText: string; dismissed: number; fp: number }[];

      const enforceRows = db.prepare(
        `SELECT id, ts, mode, label, severity, command, wouldBlock, blocked FROM enforce_log WHERE ts >= ? ORDER BY id ASC`,
      ).all(windowStartMs) as { id: number; ts: number; mode: string; label: string; severity: string; command: string; wouldBlock: number; blocked: number }[];

      const auditRows = db.prepare(
        `SELECT id, ts, actor, action, target, detail, sourceIp FROM operator_audit_log WHERE ts >= ? ORDER BY id ASC`,
      ).all(windowStartMs) as { id: number; ts: number; actor: string; action: string; target: string; detail: string; sourceIp: string }[];

      const alertsCsv = 'id,ts,ruleLabel,severity,harness,spanName,matchedText,dismissed,fp\n' +
        alertRows.map(r => [r.id, r.ts, csvEscape(r.ruleLabel), r.severity, r.harness, csvEscape(r.spanName), csvEscape(r.matchedText), r.dismissed, r.fp].join(',')).join('\n');

      const enforceCsv = 'id,ts,mode,label,severity,command,wouldBlock,blocked\n' +
        enforceRows.map(r => [r.id, new Date(r.ts).toISOString(), r.mode, csvEscape(r.label), r.severity, csvEscape(r.command), r.wouldBlock, r.blocked].join(',')).join('\n');

      const auditCsv = 'id,ts,actor,action,target,detail,sourceIp\n' +
        auditRows.map(r => [r.id, new Date(r.ts).toISOString(), r.actor, r.action, csvEscape(r.target), csvEscape(r.detail), r.sourceIp].join(',')).join('\n');

      const heldCount = snapshot.policies.filter(p => p.status === 'held').length;
      const violatedCount = snapshot.policies.filter(p => p.status === 'violated').length;
      const notProvableCount = snapshot.policies.filter(p => p.status === 'not-provable').length;

      // Generated, not hand-written, so the "cannot prove" section can never
      // drift optimistic relative to what the status logic actually found.
      const summaryLines: string[] = [
        `# ClaudeSec evidence pack`,
        ``,
        `Generated ${snapshot.generatedAt} · period ${snapshot.period.from} to ${snapshot.period.to} (${days} days)`,
        ``,
        `"Policy" here is a technical control statement enforced by software — not the ISO 42001 A.2.2 AI Policy, ` +
        `which is a document signed by management. This pack is one system reporting on itself: no independent ` +
        `party, no external time anchor.`,
        ``,
        `## Coverage`,
        ``,
        `- Data held: configured ${snapshot.coverage.dataHeld.configuredDays} day(s), effective ${snapshot.coverage.dataHeld.effectiveDays ?? 'unknown'} day(s)` +
          (snapshot.coverage.dataHeld.cappedByMaxSpans ? ' — capped by the span-count ceiling, not the day window' : ''),
        `- Mode: ${snapshot.coverage.mode} (effective: ${snapshot.coverage.effectiveMode}, source: ${snapshot.coverage.modeSource})`,
        `- Hook: ${snapshot.coverage.hook.installed}${snapshot.coverage.hook.scopes.length ? ` (${snapshot.coverage.hook.scopes.join(', ')})` : ''}`,
        `- Chain verification: ${snapshot.coverage.chain.ok ? 'ok' : 'FAILED — see manifest.json chain section'}`,
        `- Agents seen: ${snapshot.coverage.agentsSeen.map(a => `${a.harness} (${a.sessions} sessions)`).join(', ') || 'none in this window'}`,
        ``,
        `## Policies — ${heldCount} held · ${violatedCount} violated · ${notProvableCount} not provable`,
        ``,
        ...snapshot.policies.flatMap(p => [
          `### ${p.id} — ${p.sentence}`,
          `Status: **${p.status.toUpperCase()}**${p.configPolicy ? ' (configuration policy — no rule backing)' : ` — ${p.evidence.alerts} alert(s), ${p.evidence.blocked} blocked, ${p.ruleLabelCount} rule(s)`}`,
          ...(p.reasons.length ? [`Why not provable: ${p.reasons.join('; ')}`] : []),
          `Does not prove: ${p.doesNotProve.join(' ')}`,
          ``,
        ]),
        `## What this pack cannot prove`,
        ``,
        `- ${HELD_MEANS}`,
        `- ${NOT_A_SCORE}`,
        `- ${NOT_CERTIFICATION}`,
        `- ${BIGGEST_GAP}`,
        `- ${NIST_GOVERN_GAP}`,
        `- Framework coverage claimed: ${snapshot.frameworkCoverage.nist.claimedCount} of ${snapshot.frameworkCoverage.nist.total} NIST AI RMF subcategories; ` +
          `${snapshot.frameworkCoverage.iso.claimedCount} of ${snapshot.frameworkCoverage.iso.total} ISO/IEC 42001 Annex A controls; ` +
          `${snapshot.frameworkCoverage.iso.mandatoryClauses.claimed} of ${snapshot.frameworkCoverage.iso.mandatoryClauses.total} mandatory ISO clauses (4–10) — no software feature satisfies those.`,
      ];
      const summaryMarkdown = summaryLines.join('\n');

      const manifest = {
        appVersion: ctx.appVersion ?? '0.0.0',
        generatedAt: snapshot.generatedAt,
        period: snapshot.period,
        policySetHash: crypto.createHash('sha256').update(canonicalize(POLICIES)).digest('hex'),
        ruleCount: POLICIES.reduce((sum, p) => sum + p.ruleLabels.length, 0),
        coverage: snapshot.coverage,
        policies: snapshot.policies,
        frameworkCoverage: snapshot.frameworkCoverage,
        rowCounts: { alerts: alertRows.length, enforce: enforceRows.length, audit: auditRows.length },
      };

      // The signature covers manifest + both CSVs + the summary text, so a
      // verifier is attesting to everything in the download, not just the
      // headline numbers.
      const payload = { manifest, summaryMarkdown, alertsCsv, enforceCsv, auditCsv };
      const canonicalPayload = canonicalize(payload);
      const signature = signPack(canonicalPayload);

      const pack = {
        ...payload,
        verification: {
          ...signature,
          publicKeyEndpoint: '/api/audit/public-key',
          howToVerify: 'Fetch the Ed25519 public key PEM from publicKeyEndpoint. Recompute this exact JSON ' +
            'payload — { manifest, summaryMarkdown, alertsCsv, enforceCsv, auditCsv } — with object keys sorted ' +
            'recursively at every level (see canonicalize() in server/routes/governance.ts) and no extra ' +
            'whitespace, matching JSON.stringify of that sorted structure. Verify `signature` (base64) over the ' +
            'UTF-8 bytes of that string with Ed25519 — e.g. Node: crypto.verify(null, Buffer.from(payload, ' +
            '"utf8"), publicKeyPem, Buffer.from(signature, "base64")). A failing signature means the file, its ' +
            'field order, or the key has changed since it was generated.',
        },
      };

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="claudesec-evidence-pack-${new Date().toISOString().slice(0, 10)}.json"`);
      res.json(pack);
    }).catch((e: Error) => res.status(500).json({ error: `evidence pack generation failed: ${e.message}` }));
  });
}
