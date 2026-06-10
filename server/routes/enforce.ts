import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

type EnforceAction = 'alert' | 'block';

interface EnforceLogEvent {
  ts:         number;
  mode:       string;   // 'monitor' | 'enforce'
  label:      string;
  severity:   string;
  command:    string;   // already redacted/truncated by the hook
  wouldBlock: boolean;
}

const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);

export function registerEnforceRoutes(app: Express, ctx: RouteContext): void {
  const {
    io,
    scrubEnforceText,
    appendEnforceLog,
    readEnforceLog,
    enforceLogCount,
    enforceLogMax,
    getEnforceMode,
    getEnforceOverrides,
    writeEnforceConfigFile,
    enforceConfigFile,
    auditLog,
  } = ctx;
  if (
    !appendEnforceLog || !readEnforceLog || !enforceLogCount || enforceLogMax === undefined ||
    !getEnforceMode || !getEnforceOverrides || !writeEnforceConfigFile || enforceConfigFile === undefined
  ) {
    throw new Error(
      'registerEnforceRoutes requires appendEnforceLog/readEnforceLog/enforceLogCount/enforceLogMax/' +
      'getEnforceMode/getEnforceOverrides/writeEnforceConfigFile/enforceConfigFile in ctx',
    );
  }

  // The PreToolUse hook forwards the matched command/content verbatim — it only
  // collapses whitespace and truncates, it does NOT redact. So the text can
  // carry the maintainer's `/Users/<name>/…` home path and any secrets present
  // in the tool input. Run it through the same scrubber the span pipeline uses
  // (home paths → /Users/***, API keys → ‹redacted›, …) so stored + broadcast
  // data is clean at rest. Identity fallback if no scrubber is wired (fail-safe
  // to current behavior is never desired here, but ctx always supplies one).
  const scrub = (s: string): string => (scrubEnforceText ? scrubEnforceText(s) : s);

  // ── Enforcement event log (PreToolUse hook feed) ──────────────────────────
  // The opt-in claudesec-enforce.cjs hook POSTs "would-block" / "blocked"
  // events here so the dashboard can show enforcement activity. Stored in an
  // in-memory ring buffer (no DB writes); broadcast live via socket.
  app.post('/api/enforce-log', (req, res) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    const evt: EnforceLogEvent = {
      ts:         Date.now(),
      mode:       typeof b.mode === 'string' ? b.mode.slice(0, 32) : 'monitor',
      label:      typeof b.label === 'string' ? scrub(b.label).slice(0, 256) : '(unlabeled)',
      severity:   typeof b.severity === 'string' ? b.severity.slice(0, 16) : 'high',
      // Scrub BEFORE truncating so a secret straddling the 1000-char cut is
      // still fully redacted by the time the boundary is applied.
      command:    typeof b.command === 'string' ? scrub(b.command).slice(0, 1000) : '',
      wouldBlock: b.wouldBlock !== false,
    };
    appendEnforceLog(evt);
    io.emit('enforce-log', evt);
    res.json({ status: 'ok' });
  });

  app.get('/api/enforce-log', (req, res) => {
    const raw = Number(req.query.limit);
    const limit = Number.isFinite(raw) && raw > 0 ? Math.min(Math.floor(raw), enforceLogMax) : 100;
    // Defensive (belt-and-suspenders): the write path above already scrubs, but
    // re-scrub on read so any event buffered before this fix — or written while
    // a scrubber was momentarily absent — can never be returned unredacted.
    const events = readEnforceLog(limit).map(e => ({
      ...e,
      label:   scrub(e.label),
      command: scrub(e.command),
    })); // most-recent first
    res.json({ events, total: enforceLogCount() });
  });

  // ── Enforcement config (server-controlled mode + per-rule overrides) ───────
  // Source of truth for what the PreToolUse hook does. The hook reads the
  // mirrored enforce-config.json file (fail-open). Changing it here re-writes
  // that file and broadcasts so the dashboard stays in sync.
  app.get('/api/enforce/config', (_req, res) => {
    res.json({
      mode:          getEnforceMode(),
      overrides:     getEnforceOverrides(),
      configFile:    enforceConfigFile,
      envMode:       process.env.CLAUDESEC_MODE ?? null,
      bypassEnabled: process.env.CLAUDESEC_HOOKS_BYPASS === '1',
    });
  });

  app.put('/api/enforce/config', (req, res) => {
    const b = (req.body ?? {}) as { mode?: unknown; overrides?: unknown };

    // Validate mode (only if provided) — STRICT: anything else is a 400, never
    // silently coerced to 'enforce'.
    if (b.mode !== undefined) {
      if (b.mode !== 'monitor' && b.mode !== 'enforce') {
        return res.status(400).json({ error: "mode must be 'monitor' or 'enforce'" }) as any;
      }
      setConfig.run('enforce.mode', b.mode);
    }

    // Validate overrides (only if provided): a flat { ruleLabel: 'alert'|'block' }
    // map. Bad entries are rejected wholesale so we never persist garbage that
    // the hook would have to defend against.
    if (b.overrides !== undefined) {
      if (b.overrides === null || typeof b.overrides !== 'object' || Array.isArray(b.overrides)) {
        return res.status(400).json({ error: 'overrides must be an object map of ruleLabel → "alert"|"block"' }) as any;
      }
      const clean: Record<string, EnforceAction> = {};
      for (const [k, v] of Object.entries(b.overrides as Record<string, unknown>)) {
        if (typeof k !== 'string' || !k) continue;
        if (v !== 'alert' && v !== 'block') {
          return res.status(400).json({ error: `override for "${k}" must be "alert" or "block"` }) as any;
        }
        clean[k.slice(0, 256)] = v;
      }
      setConfig.run('enforce.overrides', JSON.stringify(clean));
    }

    // Mirror to the local file the hook reads, then broadcast.
    writeEnforceConfigFile();
    const effective = {
      mode:      getEnforceMode(),
      overrides: getEnforceOverrides(),
    };
    auditLog?.(req, 'enforce.config', 'enforce.config', effective);
    io.emit('enforce-config', effective);
    res.json(effective);
  });
}
