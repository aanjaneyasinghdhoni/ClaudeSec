import type { Express } from 'express';
import { db } from '../db.js';
import type { SpanRecord } from '../types.js';
import type { RouteContext } from './context.js';
import { dedupedTokenTotals } from './costs.js';

export function registerSessionRoutes(app: Express, ctx: RouteContext): void {
  const { io, healthFromCounts, computeHealthScore, appVersion } = ctx;
  if (!healthFromCounts || !computeHealthScore) {
    throw new Error('registerSessionRoutes requires healthFromCounts and computeHealthScore in ctx');
  }

  app.get('/api/sessions', (req, res) => {
    const labelFilter = req.query.label ? String(req.query.label) : null;
    const rows = db.prepare(`
      SELECT
        se.traceId,
        se.name,
        se.createdAt,
        se.pinned,
        COALESCE(se.label, 'normal') AS label,
        COALESCE(se.notes, '')       AS notes,
        COUNT(DISTINCT s.spanId) AS spanCount,
        SUM(CASE WHEN s.severity != 'none' THEN 1 ELSE 0 END) AS threatCount,
        MAX(CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS maxSeverityRank,
        GROUP_CONCAT(DISTINCT s.harness) AS harnesses,
        GROUP_CONCAT(DISTINCT s.repo, char(10)) AS repo,
        -- critical is the exfiltration tier above high; fold it into the high
        -- bucket so a confirmed exfil still penalizes health and surfaces in the
        -- breakdown instead of falling through to the green/none default.
        SUM(CASE WHEN s.severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS threatHigh,
        SUM(CASE WHEN s.severity = 'medium' THEN 1 ELSE 0 END) AS threatMedium,
        SUM(CASE WHEN s.severity = 'low'    THEN 1 ELSE 0 END) AS threatLow,
        COUNT(DISTINCT a.id) AS alertCount
      FROM sessions se
      LEFT JOIN spans  s ON s.traceId = se.traceId
      LEFT JOIN alerts a ON a.traceId = se.traceId
      GROUP BY se.traceId
      ORDER BY se.pinned DESC, (threatCount > 0) DESC, threatCount DESC, se.createdAt DESC
    `).all() as any[];

    // Compute per-session health using the SHARED healthFromCounts() formula —
    // the same one behind /api/sessions/:id/health (and the CLI report), so the
    // two paths can no longer diverge. The list query already SELECTs every input
    // the formula needs, so this adds zero extra DB round-trips (no N+1).
    let sessions = rows.map(r => {
      const health = healthFromCounts(r.threatHigh ?? 0, r.threatMedium ?? 0, r.threatLow ?? 0, r.alertCount ?? 0);
      const healthScore = health.score;
      // riskScore retained as the inverse for any consumer expecting it.
      const riskScore = 100 - healthScore;
      return { ...r, healthScore, riskScore, grade: health.grade };
    });

    if (labelFilter) {
      sessions = sessions.filter(s => s.label === labelFilter);
    }

    res.json({ sessions });
  });

  // ── Session health ────────────────────────────────────────────────────────
  app.get('/api/sessions/:traceId/health', (req, res) => {
    const exists = db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(req.params.traceId);
    if (!exists) return res.status(404).json({ error: 'session not found' }) as any;
    res.json(computeHealthScore(req.params.traceId));
  });

  app.patch('/api/sessions/:traceId', (req, res) => {
    const { name, pinned, label, notes } = req.body as {
      name?: string; pinned?: boolean; label?: string; notes?: string;
    };
    const exists = db.prepare('SELECT 1 FROM sessions WHERE traceId = ?').get(req.params.traceId);
    if (!exists) return res.status(404).json({ error: 'session not found' }) as any;

    if (name !== undefined) {
      if (!name.trim()) return res.status(400).json({ error: 'name cannot be empty' }) as any;
      db.prepare('UPDATE sessions SET name = ? WHERE traceId = ?').run(name.trim(), req.params.traceId);
    }
    if (pinned !== undefined) {
      if (pinned) {
        const pinnedCount = (db.prepare('SELECT COUNT(*) as c FROM sessions WHERE pinned = 1').get() as any).c as number;
        if (pinnedCount >= 10) {
          return res.status(409).json({ error: 'Maximum 10 pinned sessions reached. Unpin one first.' }) as any;
        }
      }
      db.prepare('UPDATE sessions SET pinned = ? WHERE traceId = ?').run(pinned ? 1 : 0, req.params.traceId);
    }
    if (label !== undefined) {
      const valid = ['normal', 'incident', 'investigation', 'automated', 'other'];
      if (!valid.includes(label)) return res.status(400).json({ error: `label must be one of: ${valid.join(', ')}` }) as any;
      db.prepare('UPDATE sessions SET label = ? WHERE traceId = ?').run(label, req.params.traceId);
    }
    if (notes !== undefined) {
      db.prepare('UPDATE sessions SET notes = ? WHERE traceId = ?').run(notes, req.params.traceId);
    }
    io.emit('sessions-update');
    res.json({ status: 'ok' });
  });

  app.get('/api/sessions/compare', (req, res) => {
    const aId = String(req.query.a ?? '');
    const bId = String(req.query.b ?? '');
    if (!aId || !bId || aId === bId) {
      return res.status(400).json({ error: 'Provide two distinct traceId values as ?a=...&b=...' }) as any;
    }

    // Token totals on the deduped, cache-aware basis (one source of truth shared
    // with the Cost tab and the report), keyed by traceId. Computed once so the
    // two sessionStats() calls don't each rescan the span table.
    const tokenByTrace = dedupedTokenTotals('trace');

    function sessionStats(traceId: string) {
      const session = db.prepare('SELECT * FROM sessions WHERE traceId = ?').get(traceId) as
        { traceId: string; name: string; createdAt: string; pinned: number } | undefined;
      if (!session) return null;
      const spans = db.prepare('SELECT * FROM spans WHERE traceId = ?').all(traceId) as SpanRecord[];
      const alerts = db.prepare('SELECT * FROM alerts WHERE traceId = ?').all(traceId) as any[];

      const { tokensIn, tokensOut } = tokenByTrace.get(traceId) ?? { tokensIn: 0, tokensOut: 0 };
      let totalDurationMs = 0, durCount = 0;
      const toolCounts = new Map<string, number>();
      const ruleCounts = new Map<string, number>();

      for (const span of spans) {
        try {
          const a = JSON.parse(span.attributes);
          const tool = String(a['gen_ai.tool.name'] ?? a['tool.name'] ?? '');
          if (tool) toolCounts.set(tool, (toolCounts.get(tool) ?? 0) + 1);
          const rule = String(a['claudesec.threat.rule'] ?? '');
          if (rule) ruleCounts.set(rule, (ruleCounts.get(rule) ?? 0) + 1);
        } catch {}
        try {
          const ms = Number((BigInt(span.endNano) - BigInt(span.startNano)) / 1_000_000n);
          if (ms > 0 && ms < 3_600_000) { totalDurationMs += ms; durCount++; }
        } catch {}
      }

      const threatCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      spans.forEach(s => { if (s.severity in threatCounts) (threatCounts as any)[s.severity]++; });

      return {
        traceId, name: session.name, createdAt: session.createdAt,
        spanCount: spans.length, alertCount: alerts.length,
        // critical folds into the high bucket — same convention as the
        // session-list SQL, so the compare view can't under-count it.
        threatHigh: threatCounts.high + threatCounts.critical, threatMedium: threatCounts.medium, threatLow: threatCounts.low,
        tokensIn, tokensOut, avgDurationMs: durCount > 0 ? Math.round(totalDurationMs / durCount) : 0,
        topTools:  [...toolCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n, c]) => ({ name: n, count: c })),
        topRules:  [...ruleCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n, c]) => ({ name: n, count: c })),
      };
    }

    const a = sessionStats(aId);
    const b = sessionStats(bId);
    if (!a || !b) return res.status(404).json({ error: 'One or both sessions not found' }) as any;
    res.json({ a, b });
  });

  app.get('/api/sessions/:traceId/report', (req, res) => {
    const { traceId } = req.params;
    const session = db.prepare('SELECT * FROM sessions WHERE traceId = ?').get(traceId) as
      { traceId: string; name: string; createdAt: string } | undefined;
    if (!session) return res.status(404).json({ error: 'Session not found' }) as any;

    const spans   = db.prepare('SELECT * FROM spans WHERE traceId = ? ORDER BY startNano ASC').all(traceId) as SpanRecord[];
    const alerts  = db.prepare("SELECT * FROM alerts WHERE traceId = ? ORDER BY id DESC").all(traceId) as any[];

    const threatCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    spans.forEach(s => { if (s.severity in threatCounts) (threatCounts as any)[s.severity]++; });

    // Token totals on the deduped, cache-aware basis the Cost tab uses, so the
    // exported report — the artifact handed to an auditor — agrees with the
    // dashboard instead of showing inflated raw, cache-blind sums.
    const reportTokens = dedupedTokenTotals('trace').get(traceId) ?? { tokensIn: 0, tokensOut: 0 };
    const totalTokensIn = reportTokens.tokensIn;
    const totalTokensOut = reportTokens.tokensOut;
    const harnessSet = new Set<string>();
    spans.forEach(s => harnessSet.add(s.harness));

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
      const escHtml = (s: string) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
      const toolName = escHtml(String(attrs['gen_ai.tool.name'] ?? attrs['tool.name'] ?? ''));
      const rule     = escHtml(String(attrs['claudesec.threat.rule'] ?? ''));
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
          <td style="padding:6px 10px; font-size:11px; color:#ef4444">${rule}</td>
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
  ${[...harnessSet].map(h => `<span class="harness-badge">${h.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}</span>`).join('')}
</div>

<div class="cards">
  <div class="card"><div class="card-val" style="color:#e2e8f0">${spans.length}</div><div class="card-label">Total Spans</div></div>
  <div class="card"><div class="card-val" style="color:#f43f5e">${threatCounts.critical}</div><div class="card-label">CRITICAL Threats</div></div>
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
  Generated by <strong>ClaudeSec</strong> v${appVersion ?? 'dev'} &nbsp;·&nbsp;
  <a href="https://github.com/aanjaneyasinghdhoni/ClaudeSec" style="color:#3b82f6;text-decoration:none">github.com/aanjaneyasinghdhoni/ClaudeSec</a>
  &nbsp;·&nbsp; ${new Date().toUTCString()}
</div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${traceId.slice(0, 8)}-${Date.now()}.html"`);
    res.send(html);
  });
}
