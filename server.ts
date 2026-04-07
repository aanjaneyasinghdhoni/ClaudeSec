import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
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
];

function detectSeverity(text: string): { severity: Severity; matchedLabel: string } {
  for (const rule of SEVERITY_RULES) {
    if (rule.pattern.test(text)) return { severity: rule.severity, matchedLabel: rule.label };
  }
  return { severity: 'none', matchedLabel: '' };
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
    let newSessions = false;

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
          const { severity, matchedLabel } = detectSeverity(searchText);
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
        });
      });
    });

    io.emit('graph-update', buildGraph());
    if (newSessions) io.emit('sessions-update');
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
    io.emit('graph-update', buildGraph());
    io.emit('sessions-update');
    res.json({ status: 'ok' });
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
