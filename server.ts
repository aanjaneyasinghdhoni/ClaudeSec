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
    scopeSpans: {
      scope: any;
      spans: OTelSpan[];
    }[];
  }[];
}

type Severity = 'none' | 'low' | 'medium' | 'high';

interface SpanRecord {
  spanId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string; // JSON string
  startNano: string;
  endNano: string;
}

// ---------------------------------------------------------------------------
// SQLite setup
// ---------------------------------------------------------------------------

const db = new Database('spans.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS spans (
    spanId      TEXT PRIMARY KEY,
    parentId    TEXT NOT NULL,
    name        TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'none',
    harness     TEXT NOT NULL DEFAULT 'unknown',
    attributes  TEXT NOT NULL DEFAULT '{}',
    startNano   TEXT NOT NULL DEFAULT '0',
    endNano     TEXT NOT NULL DEFAULT '0'
  );
`);
try { db.exec(`ALTER TABLE spans ADD COLUMN harness TEXT NOT NULL DEFAULT 'unknown'`); } catch {}

const insertSpan = db.prepare(`
  INSERT OR IGNORE INTO spans (spanId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
  VALUES (@spanId, @parentId, @name, @protocol, @reason, @severity, @harness, @attributes, @startNano, @endNano)
`);

const deleteAllSpans = db.prepare(`DELETE FROM spans`);
const getAllSpans    = db.prepare(`SELECT * FROM spans`);

// ---------------------------------------------------------------------------
// Security detection — severity levels
// ---------------------------------------------------------------------------

const SEVERITY_RULES: { pattern: RegExp; severity: Severity }[] = [
  // HIGH — direct system compromise or data destruction
  { pattern: new RegExp('rm\\s+-rf\\s+[\\/\\\\]', 'i'),    severity: 'high' },
  { pattern: new RegExp('cat\\s+\\/etc\\/passwd', 'i'),     severity: 'high' },
  { pattern: new RegExp('curl\\s+.*\\|\\s*(ba)?sh', 'i'),   severity: 'high' },
  { pattern: new RegExp('wget\\s+.*\\|\\s*(ba)?sh', 'i'),   severity: 'high' },
  { pattern: new RegExp('DROP\\s+(TABLE|DATABASE|SCHEMA)', 'i'), severity: 'high' },
  { pattern: new RegExp('TRUNCATE\\s+TABLE', 'i'),           severity: 'high' },
  { pattern: new RegExp('eval\\s*\\(', 'i'),                 severity: 'high' },
  { pattern: new RegExp('exec\\s*\\(', 'i'),                 severity: 'high' },
  // MEDIUM — exfiltration or sensitive access
  { pattern: new RegExp('process\\.env', 'i'),               severity: 'medium' },
  { pattern: new RegExp('\\.env\\b'),                         severity: 'medium' },
  { pattern: new RegExp('ssh-add', 'i'),                     severity: 'medium' },
  { pattern: new RegExp('\\/etc\\/(shadow|hosts|sudoers)', 'i'), severity: 'medium' },
  { pattern: new RegExp('atob\\s*\\(', 'i'),                 severity: 'medium' },
  { pattern: new RegExp('base64\\s+-d', 'i'),                severity: 'medium' },
  // LOW — suspicious but possibly legitimate
  { pattern: new RegExp('SELECT\\s+\\*\\s+FROM', 'i'),       severity: 'low' },
  { pattern: new RegExp('chmod\\s+[0-7]*7[0-7]*', 'i'),      severity: 'low' },
  { pattern: new RegExp('sudo\\s+', 'i'),                    severity: 'low' },
];

function detectSeverity(text: string): Severity {
  for (const rule of SEVERITY_RULES) {
    if (rule.pattern.test(text)) return rule.severity;
  }
  return 'none';
}

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<Severity, { bg: string; border: string }> = {
  none:   { bg: '',          border: '' },
  low:    { bg: '#fefce8',   border: '#eab308' },
  medium: { bg: '#fff7ed',   border: '#f97316' },
  high:   { bg: '#fee2e2',   border: '#ef4444' },
};

function recordToNode(r: SpanRecord) {
  const style = SEVERITY_STYLES[r.severity as Severity];
  return {
    id: r.spanId,
    data: {
      label:      r.name,
      attributes: JSON.parse(r.attributes),
      severity:   r.severity,
      isMalicious: r.severity !== 'none',
      protocol:   r.protocol,
      reason:     r.reason,
      harness:    r.harness,
      startNano:  r.startNano,
      endNano:    r.endNano,
    },
    position: { x: 0, y: 0 }, // dagre handles layout on frontend
    style: style.border ? { backgroundColor: style.bg, border: `2px solid ${style.border}` } : {},
  };
}

function recordToEdge(r: SpanRecord) {
  const isAlert = r.severity !== 'none';
  const edgeColor = r.severity === 'high' ? '#ef4444' : r.severity === 'medium' ? '#f97316' : r.severity === 'low' ? '#eab308' : '#64748b';
  return {
    id:       `e-${r.parentId}-${r.spanId}`,
    source:   r.parentId,
    target:   r.spanId,
    label:    r.protocol,
    animated: true,
    style:    isAlert ? { stroke: edgeColor } : {},
  };
}

function buildGraph() {
  const records = getAllSpans.all() as SpanRecord[];

  // Build per-harness root nodes
  const distinctHarnesses = (db.prepare('SELECT DISTINCT harness FROM spans').all() as { harness: string }[]);
  let rootNodes: object[];

  if (distinctHarnesses.length === 0) {
    // No spans yet — show the single fallback root
    rootNodes = [{ id: 'agent', data: { label: 'AI Agent' }, position: { x: 0, y: 0 }, type: 'input' }];
  } else {
    rootNodes = distinctHarnesses.map(({ harness: harnessId }) => {
      const hConfig = HARNESSES.find(h => h.id === harnessId) ?? HARNESSES[HARNESSES.length - 1];
      return {
        id:   hConfig.id,
        data: { label: hConfig.name, isRoot: true, harnessColor: hConfig.color },
        position: { x: 0, y: 0 },
        type: 'input',
        style: { backgroundColor: hConfig.color + '22', border: `2px solid ${hConfig.color}`, color: '#fff' },
      };
    });
  }

  const nodes = [...rootNodes, ...records.map(recordToNode)];
  const edges = records.map(recordToEdge);
  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function startServer() {
  const app = express();
  const httpServer = createServer(app);
  const io = new Server(httpServer, { cors: { origin: '*' } });

  app.use(cors());
  app.use(bodyParser.json({ limit: '10mb' }));

  // OTLP ingestion
  app.post('/v1/traces', (req, res) => {
    const traceData: TraceData = req.body;

    traceData.resourceSpans?.forEach(rs => {
      const serviceName = String(rs.resource?.attributes?.find?.((a: any) => a.key === 'service.name')?.value?.stringValue ?? '');
      const sdkName     = String(rs.resource?.attributes?.find?.((a: any) => a.key === 'telemetry.sdk.name')?.value?.stringValue ?? '');
      const harness     = detectHarness(serviceName, sdkName);

      rs.scopeSpans?.forEach(ss => {
        ss.spans?.forEach(span => {
          const attrs: Record<string, any> = {};
          (span.attributes || []).forEach(attr => {
            attrs[attr.key] =
              attr.value?.stringValue ??
              attr.value?.intValue ??
              attr.value?.boolValue ??
              JSON.stringify(attr.value);
          });

          const searchText = JSON.stringify(attrs) + ' ' + span.name;
          const severity   = detectSeverity(searchText);

          // parentId points to harness root if span has no parent
          const parentId = span.parentSpanId || harness.id;

          const record: SpanRecord = {
            spanId:    span.spanId,
            parentId,
            name:      span.name,
            protocol:  String(attrs['protocol'] ?? 'HTTPS'),
            reason:    String(attrs['reason']   ?? 'Processing step'),
            severity,
            harness:   harness.id,
            attributes: JSON.stringify(attrs),
            startNano:  String(span.startTimeUnixNano ?? '0'),
            endNano:    String(span.endTimeUnixNano   ?? '0'),
          };

          insertSpan.run(record);
        });
      });
    });

    io.emit('graph-update', buildGraph());
    res.status(200).json({ status: 'ok' });
  });

  // Current graph state
  app.get('/api/graph', (_req, res) => {
    res.json(buildGraph());
  });

  // Export full session as JSON
  app.get('/api/export', (_req, res) => {
    const records = getAllSpans.all() as SpanRecord[];
    res.setHeader('Content-Disposition', `attachment; filename="session-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), spans: records });
  });

  // Active harnesses
  app.get('/api/harnesses', (_req, res) => {
    const rows = (db.prepare('SELECT DISTINCT harness FROM spans').all() as { harness: string }[]);
    res.json({ harnesses: rows.map(r => r.harness) });
  });

  // Reset
  app.post('/api/reset', (_req, res) => {
    deleteAllSpans.run();
    io.emit('graph-update', buildGraph());
    res.json({ status: 'ok' });
  });

  // Vite dev middleware / static production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => res.sendFile(path.join(distPath, 'index.html')));
  }

  const PORT = 3000;
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
    const count = (getAllSpans.all() as SpanRecord[]).length;
    if (count > 0) console.log(`Loaded ${count} spans from database.`);
  });
}

startServer();
