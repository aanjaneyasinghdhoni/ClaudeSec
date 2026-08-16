/**
 * McpScanTab — a static scan of MCP server configs and skill files.
 *
 * The thing that shapes this screen: on a healthy machine the scan finds
 * nothing, so **the empty state is the normal state**. A screen that answers a
 * clean scan with "No data" is worthless — it cannot be told apart from a scan
 * that never ran, or one that looked in the wrong place. So the scan's own
 * receipt (what was scanned, how many files, when, and from which roots) is
 * permanent chrome above the table rather than something that only appears when
 * the table is empty.
 *
 * Findings, when they exist, are ranked worst-first and grouped by source, and
 * the matched excerpt lives in the row's expanded strip: it is untrusted text
 * captured from a file, and it is the reason to open a row, not something to
 * scan a hundred of at a glance.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ScanLine, RefreshCw, ShieldCheck, KeyRound,
  Syringe, Terminal, Bug, Server, FileCode,
} from 'lucide-react';
import type { Severity } from './shared/types';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, normalizeSeverity,
  EmptyState, ErrorState,
  Toolbar, ToolButton, ToolbarTitle,
} from './components/data';

// ── Types (mirror mcpScan.ts) ─────────────────────────────────────────────────
type ScanSeverity = 'low' | 'medium' | 'high';
type FindingKind = 'prompt-injection' | 'tool-poisoning' | 'hardcoded-secret' | 'suspicious-command';

interface ScanFinding {
  source: string;
  sourceId: string;
  kind: FindingKind;
  severity: ScanSeverity;
  label: string;
  detail: string;
  excerpt: string;
}

interface ScannedSource {
  id: string;
  type: 'mcp-server' | 'skill';
  name: string;
  file: string;
}

interface ScanResult {
  scannedAt: string;
  roots: string[];
  sources: ScannedSource[];
  findings: ScanFinding[];
  cached?: boolean;
  summary: {
    mcpServers: number;
    skills: number;
    filesScanned: number;
    findings: number;
    bySeverity: Record<ScanSeverity, number>;
    byKind: Record<FindingKind, number>;
    truncated: boolean;
  };
}

/** A finding plus the stable row identity the table needs. */
type KeyedFinding = ScanFinding & { key: string };

const SEV_RANK: Record<ScanSeverity, number> = { high: 3, medium: 2, low: 1 };

const KIND_META: Record<FindingKind, { label: string; Icon: typeof Bug }> = {
  'prompt-injection':   { label: 'Prompt injection',   Icon: Syringe  },
  'tool-poisoning':     { label: 'Tool poisoning',     Icon: Bug      },
  'hardcoded-secret':   { label: 'Hardcoded secret',   Icon: KeyRound },
  'suspicious-command': { label: 'Suspicious command', Icon: Terminal },
};

function fmtTime(iso: string): string {
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return iso; }
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/** One fact from the scan receipt. */
function Fact({ label, value, title }: { label: string; value: React.ReactNode; title?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0" title={title}>
      <span style={{ color: 'var(--cs-text-faint)' }}>{label}</span>
      <span className="cs-mono truncate" style={{ color: 'var(--cs-text-body)' }}>{value}</span>
    </span>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
export function McpScanTab() {
  const [data, setData]       = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  // Findings carry a long human sentence and an excerpt, so this list is for
  // reading rather than scanning — it starts one step off compact.
  const [density, setDensity] = useRowDensity('mcpscan', 'default');

  const runScan = useCallback((force = false) => {
    setLoading(true);
    setError('');
    fetch(`/api/mcp-scan${force ? '?force=1' : ''}`)
      .then(r => r.json())
      .then((d: ScanResult & { error?: string }) => {
        if (d.error) { setError(d.error); return; }
        setData(d);
      })
      .catch(() => setError('Could not run MCP/skill scan'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { runScan(false); }, [runScan]);

  // Worst first, and findings from the same source stay adjacent — a poisoned
  // server usually trips several patterns, and they read as one problem. The
  // key is baked in here because a finding has no id of its own, and the row
  // identity has to survive a re-sort.
  const findings = useMemo<KeyedFinding[]>(() => {
    if (!data) return [];
    const worstBySource = new Map<string, number>();
    for (const f of data.findings) {
      worstBySource.set(f.sourceId, Math.max(worstBySource.get(f.sourceId) ?? 0, SEV_RANK[f.severity]));
    }
    return data.findings
      .map((f, i) => ({ ...f, key: `${f.sourceId}::${f.kind}::${i}` }))
      .sort((a, b) =>
        (worstBySource.get(b.sourceId)! - worstBySource.get(a.sourceId)!)
        || a.sourceId.localeCompare(b.sourceId)
        || (SEV_RANK[b.severity] - SEV_RANK[a.severity]));
  }, [data]);

  // Where each finding came from on disk. The finding itself only carries the
  // source's display name; the path is what an operator needs to go and look.
  const fileById = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of data?.sources ?? []) map.set(s.id, s.file);
    return map;
  }, [data]);

  const s = data?.summary;

  const columns: DataColumn<KeyedFinding>[] = [
    {
      id: 'severity', header: 'Severity', width: '96px',
      cell: f => <SeverityBadge severity={normalizeSeverity(f.severity) as Severity} />,
    },
    {
      id: 'kind', header: 'Kind', width: '148px', hideBelow: 'xl',
      cell: f => {
        const meta = KIND_META[f.kind];
        return (
          <span className="flex items-center gap-1.5 min-w-0" title={meta.label}>
            <meta.Icon className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
            <span className="truncate">{meta.label}</span>
          </span>
        );
      },
    },
    {
      id: 'label', header: 'Finding', width: 'minmax(0,1fr)',
      cell: f => (
        <span title={f.label} style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>
          {f.label}
        </span>
      ),
    },
    {
      id: 'source', header: 'Source', width: 'minmax(0,0.8fr)', mono: true,
      cell: f => (
        <span className="flex items-center gap-1.5 min-w-0" title={f.source}>
          {f.sourceId.startsWith('mcp:')
            ? <Server className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
            : <FileCode className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}
          <span className="truncate">{f.source}</span>
        </span>
      ),
    },
    {
      id: 'detail', header: 'Why', width: 'minmax(0,1.3fr)', hideBelow: '2xl',
      cell: f => <span title={f.detail}>{f.detail}</span>,
    },
    {
      id: 'file', header: 'File', width: 'minmax(0,1fr)', hideBelow: '3xl', mono: true,
      cell: f => {
        const file = fileById.get(f.sourceId);
        return file
          ? <span title={file} dir="rtl" className="text-left">{file}</span>
          : <span style={{ color: 'var(--cs-text-faint)' }}>—</span>;
      },
    },
  ];

  // The matched excerpt. Untrusted text lifted out of a file, so it is set in
  // mono on a sunken ground and never rendered as anything but literal text.
  const renderDetail = (f: KeyedFinding) => {
    if (expanded !== f.key) return null;
    const file = fileById.get(f.sourceId);
    return (
      <div className="flex flex-col gap-1.5 py-1.5" style={{ fontSize: 'var(--cs-text-xs)' }}>
        <p style={{ color: 'var(--cs-text-muted)', lineHeight: 'var(--cs-leading-normal)' }}>{f.detail}</p>
        {f.excerpt && (
          <pre
            className="cs-mono px-2 py-1 rounded whitespace-pre-wrap break-words max-h-40 overflow-auto"
            style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}
          >
            {f.excerpt}
          </pre>
        )}
        {file && (
          <code className="cs-mono break-all" style={{ color: 'var(--cs-text-faint)' }}>{file}</code>
        )}
      </div>
    );
  };

  const scannedSummary = s
    ? `Scanned ${plural(s.mcpServers, 'MCP server')} and ${plural(s.skills, 'skill')} — ${plural(s.filesScanned, 'file')} — at ${fmtTime(data!.scannedAt)}.`
    : '';

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      <Toolbar>
        <ToolbarTitle
          icon={<ScanLine className="w-3.5 h-3.5" />}
          count={s ? s.findings : undefined}
          countTitle={s ? `${plural(s.findings, 'finding')} across ${plural(s.filesScanned, 'file')}` : undefined}
        >
          MCP &amp; skill scan
        </ToolbarTitle>

        <p className="hidden 2xl:block min-w-0 truncate" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
          Tool poisoning, prompt injection, hardcoded secrets and suspicious commands
        </p>

        <div className="flex items-center gap-1 ml-auto">
          <RowDensityToggle density={density} onChange={setDensity} className="mr-1" />
          <ToolButton
            onClick={() => runScan(true)}
            disabled={loading}
            title="Re-read every MCP config and skill file, ignoring the cache"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            {loading ? 'Scanning…' : 'Scan now'}
          </ToolButton>
        </div>
      </Toolbar>

      {/* ── The scan receipt ────────────────────────────────────────────────
          Permanent, not conditional. A clean scan and a scan that never ran
          look identical without it. */}
      {data && (
        <div
          className="shrink-0 flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5"
          style={{
            background: 'var(--cs-bg-surface)',
            borderBottom: '1px solid var(--cs-rule)',
            fontSize: 'var(--cs-text-xs)',
          }}
        >
          <Fact label="MCP servers" value={s?.mcpServers ?? 0} />
          <Fact label="Skills" value={s?.skills ?? 0} />
          <Fact label="Files" value={s?.filesScanned ?? 0} />
          <Fact label="Scanned" value={fmtTime(data.scannedAt)} title={new Date(data.scannedAt).toLocaleString()} />
          {data.cached && <span style={{ color: 'var(--cs-text-faint)' }}>cached</span>}
          {s?.truncated && (
            <span style={{ color: 'var(--cs-sev-medium-fg)' }} title="Too many files — the scan stopped early, so this result is incomplete.">
              scan capped
            </span>
          )}
          <span
            className="cs-mono truncate min-w-0 hidden xl:inline"
            style={{ color: 'var(--cs-text-faint)' }}
            title={data.roots.join('\n')}
          >
            {data.roots.join('  ·  ')}
          </span>
        </div>
      )}

      <DataTable
        rows={findings}
        columns={columns}
        rowKey={f => f.key}
        label="Scan findings"
        density={density}
        minWidth={620}
        severity={f => normalizeSeverity(f.severity) as Severity}
        onActivate={f => setExpanded(prev => (prev === f.key ? null : f.key))}
        renderDetail={renderDetail}
        loading={loading && !data}
        error={error ? (
          <ErrorState
            title="The scan could not run"
            description={`${error}. Nothing was checked, so this is not a clean result — fix the error and scan again.`}
            onRetry={() => runScan(true)}
          />
        ) : undefined}
        empty={
          <EmptyState
            icon={<ShieldCheck className="w-6 h-6" aria-hidden="true" />}
            title="Nothing matched"
            description={data
              ? `${scannedSummary} No tool poisoning, prompt injection, hardcoded secret or suspicious command matched. This is the result you want to see — re-run it after installing or updating an MCP server or skill.`
              : 'Run the scan to check every configured MCP server and skill file for tool poisoning, prompt injection, hardcoded secrets and suspicious commands.'}
            action={data && data.roots.length > 0 ? (
              <p
                className="cs-mono mt-1 max-w-lg break-all"
                style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
              >
                {data.roots.join('  ·  ')}
              </p>
            ) : undefined}
          />
        }
      />
    </div>
  );
}
