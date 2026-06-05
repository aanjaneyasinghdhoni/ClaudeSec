import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ScanLine, RefreshCw, ShieldCheck, AlertTriangle, KeyRound,
  Syringe, Terminal, Bug, Server, FileCode,
} from 'lucide-react';

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

// ── Visual maps ───────────────────────────────────────────────────────────────
const SEV_BADGE: Record<ScanSeverity, string> = {
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
};

const SEV_RANK: Record<ScanSeverity, number> = { high: 3, medium: 2, low: 1 };

const KIND_META: Record<FindingKind, { label: string; icon: React.ReactNode }> = {
  'prompt-injection':   { label: 'Prompt injection',   icon: <Syringe className="w-3.5 h-3.5" /> },
  'tool-poisoning':     { label: 'Tool poisoning',     icon: <Bug className="w-3.5 h-3.5" /> },
  'hardcoded-secret':   { label: 'Hardcoded secret',   icon: <KeyRound className="w-3.5 h-3.5" /> },
  'suspicious-command': { label: 'Suspicious command', icon: <Terminal className="w-3.5 h-3.5" /> },
};

function fmtTime(iso: string): string {
  try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return iso; }
}

// ── Component ─────────────────────────────────────────────────────────────────
export function McpScanTab() {
  const [data, setData]       = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

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

  // Group findings by source, ordered by worst severity within the group.
  const groups = useMemo(() => {
    if (!data) return [];
    const map = new Map<string, { source: string; sourceId: string; findings: ScanFinding[] }>();
    for (const f of data.findings) {
      let g = map.get(f.sourceId);
      if (!g) { g = { source: f.source, sourceId: f.sourceId, findings: [] }; map.set(f.sourceId, g); }
      g.findings.push(f);
    }
    const arr = Array.from(map.values());
    for (const g of arr) g.findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
    arr.sort((a, b) => {
      const wa = Math.max(...a.findings.map(f => SEV_RANK[f.severity]));
      const wb = Math.max(...b.findings.map(f => SEV_RANK[f.severity]));
      return wb - wa;
    });
    return arr;
  }, [data]);

  const s = data?.summary;
  const clean = !!data && data.findings.length === 0;

  return (
    <div className="flex-1 overflow-auto p-4 md:p-6">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: 'rgba(var(--cs-accent-rgb),0.12)', color: 'var(--cs-accent)' }}>
            <ScanLine className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold leading-tight" style={{ color: 'var(--cs-text-base)' }}>
              MCP &amp; Skill Scanner
            </h2>
            <p className="text-[11px] leading-tight" style={{ color: 'var(--cs-text-faint)' }}>
              Static scan of MCP server configs and skills for tool poisoning, prompt injection &amp; secrets
            </p>
          </div>
        </div>
        <button
          onClick={() => runScan(true)}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors disabled:opacity-50"
          style={{ background: 'var(--cs-accent)', color: 'var(--cs-on-accent, #fff)' }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {loading ? 'Scanning…' : 'Scan now'}
        </button>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded-xl text-[12px] flex items-center gap-2"
          style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#fca5a5' }}>
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* Summary tiles */}
      {s && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 mb-5">
          <SummaryTile icon={<Server className="w-4 h-4" />} label="MCP servers" value={s.mcpServers} />
          <SummaryTile icon={<FileCode className="w-4 h-4" />} label="Skills" value={s.skills} />
          <SummaryTile icon={<ScanLine className="w-4 h-4" />} label="Findings" value={s.findings}
            accent={s.findings > 0 ? 'rose' : 'green'} />
          <SummaryTile label="High" value={s.bySeverity.high} accent={s.bySeverity.high > 0 ? 'rose' : undefined} />
          <SummaryTile label="Medium" value={s.bySeverity.medium} accent={s.bySeverity.medium > 0 ? 'orange' : undefined} />
          <SummaryTile label="Low" value={s.bySeverity.low} accent={s.bySeverity.low > 0 ? 'yellow' : undefined} />
        </div>
      )}

      {/* Empty / clean state */}
      {clean && (
        <div className="flex flex-col items-center justify-center text-center py-16 px-4 rounded-2xl"
          style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-3"
            style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80' }}>
            <ShieldCheck className="w-7 h-7" />
          </div>
          <p className="text-sm font-semibold" style={{ color: 'var(--cs-text-base)' }}>No issues found</p>
          <p className="text-[12px] mt-1" style={{ color: 'var(--cs-text-faint)' }}>
            Scanned {s?.mcpServers ?? 0} MCP server{(s?.mcpServers ?? 0) === 1 ? '' : 's'} and{' '}
            {s?.skills ?? 0} skill{(s?.skills ?? 0) === 1 ? '' : 's'} — clean.
          </p>
          {data && (
            <p className="text-[10px] mt-3 font-mono" style={{ color: 'var(--cs-text-faint)' }}>
              {data.roots.join('  ·  ')}
            </p>
          )}
        </div>
      )}

      {/* Findings grouped by source */}
      {data && data.findings.length > 0 && (
        <div className="space-y-3">
          {groups.map(g => (
            <div key={g.sourceId} className="rounded-xl overflow-hidden"
              style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
              <div className="flex items-center gap-2 px-4 py-2.5"
                style={{ borderBottom: '1px solid var(--cs-border)', background: 'var(--cs-bg-elevated)' }}>
                {g.sourceId.startsWith('mcp:')
                  ? <Server className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />
                  : <FileCode className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />}
                <span className="text-[12px] font-semibold font-mono truncate" style={{ color: 'var(--cs-text-base)' }}>
                  {g.source}
                </span>
                <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0"
                  style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}>
                  {g.findings.length} finding{g.findings.length === 1 ? '' : 's'}
                </span>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--cs-border)' }}>
                {g.findings.map((f, i) => (
                  <div key={i} className="px-4 py-3" style={{ borderColor: 'var(--cs-border)' }}>
                    <div className="flex flex-wrap items-center gap-2 mb-1.5">
                      <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${SEV_BADGE[f.severity]}`}>
                        {f.severity}
                      </span>
                      <span className="flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded"
                        style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)' }}>
                        {KIND_META[f.kind].icon} {KIND_META[f.kind].label}
                      </span>
                      <span className="text-[12px] font-medium" style={{ color: 'var(--cs-text-base)' }}>{f.label}</span>
                    </div>
                    <p className="text-[11px] leading-snug mb-1.5" style={{ color: 'var(--cs-text-muted)' }}>{f.detail}</p>
                    {f.excerpt && (
                      <pre className="text-[10px] font-mono px-2.5 py-1.5 rounded-md overflow-x-auto whitespace-pre-wrap break-words"
                        style={{ background: 'var(--cs-bg-base)', color: 'var(--cs-text-faint)', border: '1px solid var(--cs-border)' }}>
                        {f.excerpt}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Footer meta */}
      {data && (
        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px]" style={{ color: 'var(--cs-text-faint)' }}>
          <span>Scanned {fmtTime(data.scannedAt)}</span>
          <span>{s?.filesScanned ?? 0} files</span>
          {data.cached && <span>· cached</span>}
          {s?.truncated && <span style={{ color: '#fbbf24' }}>· scan capped (too many files)</span>}
          <span className="font-mono truncate">roots: {data.roots.join(', ')}</span>
        </div>
      )}
    </div>
  );
}

function SummaryTile({ icon, label, value, accent }: {
  icon?: React.ReactNode; label: string; value: number;
  accent?: 'rose' | 'green' | 'orange' | 'yellow';
}) {
  const color =
    accent === 'rose'   ? '#fca5a5' :
    accent === 'green'  ? '#4ade80' :
    accent === 'orange' ? '#fdba74' :
    accent === 'yellow' ? '#fde047' :
    'var(--cs-text-base)';
  return (
    <div className="rounded-xl px-3 py-2.5 flex flex-col gap-1"
      style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
      <span className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide" style={{ color: 'var(--cs-text-faint)' }}>
        {icon} {label}
      </span>
      <span className="text-xl font-bold leading-none" style={{ color }}>{value}</span>
    </div>
  );
}
