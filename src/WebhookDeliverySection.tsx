import React, { useState, useEffect, useCallback } from 'react';
import {
  CheckCircle2,
  XCircle,
  RotateCw,
  Trash2,
  RefreshCw,
  Loader2,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DeliveryRow {
  id: number;
  ruleLabel: string;
  severity: string;
  urlPreview: string;
  status: 'success' | 'failed' | 'retrying';
  httpCode: number | null;
  latencyMs: number | null;
  error: string | null;
  attempts: number;
  createdAt: string;
  lastAttemptAt: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatRelativeTime(iso: string): string {
  try {
    const delta = Date.now() - new Date(iso).getTime();
    if (delta < 60_000)        return `${Math.round(delta / 1000)}s ago`;
    if (delta < 3_600_000)     return `${Math.round(delta / 60_000)}m ago`;
    if (delta < 86_400_000)    return `${Math.round(delta / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch { return '—'; }
}

const SEVERITY_CLS: Record<string, string> = {
  high:   'bg-red-900/60 text-red-300 border-red-700',
  medium: 'bg-orange-900/60 text-orange-300 border-orange-700',
  low:    'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  none:   'bg-green-900/60 text-green-300 border-green-700',
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLS[severity.toLowerCase()] ?? SEVERITY_CLS['none'];
  const label = severity.toUpperCase() === 'NONE' ? 'OK' : severity.toUpperCase();
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-xs font-semibold rounded border ${cls}`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status icon
// ---------------------------------------------------------------------------

function StatusIcon({ status }: { status: DeliveryRow['status'] }) {
  if (status === 'success') {
    return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  }
  if (status === 'failed') {
    return <XCircle className="w-4 h-4 text-red-400" />;
  }
  // retrying
  return <RotateCw className="w-4 h-4 text-yellow-400 animate-spin" />;
}

// ---------------------------------------------------------------------------
// WebhookDeliverySection
// ---------------------------------------------------------------------------

export function WebhookDeliverySection() {
  const [rows,          setRows]          = useState<DeliveryRow[]>([]);
  const [loading,       setLoading]       = useState(false);
  const [retryingId,    setRetryingId]    = useState<number | null>(null);
  const [clearing,      setClearing]      = useState(false);

  const fetchDeliveries = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/webhook-deliveries?limit=50');
      if (res.ok) {
        const data: DeliveryRow[] = await res.json();
        setRows(data);
      }
    } catch {
      // silently fail — table stays empty
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDeliveries();
  }, [fetchDeliveries]);

  const handleRetry = useCallback(async (id: number) => {
    setRetryingId(id);
    try {
      await fetch(`/api/webhook-deliveries/${id}/retry`, { method: 'POST' });
      await fetchDeliveries();
    } catch {
      // silently fail
    } finally {
      setRetryingId(null);
    }
  }, [fetchDeliveries]);

  const handleClearAll = useCallback(async () => {
    if (!window.confirm('Clear all webhook delivery history? This cannot be undone.')) return;
    setClearing(true);
    try {
      await fetch('/api/webhook-deliveries', { method: 'DELETE' });
      setRows([]);
    } catch {
      // silently fail
    } finally {
      setClearing(false);
    }
  }, []);

  return (
    <div className="space-y-3">
      {/* Toolbar row */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-400">
          {rows.length > 0
            ? `Showing ${rows.length} most recent deliveries`
            : 'No webhook deliveries yet'}
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={fetchDeliveries}
            disabled={loading}
            className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 text-xs rounded-lg transition-colors"
            title="Refresh"
          >
            {loading
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
              : <RefreshCw className="w-3.5 h-3.5" />}
            Refresh
          </button>

          {rows.length > 0 && (
            <button
              type="button"
              onClick={handleClearAll}
              disabled={clearing}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-red-900/40 hover:bg-red-900/70 disabled:opacity-40 disabled:cursor-not-allowed text-red-300 text-xs rounded-lg border border-red-800 transition-colors"
            >
              {clearing
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <Trash2 className="w-3.5 h-3.5" />}
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      {rows.length === 0 && !loading ? (
        <div className="flex flex-col items-center gap-2 py-10 text-slate-500">
          <RefreshCw className="w-7 h-7 opacity-30" />
          <p className="text-sm">No webhook deliveries yet</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm border-collapse">
            <thead className="bg-slate-800/60 border-b border-slate-800">
              <tr>
                {['Status', 'Rule', 'Severity', 'HTTP', 'Latency', 'Attempts', 'Time'].map(h => (
                  <th
                    key={h}
                    className="px-3 py-2 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
                {/* retry action column — no header label */}
                <th className="px-3 py-2 w-8" />
              </tr>
            </thead>
            <tbody>
              {rows.map(row => (
                <tr
                  key={row.id}
                  className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors"
                >
                  {/* Status */}
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <span title={row.error ?? row.status}>
                      <StatusIcon status={row.status} />
                    </span>
                  </td>

                  {/* Rule */}
                  <td className="px-3 py-2.5 max-w-[160px]">
                    <span className="block truncate text-xs text-slate-200" title={row.ruleLabel}>
                      {row.ruleLabel}
                    </span>
                    <span className="block truncate text-xs text-slate-500 mt-0.5" title={row.urlPreview}>
                      {row.urlPreview}
                    </span>
                  </td>

                  {/* Severity */}
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <SeverityBadge severity={row.severity} />
                  </td>

                  {/* HTTP code */}
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {row.httpCode != null ? (
                      <span
                        className={`text-xs font-mono ${
                          row.httpCode >= 200 && row.httpCode < 300
                            ? 'text-green-400'
                            : 'text-red-400'
                        }`}
                      >
                        {row.httpCode}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-600">—</span>
                    )}
                  </td>

                  {/* Latency */}
                  <td className="px-3 py-2.5 whitespace-nowrap text-xs font-mono text-slate-400">
                    {row.latencyMs != null ? `${row.latencyMs}ms` : '—'}
                  </td>

                  {/* Attempts */}
                  <td className="px-3 py-2.5 whitespace-nowrap text-xs text-slate-400 text-center">
                    {row.attempts}
                  </td>

                  {/* Time */}
                  <td className="px-3 py-2.5 whitespace-nowrap text-xs text-slate-500">
                    {formatRelativeTime(row.lastAttemptAt ?? row.createdAt)}
                  </td>

                  {/* Retry action */}
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {row.status === 'failed' && (
                      <button
                        type="button"
                        onClick={() => handleRetry(row.id)}
                        disabled={retryingId === row.id}
                        title="Retry delivery"
                        className="flex items-center justify-center w-6 h-6 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-400 hover:text-slate-200 transition-colors"
                      >
                        {retryingId === row.id
                          ? <Loader2 className="w-3 h-3 animate-spin" />
                          : <RotateCw className="w-3 h-3" />}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Inline error from last row if any */}
      {rows.some(r => r.error) && (
        <details className="text-xs text-slate-500">
          <summary className="cursor-pointer hover:text-slate-400 transition-colors select-none">
            Show delivery errors
          </summary>
          <ul className="mt-2 space-y-1 pl-3 border-l border-slate-800">
            {rows.filter(r => r.error).map(r => (
              <li key={r.id} className="text-red-400/80">
                <span className="text-slate-500 mr-1">#{r.id}</span>{r.error}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
