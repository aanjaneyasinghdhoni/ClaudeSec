/**
 * WebhookDeliverySection — the webhook delivery log, in Settings.
 *
 * Every attempt at the configured webhook URL lands here: status, HTTP code,
 * latency, retry count. It follows the same dense-list pattern as the alert
 * log (see `src/AlertsTab.tsx`, the reference implementation) but embedded in
 * a `Section` card rather than owning a full tab, so it is narrower and its
 * own scroll is modest — at most 50 rows.
 *
 * The measured fact that shaped this rebuild: the `webhook_deliveries` table
 * has had zero rows across 76 days of real use on this install. For most
 * people who ever open this panel, the empty state below *is* the shipping
 * state — so it has to read as "ready and waiting", not "broken", which is
 * why it spells out what lands here and how to make the first row appear.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2, XCircle, RotateCw, Trash2, RefreshCw, Loader2, Clock, Webhook,
} from 'lucide-react';
import {
  DataTable, type DataColumn,
  SeverityBadge, normalizeSeverity,
  EmptyState, ErrorState,
  Toolbar, ToolButton, ToolbarTitle,
} from './components/data';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DeliveryRow {
  id: number;
  ruleLabel: string;
  severity: string;
  urlPreview: string;
  status: 'success' | 'failed' | 'retrying' | 'pending';
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

/** Exported for the unit test — pure, no clock injection needed at call sites. */
export function formatRelativeTime(iso: string): string {
  try {
    const delta = Date.now() - new Date(iso).getTime();
    if (delta < 60_000)     return `${Math.round(delta / 1000)}s ago`;
    if (delta < 3_600_000)  return `${Math.round(delta / 60_000)}m ago`;
    if (delta < 86_400_000) return `${Math.round(delta / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch { return '—'; }
}

// Delivery status is independent of the alert severity that triggered it — a
// LOW-severity alert can still fail to deliver. Each gets its own icon and
// word so the meaning survives without the colour, same rule as severity.
const STATUS_META: Record<DeliveryRow['status'], { label: string; color: string; Icon: typeof Clock; spin?: boolean }> = {
  success:  { label: 'Delivered', color: 'var(--cs-ok)',        Icon: CheckCircle2 },
  failed:   { label: 'Failed',    color: 'var(--cs-danger)',    Icon: XCircle },
  retrying: { label: 'Retrying',  color: 'var(--cs-warn)',      Icon: RotateCw, spin: true },
  pending:  { label: 'Pending',   color: 'var(--cs-text-faint)', Icon: Clock },
};

function StatusIcon({ status }: { status: DeliveryRow['status'] }) {
  const meta = STATUS_META[status] ?? STATUS_META.pending;
  const { Icon } = meta;
  return (
    <Icon
      className={`w-3.5 h-3.5 ${meta.spin ? 'animate-spin' : ''}`}
      style={{ color: meta.color }}
      aria-hidden="true"
    />
  );
}

// ---------------------------------------------------------------------------
// WebhookDeliverySection
// ---------------------------------------------------------------------------

export function WebhookDeliverySection() {
  const [rows,        setRows]        = useState<DeliveryRow[]>([]);
  const [total,        setTotal]      = useState(0);
  // `loading` gates the skeleton and only applies to the first fetch — a
  // manual refresh reuses `refreshing` so the table doesn't flash back to a
  // skeleton every time someone clicks the button.
  const [loading,      setLoading]    = useState(true);
  const [refreshing,   setRefreshing] = useState(false);
  const [loadError,    setLoadError]  = useState<string | null>(null);
  const [retryingId,   setRetryingId] = useState<number | null>(null);
  const [clearing,     setClearing]   = useState(false);
  // A row with a delivery error can be expanded in place to read the full
  // message — the roving-tabindex equivalent of the old "Show delivery
  // errors" <details> block, but scoped to the row it belongs to.
  const [expandedId,   setExpandedId] = useState<number | null>(null);

  const fetchDeliveries = useCallback((isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    fetch('/api/webhook-deliveries?limit=50')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((json: { deliveries?: DeliveryRow[]; total?: number } | DeliveryRow[]) => {
        const data = Array.isArray(json) ? json : (json.deliveries ?? []);
        setRows(data);
        setTotal(Array.isArray(json) ? data.length : (json.total ?? data.length));
        setLoadError(null);
      })
      // A settings panel that silently shows an empty table on a real fetch
      // failure reads as "webhooks are unused" when the truth is "the view
      // is broken" — those are different messages and the operator needs to
      // be able to tell them apart.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => { setLoading(false); setRefreshing(false); });
  }, []);

  useEffect(() => {
    fetchDeliveries();
  }, [fetchDeliveries]);

  // Escape collapses an expanded error row, same affordance as closing a
  // drawer elsewhere in the app.
  useEffect(() => {
    if (expandedId == null) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpandedId(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expandedId]);

  const handleRetry = useCallback(async (id: number) => {
    setRetryingId(id);
    try {
      await fetch(`/api/webhook-deliveries/${id}/retry`, { method: 'POST' });
      fetchDeliveries();
    } catch {
      // The row's own status simply won't change on the next fetch — no
      // separate banner needed for a single retry click.
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
      setTotal(0);
    } catch {
      // silently fail — the list still reflects the last successful fetch
    } finally {
      setClearing(false);
    }
  }, []);

  // ── Columns ──────────────────────────────────────────────────────────────
  // Narrower set than the alert log's, because this table lives inside a
  // 640px settings card rather than owning the screen. Status, rule and
  // severity survive at every width; HTTP/latency/attempts are furniture that
  // drops first.
  const columns: DataColumn<DeliveryRow>[] = [
    {
      id: 'status', header: '', width: '24px',
      cell: d => <span title={STATUS_META[d.status]?.label ?? d.status}><StatusIcon status={d.status} /></span>,
    },
    {
      id: 'rule', header: 'Rule', width: 'minmax(0,1.3fr)',
      cell: d => (
        <span className="flex flex-col min-w-0 py-0.5">
          <span
            className="truncate"
            title={d.ruleLabel}
            style={{ color: 'var(--cs-text-body)', fontWeight: 'var(--cs-weight-medium)' }}
          >
            {d.ruleLabel}
          </span>
          <span className="cs-mono truncate" title={d.urlPreview} style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>
            {d.urlPreview}
          </span>
        </span>
      ),
    },
    {
      id: 'severity', header: 'Severity', width: '100px',
      cell: d => <SeverityBadge severity={normalizeSeverity(d.severity)} />,
    },
    {
      id: 'http', header: 'HTTP', width: '46px', hideBelow: 'xl', align: 'end', mono: true,
      cell: d => d.httpCode != null
        ? <span style={{ color: d.httpCode >= 200 && d.httpCode < 300 ? 'var(--cs-ok)' : 'var(--cs-danger)' }}>{d.httpCode}</span>
        : <span style={{ color: 'var(--cs-text-faint)' }}>—</span>,
    },
    {
      id: 'latency', header: 'Latency', width: '64px', hideBelow: 'xl', align: 'end', mono: true,
      cell: d => <span>{d.latencyMs != null ? `${d.latencyMs}ms` : '—'}</span>,
    },
    {
      id: 'attempts', header: 'Tries', width: '48px', hideBelow: '2xl', align: 'end', mono: true,
      cell: d => <span>{d.attempts}</span>,
    },
    {
      id: 'time', header: 'Time', width: '72px', hideBelow: 'xl', mono: true,
      cell: d => (
        <span title={new Date(d.lastAttemptAt ?? d.createdAt).toLocaleString()}>
          {formatRelativeTime(d.lastAttemptAt ?? d.createdAt)}
        </span>
      ),
    },
    {
      id: 'retry', header: '', width: '28px', align: 'end',
      cell: d => (
        <span onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
          {d.status === 'failed' && (
            <button
              type="button"
              onClick={() => handleRetry(d.id)}
              disabled={retryingId === d.id}
              title="Retry delivery"
              className="p-1 rounded transition-colors disabled:opacity-50"
              style={{ color: 'var(--cs-text-faint)' }}
            >
              {retryingId === d.id
                ? <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                : <RotateCw className="w-3 h-3" aria-hidden="true" />}
            </button>
          )}
        </span>
      ),
    },
  ];

  const renderDetail = (d: DeliveryRow) => {
    if (!d.error || expandedId !== d.id) return null;
    return (
      <div style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-danger)', lineHeight: 'var(--cs-leading-normal)' }}>
        {d.error}
      </div>
    );
  };

  const staleWarning = loadError && rows.length > 0;

  return (
    <div className="rounded-lg overflow-hidden" style={{ background: 'var(--cs-bg-sunken)' }}>
      <Toolbar>
        <ToolbarTitle
          icon={<Webhook className="w-3.5 h-3.5" />}
          count={rows.length > 0 ? `${rows.length}${total > rows.length ? `/${total}` : ''}` : undefined}
          countTitle={`Showing ${rows.length} of ${total} deliveries`}
        >
          Deliveries
        </ToolbarTitle>
        {staleWarning && (
          <span
            role="status"
            title={`Last refresh failed (${loadError}). The list below is what was last loaded successfully.`}
            style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-xs)' }}
          >
            Stale
          </span>
        )}
        <div className="flex items-center gap-1 ml-auto">
          <ToolButton onClick={() => fetchDeliveries(true)} disabled={refreshing} title="Refresh">
            {refreshing
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
              : <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />}
            Refresh
          </ToolButton>
          {rows.length > 0 && (
            <ToolButton danger onClick={handleClearAll} disabled={clearing} title="Delete every delivery record — cannot be undone">
              {clearing
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                : <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />}
              Clear
            </ToolButton>
          )}
        </div>
      </Toolbar>

      <DataTable
        rows={rows}
        columns={columns}
        rowKey={d => d.id}
        label="Webhook deliveries"
        minWidth={360}
        severity={d => normalizeSeverity(d.severity)}
        onActivate={d => setExpandedId(prev => prev === d.id ? null : d.id)}
        renderDetail={renderDetail}
        loading={loading}
        error={loadError && rows.length === 0 ? (
          <ErrorState
            description={`The delivery log did not respond (${loadError}). Webhook delivery itself is unaffected — this is only the view.`}
            onRetry={() => { setLoading(true); fetchDeliveries(); }}
          />
        ) : undefined}
        empty={(
          <EmptyState
            icon={<Webhook className="w-6 h-6" aria-hidden="true" />}
            title="No deliveries yet"
            description="This fills in the moment your webhook receives its first alert — every attempt lands here with its status, HTTP code, latency and retry count, success or failure. A good first webhook is any HTTPS endpoint that returns 2xx quickly, like a Slack incoming webhook. Configure one above, then use its “Send test” button — the delivery appears here within a second."
          />
        )}
      />
    </div>
  );
}
