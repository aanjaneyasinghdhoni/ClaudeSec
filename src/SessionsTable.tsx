// src/SessionsTable.tsx
import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import {
  Activity, Shield, Star, Edit2, Trash2, ChevronUp, ChevronDown,
  Search, X,
} from 'lucide-react';

type SessionLabel = 'normal' | 'incident' | 'investigation' | 'automated' | 'other';

interface Session {
  traceId: string;
  name: string;
  createdAt: string;
  pinned: number;
  label: SessionLabel;
  notes: string;
  spanCount: number;
  threatCount: number;
  maxSeverityRank: number;
  harnesses: string | null;
  healthScore?: number;
  riskScore?: number;
  threatHigh?: number;
  threatMedium?: number;
  threatLow?: number;
  alertCount?: number;
}

interface SessionsTableProps {
  sessions: Session[];
  onOpenGraph: (traceId: string) => void;
  onPin: (traceId: string, pinned: boolean) => void;
  onRename: (traceId: string, name: string) => void;
  onDelete: (traceId: string) => void;
}

type SortField = 'name' | 'harness' | 'spanCount' | 'threatCount' | 'riskScore' | 'healthScore' | 'createdAt';
type SortDir = 'asc' | 'desc';

const LABEL_COLORS: Record<SessionLabel, string> = {
  normal: '#64748b',
  incident: '#ef4444',
  investigation: '#f97316',
  automated: '#3b82f6',
  other: '#a855f7',
};

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'github-copilot': '#6366f1',
  'openhands': '#22c55e',
  'cursor': '#a855f7',
  'aider': '#ec4899',
  'cline': '#14b8a6',
  'goose': '#f59e0b',
  'continue': '#0ea5e9',
  'windsurf': '#38bdf8',
  'unknown': '#64748b',
};

const ROW_HEIGHT = 44;
const OVERSCAN = 5;

function useVirtualScroll(totalItems: number, containerRef: React.RefObject<HTMLDivElement | null>) {
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(600);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver(entries => {
      for (const entry of entries) setContainerHeight(entry.contentRect.height);
    });
    obs.observe(el);
    setContainerHeight(el.clientHeight);
    return () => obs.disconnect();
  }, [containerRef]);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop((e.target as HTMLDivElement).scrollTop);
  }, []);

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const visibleCount = Math.ceil(containerHeight / ROW_HEIGHT) + OVERSCAN * 2;
  const endIndex = Math.min(totalItems, startIndex + visibleCount);

  return { startIndex, endIndex, handleScroll, totalHeight: totalItems * ROW_HEIGHT };
}

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function SessionsTable({ sessions, onOpenGraph, onPin, onRename, onDelete }: SessionsTableProps) {
  const [sortField, setSortField] = useState<SortField>('createdAt');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [filterText, setFilterText] = useState('');
  const [labelFilter, setLabelFilter] = useState<SessionLabel | 'all'>('all');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir(field === 'name' || field === 'harness' ? 'asc' : 'desc');
    }
  };

  const filtered = useMemo(() => {
    let list = sessions;
    if (filterText) {
      const q = filterText.toLowerCase();
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        (s.harnesses ?? '').toLowerCase().includes(q)
      );
    }
    if (labelFilter !== 'all') {
      list = list.filter(s => (s.label ?? 'normal') === labelFilter);
    }
    return list;
  }, [sessions, filterText, labelFilter]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      if (a.pinned && !b.pinned) return -1;
      if (!a.pinned && b.pinned) return 1;
      let cmp = 0;
      switch (sortField) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'harness': cmp = (a.harnesses ?? '').localeCompare(b.harnesses ?? ''); break;
        case 'spanCount': cmp = a.spanCount - b.spanCount; break;
        case 'threatCount': cmp = a.threatCount - b.threatCount; break;
        case 'riskScore': cmp = (a.riskScore ?? 0) - (b.riskScore ?? 0); break;
        case 'healthScore': cmp = (a.healthScore ?? 0) - (b.healthScore ?? 0); break;
        case 'createdAt': cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(); break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return arr;
  }, [filtered, sortField, sortDir]);

  const { startIndex, endIndex, handleScroll, totalHeight } = useVirtualScroll(sorted.length, containerRef);

  const commitRename = (traceId: string) => {
    const trimmed = editName.trim();
    if (trimmed) onRename(traceId, trimmed);
    setEditingId(null);
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDir === 'asc'
      ? <ChevronUp className="w-3 h-3 inline ml-0.5" />
      : <ChevronDown className="w-3 h-3 inline ml-0.5" />;
  };

  return (
    <div className="flex flex-col h-full" style={{ background: 'var(--cs-bg-primary)' }}>
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <div className="relative flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }} />
          <input
            value={filterText}
            onChange={e => setFilterText(e.target.value)}
            placeholder="Filter sessions..."
            className="w-full pl-7 pr-7 py-1.5 text-xs rounded-md outline-none"
            style={{
              background: 'var(--cs-bg-elevated)',
              border: '1px solid var(--cs-border)',
              color: 'var(--cs-text-base)',
            }}
          />
          {filterText && (
            <button onClick={() => setFilterText('')} className="absolute right-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }}>
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'incident', 'investigation', 'automated', 'other'] as const).map(l => (
            <button
              key={l}
              onClick={() => setLabelFilter(l)}
              className="px-2 py-1 text-[10px] font-medium rounded-md transition-all"
              style={
                labelFilter === l
                  ? l === 'all'
                    ? { background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-base)', border: '1px solid var(--cs-border-soft)' }
                    : { background: (LABEL_COLORS[l] ?? '#64748b') + '22', color: LABEL_COLORS[l], border: `1px solid ${LABEL_COLORS[l]}44` }
                  : { background: 'transparent', color: 'var(--cs-text-faint)', border: '1px solid transparent' }
              }
            >
              {l === 'all' ? 'All' : l}
            </button>
          ))}
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'var(--cs-text-faint)' }}>
          {filtered.length} session{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table header */}
      <div className="grid shrink-0 px-4 py-2 text-[10px] font-bold uppercase tracking-wider select-none"
        style={{
          gridTemplateColumns: '2fr 1fr 80px 120px 100px 90px 80px',
          color: 'var(--cs-text-faint)',
          borderBottom: '1px solid var(--cs-border)',
          background: 'var(--cs-bg-surface)',
        }}
      >
        <button className="text-left hover:text-white transition-colors" onClick={() => toggleSort('name')}>
          Name <SortIcon field="name" />
        </button>
        <button className="text-left hover:text-white transition-colors" onClick={() => toggleSort('harness')}>
          Harness <SortIcon field="harness" />
        </button>
        <button className="text-right hover:text-white transition-colors" onClick={() => toggleSort('spanCount')}>
          Spans <SortIcon field="spanCount" />
        </button>
        <button className="text-center hover:text-white transition-colors" onClick={() => toggleSort('threatCount')}>
          Threats <SortIcon field="threatCount" />
        </button>
        <button className="text-center hover:text-white transition-colors" onClick={() => toggleSort('riskScore')}>
          Risk <SortIcon field="riskScore" />
        </button>
        <button className="text-right hover:text-white transition-colors" onClick={() => toggleSort('createdAt')}>
          Started <SortIcon field="createdAt" />
        </button>
        <div className="text-right">Actions</div>
      </div>

      {/* Virtual scrolling body */}
      <div ref={containerRef} onScroll={handleScroll} className="flex-1 overflow-y-auto min-h-0">
        <div style={{ height: totalHeight, position: 'relative' }}>
          {sorted.slice(startIndex, endIndex).map((s, i) => {
            const idx = startIndex + i;
            const risk = s.riskScore ?? 0;
            const riskColor = risk >= 70 ? '#ef4444' : risk >= 30 ? '#f59e0b' : '#22c55e';
            const harnessList = (s.harnesses ?? 'unknown').split(',');
            const isEditing = editingId === s.traceId;

            return (
              <div
                key={s.traceId}
                className="grid items-center px-4 text-xs transition-colors hover:bg-white/[0.03] group cursor-pointer"
                style={{
                  gridTemplateColumns: '2fr 1fr 80px 120px 100px 90px 80px',
                  height: ROW_HEIGHT,
                  position: 'absolute',
                  top: idx * ROW_HEIGHT,
                  left: 0,
                  right: 0,
                  contain: 'content',
                  borderBottom: '1px solid color-mix(in srgb, var(--cs-border) 30%, transparent)',
                }}
                onClick={() => onOpenGraph(s.traceId)}
              >
                {/* Name */}
                <div className="flex items-center gap-2 min-w-0 pr-2">
                  {!!s.pinned && <Star className="w-3 h-3 text-yellow-400 shrink-0 fill-yellow-400" />}
                  {isEditing ? (
                    <form className="flex-1 min-w-0" onSubmit={e => { e.preventDefault(); commitRename(s.traceId); }} onClick={e => e.stopPropagation()}>
                      <input
                        autoFocus
                        value={editName}
                        onChange={e => setEditName(e.target.value)}
                        onBlur={() => commitRename(s.traceId)}
                        className="w-full text-xs rounded px-1 py-0.5 outline-none"
                        style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-base)' }}
                      />
                    </form>
                  ) : (
                    <span className="truncate" style={{ color: 'var(--cs-text-base)' }}>{s.name}</span>
                  )}
                </div>

                {/* Harness */}
                <div className="flex items-center gap-1 min-w-0">
                  {harnessList.slice(0, 2).map(h => (
                    <span key={h} className="px-1.5 py-0.5 rounded text-[10px] font-medium truncate"
                      style={{ background: (HARNESS_COLORS[h.trim()] ?? '#64748b') + '22', color: HARNESS_COLORS[h.trim()] ?? '#64748b' }}>
                      {h.trim()}
                    </span>
                  ))}
                  {harnessList.length > 2 && <span className="text-[10px]" style={{ color: 'var(--cs-text-faint)' }}>+{harnessList.length - 2}</span>}
                </div>

                {/* Spans */}
                <div className="text-right font-mono" style={{ color: 'var(--cs-text-muted)' }}>
                  {s.spanCount.toLocaleString()}
                </div>

                {/* Threats */}
                <div className="flex items-center justify-center gap-1">
                  {(s.threatHigh ?? 0) > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: '#ef444422', color: '#ef4444' }}>
                      {s.threatHigh} H
                    </span>
                  )}
                  {(s.threatMedium ?? 0) > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: '#f9731622', color: '#f97316' }}>
                      {s.threatMedium} M
                    </span>
                  )}
                  {(s.threatLow ?? 0) > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: '#eab30822', color: '#eab308' }}>
                      {s.threatLow} L
                    </span>
                  )}
                  {s.threatCount === 0 && (
                    <span className="text-[10px]" style={{ color: 'var(--cs-text-faint)' }}>-</span>
                  )}
                </div>

                {/* Risk bar */}
                <div className="flex items-center gap-2 justify-center">
                  <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--cs-bg-elevated)' }}>
                    <div className="h-full rounded-full transition-all" style={{ width: `${risk}%`, background: riskColor }} />
                  </div>
                  <span className="text-[10px] font-mono w-6 text-right" style={{ color: riskColor }}>{risk}</span>
                </div>

                {/* Started */}
                <div className="text-right text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
                  {timeAgo(s.createdAt)}
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
                  <button
                    onClick={() => onPin(s.traceId, !s.pinned)}
                    className="p-1 rounded hover:bg-white/10 transition-colors"
                    title={s.pinned ? 'Unpin' : 'Pin'}
                    style={{ color: s.pinned ? '#facc15' : 'var(--cs-text-faint)' }}
                  >
                    <Star className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => { setEditingId(s.traceId); setEditName(s.name); }}
                    className="p-1 rounded hover:bg-white/10 transition-colors"
                    title="Rename"
                    style={{ color: 'var(--cs-text-faint)' }}
                  >
                    <Edit2 className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => onDelete(s.traceId)}
                    className="p-1 rounded hover:bg-red-900/30 transition-colors"
                    title="Delete session"
                    style={{ color: 'var(--cs-text-faint)' }}
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Empty state */}
        {sorted.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full gap-2" style={{ color: 'var(--cs-text-faint)' }}>
            <Shield className="w-8 h-8 opacity-30" />
            <p className="text-sm">No sessions found</p>
            {filterText && <p className="text-xs">Try adjusting your filters</p>}
          </div>
        )}
      </div>
    </div>
  );
}
