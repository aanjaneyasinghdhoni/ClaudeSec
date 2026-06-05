/**
 * ContextSidebar — Shows different sidebar content based on the active category.
 * Observe: Sessions + Filters + Spans (existing sidebar)
 * Detect: Alert stats + severity filter
 * Protect: Rule search + categories
 * Review: Bookmark info
 * Manage: Settings nav links
 */
import React, { useEffect, useState } from 'react';
import {
  AlertTriangle, Shield, Search, Bookmark, Settings,
  Cpu, Zap, Database, Bell, ChevronRight, X,
} from 'lucide-react';
import type { Category } from './CategoryNav';
import { socket } from './socket';

interface AlertLike {
  ruleLabel: string;
  severity: string;
}

const PROTECT_CATEGORIES = [
  { label: 'File Operations',   color: '#3b82f6', match: /file|read|write|path|fs|directory|dir/i },
  { label: 'Network Access',    color: '#f97316', match: /network|http|curl|wget|dns|fetch|request|url|socket/i },
  { label: 'Command Execution', color: '#ef4444', match: /exec|command|bash|shell|spawn|subprocess|reverse[- ]?shell|sudo/i },
  { label: 'Code Injection',    color: '#a855f7', match: /inject|eval|payload|deserial|template|sql|xss/i },
  { label: 'Data Exfiltration', color: '#eab308', match: /exfil|leak|upload|credential|secret|token|key|password|env/i },
  { label: 'Prompt Injection',  color: '#ec4899', match: /prompt|jailbreak|ignore previous|system prompt|instruction/i },
] as const;

function categorizeRule(ruleLabel: string): number {
  for (let i = 0; i < PROTECT_CATEGORIES.length; i++) {
    if (PROTECT_CATEGORIES[i].match.test(ruleLabel)) return i;
  }
  return 2;
}

function useAlertCounts() {
  const [counts, setCounts] = useState<number[]>(() => PROTECT_CATEGORIES.map(() => 0));
  const [highTotal, setHighTotal] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      fetch('/api/alerts?limit=1000')
        .then(r => r.json())
        .then(({ alerts }: { alerts: AlertLike[] }) => {
          if (cancelled) return;
          const next = PROTECT_CATEGORIES.map(() => 0);
          let high = 0;
          for (const a of alerts ?? []) {
            next[categorizeRule(a.ruleLabel ?? '')] += 1;
            if (a.severity === 'high') high += 1;
          }
          setCounts(next);
          setHighTotal(high);
        })
        .catch(() => {});
    };
    load();
    socket.on('alerts-update', load);
    return () => { cancelled = true; socket.off('alerts-update', load); };
  }, []);

  return { counts, highTotal };
}

export type TimeRange = '1h' | '24h' | '7d' | 'all';

const TIME_RANGES: { label: string; range: TimeRange }[] = [
  { label: 'Last 1 hour',   range: '1h' },
  { label: 'Last 24 hours', range: '24h' },
  { label: 'Last 7 days',   range: '7d' },
  { label: 'All time',      range: 'all' },
];

// ── Quick Filters (time range) ──────────────────────────────────────────────
// Lives in the OBSERVE sidebar, next to the Timeline it actually filters
// (timeRange drives visibleWorkflows). It used to sit in the Detect sidebar,
// which only shows Alerts/Search — so the buttons appeared to do nothing.
function QuickFilters({ timeRange, onTimeRangeChange }: {
  timeRange: TimeRange;
  onTimeRangeChange: (range: TimeRange) => void;
}) {
  return (
    <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
      <p className="sidebar-section-label mb-2">
        <Search className="w-3 h-3" /> Quick Filters
      </p>
      <div className="space-y-1">
        {TIME_RANGES.map(({ label, range }) => {
          const isActive = timeRange === range;
          return (
            <button
              key={range}
              onClick={() => onTimeRangeChange(range)}
              className="w-full text-left px-2.5 py-1.5 rounded-md text-xs font-medium transition-all"
              style={{
                background: isActive ? 'rgba(var(--cs-accent-rgb),0.1)' : 'transparent',
                color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-muted)',
              }}
            >
              {label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Detect Sidebar ─────────────────────────────────────────────────────────
function DetectSidebar({ alertCount }: { alertCount: number }) {
  const { highTotal } = useAlertCounts();
  return (
    <div className="flex flex-col h-full">
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <AlertTriangle className="w-3 h-3" /> Alert Summary
        </p>
        <div className="grid grid-cols-2 gap-1.5">
          <div className="p-2 rounded-lg text-center" style={{ background: 'var(--cs-bg-primary)', border: '1px solid var(--cs-border)' }}>
            <p className="text-lg font-bold font-mono" style={{ color: 'var(--cs-text-base)' }}>{alertCount}</p>
            <p className="text-[9px] uppercase tracking-wider font-mono" style={{ color: 'var(--cs-text-faint)' }}>Total</p>
          </div>
          <div className="p-2 rounded-lg text-center" style={{ background: 'rgba(255,59,92,0.06)', border: '1px solid rgba(255,59,92,0.15)' }}>
            <p className="text-lg font-bold font-mono" style={{ color: '#ff3b5c' }}>{highTotal ?? '…'}</p>
            <p className="text-[9px] uppercase tracking-wider font-mono" style={{ color: '#ff3b5c' }}>High</p>
          </div>
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center p-4">
        <p className="text-[11px] text-center" style={{ color: 'var(--cs-text-faint)' }}>
          Select an alert in the main view to see details
        </p>
      </div>
    </div>
  );
}

// ── Protect Sidebar ────────────────────────────────────────────────────────
function ProtectSidebar() {
  const { counts } = useAlertCounts();
  return (
    <div className="flex flex-col h-full">
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <Shield className="w-3 h-3" /> Rule Categories
        </p>
        <div className="space-y-1">
          {PROTECT_CATEGORIES.map((c, i) => (
            <div key={c.label} className="flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs" style={{ color: 'var(--cs-text-muted)' }}>
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c.color }} />
              <span className="flex-1 truncate">{c.label}</span>
              <span className="font-mono tabular-nums shrink-0" style={{ color: 'var(--cs-text-faint)' }}>{counts[i]}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center p-4">
        <p className="text-[11px] text-center" style={{ color: 'var(--cs-text-faint)' }}>
          Manage security rules in the main panel
        </p>
      </div>
    </div>
  );
}

// ── Review Sidebar ─────────────────────────────────────────────────────────
function ReviewSidebar() {
  return (
    <div className="flex flex-col h-full">
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <Bookmark className="w-3 h-3" /> Bookmarks
        </p>
        <p className="text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
          Saved spans and sessions for quick access.
        </p>
      </div>
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="text-center">
          <Bookmark className="w-8 h-8 mx-auto mb-2" style={{ color: 'var(--cs-text-faint)', opacity: 0.4 }} />
          <p className="text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
            Select a span in the Timeline and click the bookmark icon to see it here
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Manage Sidebar ─────────────────────────────────────────────────────────
interface ManageSidebarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}
function ManageSidebar({ activeTab, onTabChange }: ManageSidebarProps) {
  const items = [
    { id: 'harnesses', label: 'Harnesses', icon: <Cpu className="w-3.5 h-3.5" /> },
    { id: 'costs',     label: 'Cost Analysis', icon: <Zap className="w-3.5 h-3.5" /> },
    { id: 'settings',  label: 'Settings', icon: <Settings className="w-3.5 h-3.5" /> },
  ];
  return (
    <div className="flex flex-col h-full">
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <Settings className="w-3 h-3" /> Management
        </p>
      </div>
      <div className="p-2 space-y-0.5">
        {items.map(item => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-medium transition-all text-left"
              style={{
                background: isActive ? 'rgba(var(--cs-accent-rgb),0.1)' : 'transparent',
                color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-muted)',
              }}
            >
              {item.icon}
              {item.label}
              <ChevronRight className="w-3 h-3 ml-auto" style={{ opacity: isActive ? 1 : 0.3 }} />
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Export ─────────────────────────────────────────────────────────────
export interface ContextSidebarProps {
  category: Category;
  alertCount: number;
  activeTab: string;
  onTabChange: (tab: string) => void;
  timeRange: TimeRange;
  onTimeRangeChange: (range: TimeRange) => void;
  /** Observe sidebar is rendered inline in App.tsx (too much state to extract cleanly) */
  observeContent?: React.ReactNode;
  /** Drawer state (below lg). At >=lg the sidebar is always a static in-row column. */
  isOpen?: boolean;
  onClose?: () => void;
}

export function ContextSidebar({ category, alertCount, activeTab, onTabChange, timeRange, onTimeRangeChange, observeContent, isOpen = false, onClose }: ContextSidebarProps) {
  return (
    <aside
      className={`w-64 flex flex-col overflow-hidden bg-[var(--cs-bg-surface)] fixed inset-y-0 left-0 z-40 transition-transform duration-300 ease-out motion-reduce:transition-none lg:static lg:z-auto lg:translate-x-0 lg:shrink-0 lg:transition-none ${isOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full'}`}
      style={{ borderRight: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}
    >
      {/* Drawer close bar — below lg only */}
      <div className="lg:hidden flex items-center justify-end px-2.5 py-2 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <button
          onClick={onClose}
          className="inline-flex items-center justify-center w-9 h-9 rounded-lg transition-colors"
          style={{ color: 'var(--cs-text-muted)' }}
          aria-label="Close sidebar"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      {category === 'observe' && (
        <>
          <QuickFilters timeRange={timeRange} onTimeRangeChange={onTimeRangeChange} />
          {observeContent}
        </>
      )}
      {category === 'detect' && <DetectSidebar alertCount={alertCount} />}
      {category === 'protect' && <ProtectSidebar />}
      {category === 'review' && <ReviewSidebar />}
      {category === 'manage' && <ManageSidebar activeTab={activeTab} onTabChange={onTabChange} />}
    </aside>
  );
}
