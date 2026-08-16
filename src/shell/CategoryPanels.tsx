import React, { useEffect, useState } from 'react';
import { AlertTriangle, Bookmark, ChevronRight, Cpu, Scale, Settings, Shield, Zap } from 'lucide-react';
import { socket } from '../socket';
import type { Tab } from '../dashboardTypes';
import {
  SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarMenu, SidebarMenuItem,
} from '../components/ui/sidebar';

/**
 * The list column's content for the four categories that are not Observe.
 * Each one is a single block, not a stack of bordered panels: the old sidebar
 * put five equal-weight outlined boxes in one column, which ranked nothing and
 * forced a full left-to-right read every time.
 */

interface AlertLike {
  ruleLabel: string;
  severity: string;
}

const PROTECT_CATEGORIES = [
  { label: 'File Operations',   sev: 'low',      match: /file|read|write|path|fs|directory|dir/i },
  { label: 'Network Access',    sev: 'high',     match: /network|http|curl|wget|dns|fetch|request|url|socket/i },
  { label: 'Command Execution', sev: 'critical', match: /exec|command|bash|shell|spawn|subprocess|reverse[- ]?shell|sudo/i },
  { label: 'Code Injection',    sev: 'high',     match: /inject|eval|payload|deserial|template|sql|xss/i },
  { label: 'Data Exfiltration', sev: 'critical', match: /exfil|leak|upload|credential|secret|token|key|password|env/i },
  { label: 'Prompt Injection',  sev: 'medium',   match: /prompt|jailbreak|ignore previous|system prompt|instruction/i },
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
            if (a.severity === 'high' || a.severity === 'critical') high += 1;
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

function PanelLabel({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <SidebarGroupLabel className="h-6 gap-1.5 text-[10px] font-semibold uppercase tracking-wider">
      {icon}{children}
    </SidebarGroupLabel>
  );
}

export function DetectPanel({ alertCount }: { alertCount: number }) {
  const { highTotal } = useAlertCounts();
  return (
    <SidebarGroup className="p-1.5">
      <PanelLabel icon={<AlertTriangle className="size-3" />}>Alert summary</PanelLabel>
      <SidebarGroupContent className="grid grid-cols-2 gap-1.5 pt-1">
        <Stat value={alertCount} label="Total" />
        <Stat value={highTotal ?? '…'} label="High +" tone="critical" />
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

function Stat({ value, label, tone }: { value: number | string; label: string; tone?: 'critical' }) {
  return (
    <div className="rounded-lg p-2 text-center" style={{ background: tone ? 'var(--cs-sev-critical-bg)' : 'var(--cs-bg-raised)' }}>
      <p className="font-display text-lg font-bold tabular-nums" style={{ color: tone ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-strong)' }}>{value}</p>
      <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>{label}</p>
    </div>
  );
}

export function ProtectPanel() {
  const { counts } = useAlertCounts();
  return (
    <SidebarGroup className="p-1.5">
      <PanelLabel icon={<Shield className="size-3" />}>Rule categories</PanelLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {PROTECT_CATEGORIES.map((category, i) => (
            <SidebarMenuItem key={category.label}>
              <div className="flex h-7 items-center gap-2 rounded-md px-2 text-xs" style={{ color: 'var(--cs-text-muted)' }}>
                <span className="h-3.5 w-[3px] shrink-0 rounded-full" style={{ background: `var(--cs-sev-${category.sev})` }} />
                <span className="min-w-0 flex-1 truncate">{category.label}</span>
                <span className="font-mono tabular-nums" style={{ color: 'var(--cs-text-faint)' }}>{counts[i]}</span>
              </div>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

export function ReviewPanel() {
  return (
    <SidebarGroup className="p-1.5">
      <PanelLabel icon={<Bookmark className="size-3" />}>Bookmarks</PanelLabel>
      <SidebarGroupContent>
        <p className="px-2 py-1 text-[11px] leading-relaxed" style={{ color: 'var(--cs-text-faint)' }}>
          Select a span in the Timeline and bookmark it to pin it here for later review.
        </p>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

export function GovernPanel() {
  return (
    <SidebarGroup className="p-1.5">
      <PanelLabel icon={<Scale className="size-3" />}>Policies</PanelLabel>
      <SidebarGroupContent>
        <p className="px-2 py-1 text-[11px] leading-relaxed" style={{ color: 'var(--cs-text-faint)' }}>
          Twelve plain-English policies, each backed by rules Protect already enforces. This reads
          what already happened — it adds no new detection of its own.
        </p>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

const MANAGE_ITEMS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'harnesses', label: 'Harnesses',     icon: <Cpu className="size-3.5" /> },
  { id: 'costs',     label: 'Cost analysis', icon: <Zap className="size-3.5" /> },
  { id: 'settings',  label: 'Settings',      icon: <Settings className="size-3.5" /> },
];

export function ManagePanel({ activeTab, onTabChange }: { activeTab: Tab; onTabChange: (tab: Tab) => void }) {
  return (
    <SidebarGroup className="p-1.5">
      <PanelLabel icon={<Settings className="size-3" />}>Management</PanelLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {MANAGE_ITEMS.map(item => {
            const isActive = activeTab === item.id;
            return (
              <SidebarMenuItem key={item.id}>
                <button
                  type="button"
                  onClick={() => onTabChange(item.id)}
                  className="flex h-8 w-full items-center gap-2 rounded-md px-2 text-left text-xs transition-colors hover:bg-sidebar-accent"
                  style={isActive
                    ? { background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)' }
                    : { color: 'var(--cs-text-muted)' }}
                >
                  {item.icon}
                  {item.label}
                  <ChevronRight className="ml-auto size-3" style={{ opacity: isActive ? 1 : 0.3 }} />
                </button>
              </SidebarMenuItem>
            );
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
