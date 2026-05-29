/**
 * ContextSidebar — Shows different sidebar content based on the active category.
 * Observe: Sessions + Filters + Spans (existing sidebar)
 * Detect: Alert stats + severity filter
 * Protect: Rule search + categories
 * Review: Bookmark info
 * Manage: Settings nav links
 */
import React from 'react';
import {
  AlertTriangle, Shield, Search, Bookmark, Settings,
  Cpu, Zap, Database, Bell, ChevronRight,
} from 'lucide-react';
import type { Category } from './CategoryNav';

// ── Detect Sidebar ─────────────────────────────────────────────────────────
function DetectSidebar({ alertCount }: { alertCount: number }) {
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
            <p className="text-lg font-bold font-mono" style={{ color: '#ff3b5c' }}>—</p>
            <p className="text-[9px] uppercase tracking-wider font-mono" style={{ color: '#ff3b5c' }}>High</p>
          </div>
        </div>
      </div>
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <Search className="w-3 h-3" /> Quick Filters
        </p>
        <div className="space-y-1">
          {['Last 1 hour', 'Last 24 hours', 'Last 7 days', 'All time'].map(label => (
            <button
              key={label}
              className="w-full text-left px-2.5 py-1.5 rounded-md text-xs font-medium transition-all"
              style={{ color: 'var(--cs-text-muted)' }}
              onMouseEnter={e => (e.target as HTMLElement).style.background = 'var(--cs-bg-elevated)'}
              onMouseLeave={e => (e.target as HTMLElement).style.background = 'transparent'}
            >
              {label}
            </button>
          ))}
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
  const categories = [
    { label: 'File Operations', color: '#3b82f6' },
    { label: 'Network Access', color: '#f97316' },
    { label: 'Command Execution', color: '#ef4444' },
    { label: 'Code Injection', color: '#a855f7' },
    { label: 'Data Exfiltration', color: '#eab308' },
    { label: 'Prompt Injection', color: '#ec4899' },
  ];
  return (
    <div className="flex flex-col h-full">
      <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <p className="sidebar-section-label mb-2">
          <Shield className="w-3 h-3" /> Rule Categories
        </p>
        <div className="space-y-1">
          {categories.map(c => (
            <div key={c.label} className="flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs" style={{ color: 'var(--cs-text-muted)' }}>
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c.color }} />
              {c.label}
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
            Bookmark spans from the timeline to see them here
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
                background: isActive ? 'rgba(0,212,170,0.1)' : 'transparent',
                color: isActive ? '#00d4aa' : 'var(--cs-text-muted)',
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
  /** Observe sidebar is rendered inline in App.tsx (too much state to extract cleanly) */
  observeContent?: React.ReactNode;
}

export function ContextSidebar({ category, alertCount, activeTab, onTabChange, observeContent }: ContextSidebarProps) {
  return (
    <aside className="w-64 flex flex-col overflow-hidden shrink-0" style={{ borderRight: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}>
      {category === 'observe' && observeContent}
      {category === 'detect' && <DetectSidebar alertCount={alertCount} />}
      {category === 'protect' && <ProtectSidebar />}
      {category === 'review' && <ReviewSidebar />}
      {category === 'manage' && <ManageSidebar activeTab={activeTab} onTabChange={onTabChange} />}
    </aside>
  );
}
