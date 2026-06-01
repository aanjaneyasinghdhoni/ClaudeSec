import React, { useEffect, useState } from 'react';
import {
  Eye, AlertTriangle, Shield, Bookmark, Settings, PanelLeftClose, PanelLeftOpen, BookOpen,
} from 'lucide-react';

export type Category = 'observe' | 'detect' | 'protect' | 'review' | 'manage';

export const CATEGORIES: { id: Category; label: string; icon: React.ReactNode }[] = [
  { id: 'observe', label: 'Observe',  icon: <Eye className="w-4 h-4 shrink-0" /> },
  { id: 'detect',  label: 'Detect',   icon: <AlertTriangle className="w-4 h-4 shrink-0" /> },
  { id: 'protect', label: 'Protect',  icon: <Shield className="w-4 h-4 shrink-0" /> },
  { id: 'review',  label: 'Review',   icon: <Bookmark className="w-4 h-4 shrink-0" /> },
  { id: 'manage',  label: 'Manage',   icon: <Settings className="w-4 h-4 shrink-0" /> },
];

const STORAGE_KEY = 'claudesec.railCollapsed';

interface Props {
  active: Category;
  onChange: (cat: Category) => void;
  alertCount?: number;
}

export function CategoryNav({ active, onChange, alertCount = 0 }: Props) {
  const [collapsed, setCollapsed] = useState<boolean>(
    () => localStorage.getItem(STORAGE_KEY) === 'true'
  );

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, String(collapsed)); } catch { /* ignore */ }
  }, [collapsed]);

  return (
    <div
      className={`shrink-0 flex flex-col py-3 px-2 gap-1 transition-[width] duration-200 ease-out overflow-hidden ${collapsed ? 'w-[56px] items-center' : 'w-[180px]'}`}
      style={{
        borderRight: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}
    >
      <button
        onClick={() => setCollapsed(v => !v)}
        title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        className={`category-btn h-10 rounded-xl flex items-center mb-1 ${collapsed ? 'w-10 justify-center' : 'w-full px-2.5 gap-2.5'}`}
        style={{ color: 'var(--cs-text-faint)' }}
      >
        {collapsed ? <PanelLeftOpen className="w-4 h-4 shrink-0" /> : <PanelLeftClose className="w-4 h-4 shrink-0" />}
        {!collapsed && (
          <span className="text-xs font-medium tracking-wide whitespace-nowrap">Collapse</span>
        )}
      </button>

      {CATEGORIES.map(cat => {
        const isActive = active === cat.id;
        return (
          <button
            key={cat.id}
            onClick={() => onChange(cat.id)}
            title={cat.label}
            className={`category-btn relative h-10 rounded-xl flex items-center ${collapsed ? 'w-10 justify-center' : 'w-full px-2.5 gap-2.5'}`}
            style={{
              background: isActive ? 'rgba(var(--cs-accent-rgb),0.1)' : 'transparent',
              color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
            }}
          >
            {cat.icon}
            {!collapsed && (
              <span className="text-xs font-medium tracking-wide whitespace-nowrap">{cat.label}</span>
            )}

            {cat.id === 'detect' && alertCount > 0 && (
              <span
                className={`min-w-[16px] h-[16px] px-1 text-[9px] font-bold rounded-full flex items-center justify-center leading-none bg-rose-500 text-white ${
                  collapsed ? 'absolute -top-0.5 -right-0.5' : 'ml-auto'
                }`}
              >
                {alertCount > 99 ? '99+' : alertCount}
              </span>
            )}

            {isActive && (
              <div className="absolute left-0 top-2.5 bottom-2.5 w-[2px] rounded-r-full" style={{ background: 'var(--cs-accent)' }} />
            )}
          </button>
        );
      })}

      <div
        className={`mt-auto mb-1 ${collapsed ? 'w-6' : 'w-full'}`}
        style={{ height: '1px', background: 'var(--cs-border)' }}
      />

      <button
        onClick={() => window.open('https://github.com/aanjaneyasinghdhoni/ClaudeSec#readme', '_blank', 'noopener')}
        title="Documentation"
        className={`category-btn h-10 rounded-xl flex items-center ${collapsed ? 'w-10 justify-center' : 'w-full px-2.5 gap-2.5'}`}
        style={{ color: 'var(--cs-text-faint)' }}
      >
        <BookOpen className="w-4 h-4 shrink-0" />
        {!collapsed && (
          <span className="text-xs font-medium tracking-wide whitespace-nowrap">Docs</span>
        )}
      </button>
    </div>
  );
}
