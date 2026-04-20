/**
 * CategoryNav — Slim vertical icon rail for category-based navigation.
 * Sits to the left of the existing session sidebar.
 */
import React from 'react';
import {
  Eye, AlertTriangle, Shield, Bookmark, Settings,
} from 'lucide-react';

export type Category = 'observe' | 'detect' | 'protect' | 'review' | 'manage';

export const CATEGORIES: { id: Category; label: string; icon: React.ReactNode }[] = [
  { id: 'observe', label: 'Observe',  icon: <Eye className="w-4 h-4" /> },
  { id: 'detect',  label: 'Detect',   icon: <AlertTriangle className="w-4 h-4" /> },
  { id: 'protect', label: 'Protect',  icon: <Shield className="w-4 h-4" /> },
  { id: 'review',  label: 'Review',   icon: <Bookmark className="w-4 h-4" /> },
  { id: 'manage',  label: 'Manage',   icon: <Settings className="w-4 h-4" /> },
];

interface Props {
  active: Category;
  onChange: (cat: Category) => void;
  alertCount?: number;
}

export function CategoryNav({ active, onChange, alertCount = 0 }: Props) {
  return (
    <div
      className="w-[56px] shrink-0 flex flex-col items-center py-3 gap-1"
      style={{
        borderRight: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}
    >
      {CATEGORIES.map(cat => {
        const isActive = active === cat.id;
        return (
          <button
            key={cat.id}
            onClick={() => onChange(cat.id)}
            title={cat.label}
            className="category-btn relative w-10 h-10 rounded-xl flex flex-col items-center justify-center gap-0.5"
            style={{
              background: isActive ? 'rgba(0,212,170,0.1)' : 'transparent',
              color: isActive ? '#00d4aa' : 'var(--cs-text-faint)',
            }}
          >
            {cat.icon}
            <span className="text-[8px] font-medium leading-none tracking-wide">{cat.label}</span>

            {/* Alert badge on Detect */}
            {cat.id === 'detect' && alertCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-[14px] px-0.5 text-[8px] font-bold rounded-full flex items-center justify-center leading-none bg-rose-500 text-white">
                {alertCount > 99 ? '99+' : alertCount}
              </span>
            )}

            {/* Active indicator */}
            {isActive && (
              <div className="absolute left-0 top-2.5 bottom-2.5 w-[2px] rounded-r-full" style={{ background: '#00d4aa' }} />
            )}
          </button>
        );
      })}
    </div>
  );
}
