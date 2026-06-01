import { useState, useRef, useEffect } from 'react';
import { Palette, Check } from 'lucide-react';

export type ThemeId = 'midnight' | 'carbon' | 'daylight' | 'paper';

export const THEMES: { id: ThemeId; name: string; mode: string; swatch: string; bg: string }[] = [
  { id: 'midnight', name: 'Midnight', mode: 'Dark',  swatch: '#00d4aa', bg: '#0a0e1a' },
  { id: 'carbon',   name: 'Carbon',   mode: 'Dark',  swatch: '#f5a623', bg: '#0b0b0c' },
  { id: 'daylight', name: 'Daylight', mode: 'Light', swatch: '#00a884', bg: '#f7f8fa' },
  { id: 'paper',    name: 'Paper',    mode: 'Light', swatch: '#6366f1', bg: '#faf7f2' },
];

export const LIGHT_THEMES: ThemeId[] = ['daylight', 'paper'];

export function ThemeSwitcher({ theme, onChange }: { theme: ThemeId; onChange: (t: ThemeId) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  const current = THEMES.find(t => t.id === theme) ?? THEMES[0];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="p-1.5 rounded-lg transition-all flex items-center gap-1.5"
        style={{ color: open ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
        title={`Theme — ${current.name}`}
      >
        <Palette className="w-3.5 h-3.5" />
        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: current.swatch }} />
      </button>
      {open && (
        <div
          className="absolute right-0 mt-2 w-48 rounded-xl p-1.5 z-50"
          style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)', boxShadow: '0 12px 32px rgba(0,0,0,0.18)' }}
        >
          <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>Theme</div>
          {THEMES.map(t => (
            <button
              key={t.id}
              onClick={() => { onChange(t.id); setOpen(false); }}
              className="theme-option w-full flex items-center gap-2.5 px-2 py-1.5 rounded-lg transition-colors"
              style={t.id === theme ? { background: 'var(--cs-accent-dim)' } : undefined}
            >
              <span className="w-4 h-4 rounded-full shrink-0" style={{ background: t.bg, border: `2px solid ${t.swatch}` }} />
              <span className="text-xs font-medium" style={{ color: 'var(--cs-text-base)' }}>{t.name}</span>
              <span className="text-[10px] ml-auto" style={{ color: 'var(--cs-text-faint)' }}>{t.mode}</span>
              {t.id === theme && <Check className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-accent)' }} />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
