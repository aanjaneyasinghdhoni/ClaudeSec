/**
 * Row density — the control, and the hook that remembers the choice.
 *
 * Density is picked per surface and never mixed within one surface, so this is
 * a single three-way switch rather than a per-column setting. The default is
 * deliberately `compact`: the binding constraint on this dashboard is vertical,
 * not horizontal. On a 1366×768 laptop, once browser chrome, the app header,
 * the filter bar and the status bar are paid for, there is roughly 500px of
 * table body left — twelve rows at 40px, but fifteen at 32px. Three extra rows
 * is the difference between seeing a burst of alerts and scrolling to find it.
 *
 * The choice is per-surface and persisted, because an operator who prefers
 * roomy rows in Settings still wants the alert log tight.
 */
import { useCallback, useState } from 'react';
import { Rows4, Rows3, Rows2 } from 'lucide-react';

export type RowDensity = 'compact' | 'default' | 'comfy';

const OPTIONS: { value: RowDensity; label: string; Icon: typeof Rows2 }[] = [
  { value: 'compact', label: 'Compact rows',     Icon: Rows4 },
  { value: 'default', label: 'Default rows',     Icon: Rows3 },
  { value: 'comfy',   label: 'Comfortable rows', Icon: Rows2 },
];

const isDensity = (v: unknown): v is RowDensity =>
  v === 'compact' || v === 'default' || v === 'comfy';

/**
 * Persisted density for one surface.
 *
 * @param storageKey unique per surface, e.g. `alerts`.
 * @param fallback   density to use on first visit. Compact unless the surface
 *                   is for reading and deciding rather than scanning.
 */
export function useRowDensity(storageKey: string, fallback: RowDensity = 'compact') {
  const key = `claudesec.density.${storageKey}`;

  const [density, setDensityState] = useState<RowDensity>(() => {
    // Storage can throw in a locked-down browser profile. A preference is never
    // worth breaking the dashboard over, so any failure just takes the default.
    try {
      const stored = window.localStorage.getItem(key);
      return isDensity(stored) ? stored : fallback;
    } catch {
      return fallback;
    }
  });

  const setDensity = useCallback((next: RowDensity) => {
    setDensityState(next);
    try { window.localStorage.setItem(key, next); } catch { /* preference only */ }
  }, [key]);

  return [density, setDensity] as const;
}

/** A three-way segmented control. Icon-only — it is chrome, not content. */
export function RowDensityToggle({
  density,
  onChange,
  className = '',
}: {
  density: RowDensity;
  onChange: (next: RowDensity) => void;
  className?: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Row density"
      className={`inline-flex items-center rounded-md p-0.5 ${className}`}
      style={{ background: 'var(--cs-bg-raised)' }}
    >
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = density === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => onChange(value)}
            className="p-1 rounded transition-colors"
            style={{
              background: active ? 'var(--cs-accent-soft)' : 'transparent',
              color: active ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
            }}
          >
            <Icon className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}
