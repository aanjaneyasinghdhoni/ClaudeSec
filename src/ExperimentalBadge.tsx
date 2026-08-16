import React from 'react';
import { Info } from 'lucide-react';

/**
 * A small, deliberately *neutral* badge that marks a value as a best-effort
 * estimate (a heuristic), not an error. It uses the informational blue token —
 * never a red/amber warning colour — so a heuristic reading never looks like a
 * failure at a glance. The optional `title` carries the "why" on hover.
 */
export function ExperimentalBadge({ title, label = 'Estimate' }: { title?: string; label?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1 rounded-full font-medium align-middle"
      style={{
        fontSize: '10px',
        lineHeight: 1,
        padding: '2px 7px',
        color: 'var(--cs-info)',
        border: '1px solid rgba(var(--cs-info-rgb),0.35)',
        background: 'rgba(var(--cs-info-rgb),0.10)',
        cursor: title ? 'help' : 'default',
      }}
    >
      <Info style={{ width: 11, height: 11 }} />
      {label}
    </span>
  );
}
