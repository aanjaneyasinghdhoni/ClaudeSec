import React from 'react';

export function ExperimentalBadge({ title }: { title?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center rounded-full font-semibold uppercase tracking-wider align-middle"
      style={{
        fontSize: '10px',
        lineHeight: 1,
        padding: '2px 6px',
        color: 'var(--cs-accent)',
        border: '1px solid rgba(var(--cs-accent-rgb),0.4)',
        background: 'rgba(var(--cs-accent-rgb),0.08)',
        cursor: title ? 'help' : 'default',
      }}
    >
      Experimental
    </span>
  );
}
