/**
 * The control strip that sits above a data surface.
 *
 * Every data tab needs the same thing: one quiet horizontal strip holding the
 * surface's title, its counts, its filters and its actions. The alert log
 * proved the shape; this extracts it so the rules table, the enforcement feed
 * and the scanner cannot drift into three different-looking toolbars.
 *
 * It is chrome, so it is deliberately underdressed — no outlines, no fills
 * except on the control that is currently on. The one border it carries is the
 * hairline that separates it from the rows below, because that edge is doing
 * real work: it is where the sticky column header starts.
 */
import React from 'react';

/** One strip, sitting on the surface plane, above a table. */
export function Toolbar({
  children,
  className = '',
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`flex items-center gap-2 xl:gap-3 px-3 py-1.5 shrink-0 flex-wrap ${className}`}
      style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
    >
      {children}
    </div>
  );
}

/**
 * Every button in a toolbar shares one shape, so the strip reads as a single
 * control rather than as a row of unrelated widgets.
 *
 * `active` is the only state that gets a fill — the accent, which means
 * "selected" and never "dangerous". `danger` colours a destructive action with
 * the critical token; that is the one place a toolbar is allowed chroma, and it
 * is on an action the operator has to be able to find in a hurry.
 */
export function ToolButton({
  active = false,
  danger = false,
  children,
  className = '',
  ...props
}: React.ComponentProps<'button'> & { active?: boolean; danger?: boolean }) {
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors whitespace-nowrap disabled:opacity-50 ${className}`}
      style={{
        background: active ? 'var(--cs-accent-soft)' : 'transparent',
        color: active ? 'var(--cs-accent)'
             : danger ? 'var(--cs-sev-critical-fg)'
             : 'var(--cs-text-muted)',
        fontSize: 'var(--cs-text-xs)',
      }}
    >
      {children}
    </button>
  );
}

/**
 * The leading block of a toolbar: an icon, the surface's name, and a count.
 *
 * The count is mono because it is a number that changes in place while the
 * operator is looking at it, and digits that jitter between renders are the
 * fastest way to make a live dashboard feel untrustworthy.
 */
export function ToolbarTitle({
  icon,
  children,
  count,
  countTitle,
}: {
  icon?: React.ReactNode;
  children: React.ReactNode;
  count?: React.ReactNode;
  countTitle?: string;
}) {
  return (
    <div className="flex items-center gap-2 shrink-0">
      {icon && <span style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true">{icon}</span>}
      <h2
        style={{
          fontSize: 'var(--cs-text-base)',
          fontWeight: 'var(--cs-weight-semibold)',
          color: 'var(--cs-text-strong)',
        }}
      >
        {children}
      </h2>
      {count != null && (
        <span
          className="cs-mono"
          title={countTitle}
          style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
        >
          {count}
        </span>
      )}
    </div>
  );
}

/**
 * The single text input a surface is allowed. Quiet at rest — a change of
 * ground rather than an outline — and Escape clears it, because a filter you
 * cannot get out of without the mouse is a filter that gets left on.
 */
export function ToolSearch({
  value,
  onChange,
  placeholder,
  label,
  className = '',
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder: string;
  /** Accessible name. The placeholder disappears once something is typed. */
  label: string;
  className?: string;
}) {
  return (
    <input
      type="text"
      role="searchbox"
      value={value}
      aria-label={label}
      placeholder={placeholder}
      onChange={e => onChange(e.target.value)}
      onKeyDown={e => { if (e.key === 'Escape' && value) { e.stopPropagation(); onChange(''); } }}
      className={`px-2 py-1 rounded-md outline-none min-w-0 ${className}`}
      style={{
        background: 'var(--cs-bg-raised)',
        color: 'var(--cs-text-body)',
        fontSize: 'var(--cs-text-xs)',
      }}
    />
  );
}
