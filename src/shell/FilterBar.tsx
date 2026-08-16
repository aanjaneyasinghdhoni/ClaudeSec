import React, { useState } from 'react';
import { Search, SlidersHorizontal, X, ChevronDown, Check } from 'lucide-react';
import type { Severity } from '../shared/types';
import {
  useFilters, SAVED_VIEWS, SEVERITY_ORDER, SEVERITY_SHORT, TIME_RANGES,
  type TimeRange,
} from './filterState';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Checkbox } from '../components/ui/checkbox';
import { Popover, PopoverContent, PopoverTrigger } from '../components/ui/popover';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible';

export interface FacetOption {
  value: string;
  label: string;
  count: number;
  /** Renders a severity dot next to the row — used to flag risky repositories. */
  alert?: boolean;
}

export interface FilterBarProps {
  /** Counts per severity across everything the *other* facets let through, so a
   *  count tells you what selecting that level would actually give you. */
  severityCounts: Record<Severity, number>;
  repoOptions: FacetOption[];
  harnessOptions: FacetOption[];
  resultCount: number;
  totalCount: number;
  /** Noun for the result count — "spans" on the timeline, "alerts" on Detect. */
  noun?: string;
}

/**
 * The one filter surface.
 *
 * Everything that used to filter — the Quick Filters block, the repository
 * panel and the Filters panel with its own search box, its All/Normal/Malicious
 * toggle and a second copy of the repo list — collapses into this bar plus one
 * facet popover behind the Filters button. Left to right: saved view, the only
 * search input on the screen, the permanent five-level severity scale, the
 * removable chips for whatever else is applied, then the facet button and the
 * result count.
 *
 * Severity gets the permanent, always-visible control because it is the primary
 * axis of the product; the old three-way All/Normal/Malicious toggle was a
 * coarse answer to a five-level question and could not express "medium and up".
 */
export function FilterBar({
  severityCounts, repoOptions, harnessOptions, resultCount, totalCount, noun = 'spans',
}: FilterBarProps) {
  const { filters, active, chips, setSearch, setTime, toggle, remove, clearAll, activeView, applyView } = useFilters();
  const [facetsOpen, setFacetsOpen] = useState(false);

  const viewLabel = activeView === 'custom'
    ? 'Custom'
    : SAVED_VIEWS.find(v => v.id === activeView)?.label ?? 'All activity';

  const facetCount = filters.repo.length + filters.harness.length + (filters.time === 'all' ? 0 : 1);

  return (
    <div
      className="sticky top-0 z-20 flex min-h-11 flex-wrap items-center gap-1.5 px-3 py-1.5"
      style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
    >
      {/* Saved view — a named preset of this same state, never a second state. */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="shrink-0 font-medium">
            {viewLabel}
            <ChevronDown className="size-3 opacity-60" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-64">
          {SAVED_VIEWS.map(view => (
            <DropdownMenuItem key={view.id} onSelect={() => applyView(view.id)} className="flex-col items-start gap-0">
              <span className="flex w-full items-center gap-2">
                {view.label}
                {activeView === view.id && <Check className="ml-auto size-3.5" />}
              </span>
              <span className="text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>{view.description}</span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* The only text input on the screen. */}
      <div className="relative w-40 shrink-0 2xl:w-56">
        <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }} />
        <Input
          value={filters.q}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search… (or key=value)"
          aria-label="Search activity"
          className="h-7 pl-7 pr-7 text-xs"
        />
        {filters.q && (
          <button
            type="button"
            onClick={() => setSearch('')}
            aria-label="Clear search"
            className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5"
            style={{ color: 'var(--cs-text-faint)' }}
          >
            <X className="size-3" />
          </button>
        )}
      </div>

      {/* Permanent five-level severity scale, multi-select, with live counts. */}
      <div
        role="group"
        aria-label="Severity"
        className="flex shrink-0 items-center gap-px rounded-md p-px"
        style={{ background: 'var(--cs-bg-raised)' }}
      >
        {SEVERITY_ORDER.map(sev => {
          const on = filters.sev.includes(sev);
          return (
            <button
              key={sev}
              type="button"
              aria-pressed={on}
              onClick={() => toggle('sev', sev)}
              title={`${SEVERITY_SHORT[sev]} — ${severityCounts[sev] ?? 0}`}
              className="flex h-6 items-center gap-1 rounded-[5px] px-1.5 text-[11px] font-medium transition-colors"
              style={on
                ? { background: `var(--cs-sev-${sev}-bg)`, color: `var(--cs-sev-${sev}-fg)` }
                : { color: 'var(--cs-text-faint)' }}
            >
              <span className="size-1.5 shrink-0 rounded-full" style={{ background: `var(--cs-sev-${sev})` }} />
              <span className="hidden 2xl:inline">{SEVERITY_SHORT[sev]}</span>
              <span className="font-mono tabular-nums">{severityCounts[sev] ?? 0}</span>
            </button>
          );
        })}
      </div>

      {/* Applied chips — each individually removable. */}
      {chips.map(chip => (
        <Badge key={`${chip.key}:${chip.value}`} variant="secondary" className="shrink-0 gap-1 pr-1">
          <span className="max-w-32 truncate">{chip.label}</span>
          <button
            type="button"
            onClick={() => remove(chip)}
            aria-label={`Remove filter ${chip.label}`}
            className="rounded-full p-0.5 hover:opacity-70"
          >
            <X className="size-2.5" />
          </button>
        </Badge>
      ))}

      {/* One facet popover holds every remaining axis, as checkbox rows. */}
      <Popover open={facetsOpen} onOpenChange={setFacetsOpen}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="sm" className="shrink-0">
            <SlidersHorizontal className="size-3.5" />
            Filters
            {facetCount > 0 && (
              <span className="font-mono tabular-nums" style={{ color: 'var(--cs-accent)' }}>{facetCount}</span>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-72 p-0">
          <div className="max-h-[60svh] overflow-y-auto p-1">
            <FacetGroup
              label="Repository"
              options={repoOptions}
              selected={filters.repo}
              onToggle={value => toggle('repo', value)}
            />
            <FacetGroup
              label="Harness"
              options={harnessOptions}
              selected={filters.harness}
              onToggle={value => toggle('harness', value)}
            />
            <FacetGroup
              label="Time range"
              options={TIME_RANGES.map(t => ({ value: t.value, label: t.label, count: -1 }))}
              selected={filters.time === 'all' ? [] : [filters.time]}
              onToggle={value => setTime(filters.time === value ? 'all' : (value as TimeRange))}
            />
          </div>
        </PopoverContent>
      </Popover>

      {/* Result count and the single escape hatch. */}
      <div className="ml-auto flex shrink-0 items-center gap-2 text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
        <span className="font-mono tabular-nums">
          {resultCount.toLocaleString()}
          {resultCount !== totalCount && <> / {totalCount.toLocaleString()}</>} {noun}
        </span>
        {active && (
          <Button variant="ghost" size="xs" onClick={clearAll}>Clear all</Button>
        )}
      </div>
    </div>
  );
}

function FacetGroup({ label, options, selected, onToggle }: {
  label: string;
  options: FacetOption[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  // Every group starts open. With only three facets in the popover there is
  // nothing to gain from collapsing them by default and a real cost: a
  // collapsed-by-default group renders as its header and nothing else, so a
  // freshly opened Filters popover looked completely empty — three buttons,
  // no options underneath any of them — until the user knew to click each
  // one. Collapsing stays available for tidying up once a facet is in use.
  const [open, setOpen] = useState(true);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>
        <ChevronDown className={`size-3 transition-transform ${open ? '' : '-rotate-90'}`} />
        {label}
        {selected.length > 0 && (
          <span className="ml-auto font-mono" style={{ color: 'var(--cs-accent)' }}>{selected.length}</span>
        )}
      </CollapsibleTrigger>
      <CollapsibleContent>
        {options.length === 0 ? (
          // A facet that genuinely has nothing to offer still says so, rather
          // than silently rendering nothing — the failure mode that hid this
          // bug in the first place, where an empty array collapsed the whole
          // group (header included) instead of surfacing as a visible state.
          <p className="px-2 py-2 text-xs" style={{ color: 'var(--cs-text-faint)' }}>
            Nothing to filter on yet.
          </p>
        ) : (
          <ul className="pb-1">
            {options.map(opt => {
              const id = `facet-${label}-${opt.value}`;
              return (
                <li key={opt.value}>
                  <label htmlFor={id} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-xs hover:bg-accent">
                    <Checkbox id={id} checked={selected.includes(opt.value)} onCheckedChange={() => onToggle(opt.value)} />
                    <span className="min-w-0 flex-1 truncate">{opt.label}</span>
                    {opt.alert && <span className="size-1.5 shrink-0 rounded-full" style={{ background: 'var(--cs-sev-critical)' }} />}
                    {opt.count >= 0 && (
                      <span className="shrink-0 font-mono tabular-nums" style={{ color: 'var(--cs-text-faint)' }}>{opt.count}</span>
                    )}
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </CollapsibleContent>
    </Collapsible>
  );
}
