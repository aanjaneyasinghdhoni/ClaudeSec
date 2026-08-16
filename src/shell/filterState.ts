import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Severity } from '../shared/types';
import { repoLabel } from '../dashboardTypes';
import { HARNESS_NAMES } from '../dashboardTypes';

/**
 * Filter state, held in the query string and nowhere else.
 *
 * The dashboard used to filter from three places at once — a Quick Filters
 * block, a repository panel and a Filters panel — each with its own React
 * state, so they could and did disagree. Every control now reads and writes
 * these params, which means there is exactly one value per axis: two surfaces
 * cannot drift apart because there is only one thing to drift from. It also
 * makes a filtered view bookmarkable and shareable.
 *
 * `useSearchParams` (not nuqs) because the app is mounted under HashRouter and
 * nuqs only supports BrowserRouter. React Router's own hook is router-agnostic
 * and reads the params out of the fragment exactly the same way.
 */

export type TimeRange = '1h' | '24h' | '7d' | 'all';

export const SEVERITY_ORDER: Severity[] = ['none', 'low', 'medium', 'high', 'critical'];

/** Short labels for the always-visible severity scale. */
export const SEVERITY_SHORT: Record<Severity, string> = {
  none: 'None', low: 'Low', medium: 'Med', high: 'High', critical: 'Crit',
};

export const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h',  label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d',  label: 'Last 7 days' },
  { value: 'all', label: 'All time' },
];

/**
 * A saved view is a *named preset of the same filter state* — not a parallel
 * filter surface. That is the whole reason the old Quick Filters block could
 * disagree with the Filters block: it held its own state. Selecting a view here
 * just writes these params, so the bar immediately reflects it and the chips,
 * the facet panel and the URL all agree.
 */
export interface SavedView {
  id: string;
  label: string;
  description: string;
  params: Partial<Record<FilterKey, string>>;
}

export const SAVED_VIEWS: SavedView[] = [
  { id: 'all',      label: 'All activity',  description: 'Everything ingested, no filter',        params: {} },
  { id: 'threats',  label: 'Threats only',  description: 'Anything a rule matched',               params: { sev: 'low,medium,high,critical' } },
  { id: 'act-now',  label: 'Act now',       description: 'High and critical only',                params: { sev: 'high,critical' } },
  { id: 'recent',   label: 'Last hour',     description: 'Everything from the last hour',         params: { t: '1h' } },
  { id: 'triage',   label: 'Triage queue',  description: 'High and critical from the last day',   params: { sev: 'high,critical', t: '24h' } },
];

type FilterKey = 'q' | 'sev' | 'repo' | 'harness' | 't';

const ALL_KEYS: FilterKey[] = ['q', 'sev', 'repo', 'harness', 't'];

export interface Filters {
  q: string;
  /** Empty means "no severity filter", which is not the same as "none selected". */
  sev: Severity[];
  repo: string[];
  harness: string[];
  time: TimeRange;
}

export interface FilterChip {
  key: FilterKey;
  value: string;
  label: string;
}

export interface FilterApi {
  filters: Filters;
  /** True when anything at all is filtering the list. */
  active: boolean;
  chips: FilterChip[];
  setSearch: (value: string) => void;
  setTime: (value: TimeRange) => void;
  toggle: (key: 'sev' | 'repo' | 'harness', value: string) => void;
  remove: (chip: FilterChip) => void;
  clearAll: () => void;
  /** The saved view whose params exactly match the current state, if any. */
  activeView: string;
  applyView: (id: string) => void;
}

function readList(raw: string | null): string[] {
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function isTimeRange(v: string | null): v is TimeRange {
  return v === '1h' || v === '24h' || v === '7d' || v === 'all';
}

/**
 * Turns filter state into the query string /api/graph expects. The param
 * names (repo, sev, harness, t, q) are the same ones this file already reads
 * out of the URL, so a deep link built from `filters` and a server-side fetch
 * built from this function agree by construction — there is nothing to keep
 * in sync by hand. `session` is passed separately because it is Timeline-only
 * state (not one of the URL-driven Filters), not because it means something
 * different server-side.
 */
export function graphQueryParams(filters: Filters, session?: string | null): URLSearchParams {
  const params = new URLSearchParams();
  if (session) params.set('session', session);
  if (filters.q.trim()) params.set('q', filters.q.trim());
  if (filters.sev.length) params.set('sev', filters.sev.join(','));
  if (filters.repo.length) params.set('repo', filters.repo.join(','));
  if (filters.harness.length) params.set('harness', filters.harness.join(','));
  if (filters.time !== 'all') params.set('t', filters.time);
  return params;
}

export function useFilters(): FilterApi {
  const [params, setParams] = useSearchParams();

  const filters = useMemo<Filters>(() => ({
    q: params.get('q') ?? '',
    sev: readList(params.get('sev')).filter((s): s is Severity =>
      (SEVERITY_ORDER as string[]).includes(s)),
    repo: readList(params.get('repo')),
    harness: readList(params.get('harness')),
    time: isTimeRange(params.get('t')) ? (params.get('t') as TimeRange) : 'all',
  }), [params]);

  // Every writer funnels through here so an empty value always *removes* the
  // param rather than leaving `?sev=` behind — otherwise "no filter" and "filter
  // set to nothing" would produce different URLs for the same view.
  const write = useCallback((patch: Partial<Record<FilterKey, string>>) => {
    setParams(prev => {
      const next = new URLSearchParams(prev);
      for (const [key, value] of Object.entries(patch)) {
        if (!value) next.delete(key);
        else next.set(key, value);
      }
      return next;
    }, { replace: true });
  }, [setParams]);

  const setSearch = useCallback((value: string) => write({ q: value }), [write]);
  const setTime = useCallback((value: TimeRange) => write({ t: value === 'all' ? '' : value }), [write]);

  const toggle = useCallback((key: 'sev' | 'repo' | 'harness', value: string) => {
    const param = key === 'sev' ? 'sev' : key === 'repo' ? 'repo' : 'harness';
    const current = readList(params.get(param));
    const next = current.includes(value)
      ? current.filter(v => v !== value)
      : [...current, value];
    write({ [param]: next.join(',') } as Partial<Record<FilterKey, string>>);
  }, [params, write]);

  const clearAll = useCallback(() => {
    setParams(prev => {
      const next = new URLSearchParams(prev);
      for (const key of ALL_KEYS) next.delete(key);
      return next;
    }, { replace: true });
  }, [setParams]);

  const chips = useMemo<FilterChip[]>(() => {
    const out: FilterChip[] = [];
    if (filters.q) out.push({ key: 'q', value: filters.q, label: `“${filters.q}”` });
    for (const r of filters.repo) out.push({ key: 'repo', value: r, label: repoLabel(r) });
    for (const h of filters.harness) out.push({ key: 'harness', value: h, label: HARNESS_NAMES[h] ?? h });
    if (filters.time !== 'all') {
      out.push({
        key: 't',
        value: filters.time,
        label: TIME_RANGES.find(t => t.value === filters.time)?.label ?? filters.time,
      });
    }
    return out;
  }, [filters]);

  const remove = useCallback((chip: FilterChip) => {
    if (chip.key === 'q') write({ q: '' });
    else if (chip.key === 't') write({ t: '' });
    else toggle(chip.key === 'repo' ? 'repo' : 'harness', chip.value);
  }, [write, toggle]);

  // Derived, never stored: a view is "active" when the params it would write are
  // the params already in the URL. Storing a `view=` key as well would give the
  // bar a second source of truth and reintroduce exactly the drift this replaces.
  const activeView = useMemo(() => {
    const current = ALL_KEYS.map(k => `${k}=${params.get(k) ?? ''}`).join('&');
    const match = SAVED_VIEWS.find(v =>
      ALL_KEYS.map(k => `${k}=${v.params[k] ?? ''}`).join('&') === current);
    return match?.id ?? 'custom';
  }, [params]);

  const applyView = useCallback((id: string) => {
    const view = SAVED_VIEWS.find(v => v.id === id);
    if (!view) return;
    setParams(prev => {
      const next = new URLSearchParams(prev);
      for (const key of ALL_KEYS) {
        const value = view.params[key];
        if (value) next.set(key, value);
        else next.delete(key);
      }
      return next;
    }, { replace: true });
  }, [setParams]);

  const active = chips.length > 0 || filters.sev.length > 0;

  return { filters, active, chips, setSearch, setTime, toggle, remove, clearAll, activeView, applyView };
}
