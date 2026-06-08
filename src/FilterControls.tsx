import React, { useMemo, useState } from 'react';
import { Search, X } from 'lucide-react';

export interface FacetOption {
  value: string;
  label: string;
}

export interface FacetConfig<T> {
  key: string;
  label: string;
  options: FacetOption[];
  accessor: (item: T) => string;
}

export interface UseListControlsOptions<T> {
  searchText: (item: T) => string;
  facets?: FacetConfig<T>[];
  pageSize?: number;
}

export interface ListControls<T> {
  query: string;
  setQuery: (value: string) => void;
  facetValues: Record<string, string>;
  setFacet: (key: string, value: string) => void;
  visible: T[];
  total: number;
  shown: number;
  showMore: () => void;
  showAll: () => void;
}

export function useListControls<T>(
  items: T[],
  { searchText, facets = [], pageSize = 50 }: UseListControlsOptions<T>,
): ListControls<T> {
  const [query, setQueryState] = useState('');
  const [facetValues, setFacetValues] = useState<Record<string, string>>({});
  const [count, setCount] = useState(pageSize);

  const setQuery = (value: string) => {
    setQueryState(value);
    setCount(pageSize);
  };

  const setFacet = (key: string, value: string) => {
    setFacetValues(prev => ({ ...prev, [key]: value }));
    setCount(pageSize);
  };

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter(item => {
      if (needle && !searchText(item).toLowerCase().includes(needle)) return false;
      for (const facet of facets) {
        const selected = facetValues[facet.key];
        if (selected && facet.accessor(item) !== selected) return false;
      }
      return true;
    });
  }, [items, query, facetValues, searchText, facets]);

  const visible = useMemo(() => filtered.slice(0, count), [filtered, count]);

  return {
    query,
    setQuery,
    facetValues,
    setFacet,
    visible,
    total: filtered.length,
    shown: visible.length,
    showMore: () => setCount(c => c + pageSize),
    showAll: () => setCount(Infinity),
  };
}

export interface FilterBarProps<T> {
  query: string;
  setQuery: (value: string) => void;
  facetValues: Record<string, string>;
  setFacet: (key: string, value: string) => void;
  facets?: FacetConfig<T>[];
  placeholder?: string;
}

export function FilterBar<T>({
  query,
  setQuery,
  facetValues,
  setFacet,
  facets = [],
  placeholder = 'Search…',
}: FilterBarProps<T>): React.ReactElement {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <div className="relative">
        <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }} />
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder={placeholder}
          className="w-48 pl-8 pr-7 py-1.5 text-xs rounded-lg outline-none"
          style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)', color: 'var(--cs-text-base)' }}
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery('')}
            className="absolute right-2.5 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--cs-text-faint)' }}
          >
            <X className="w-3 h-3" />
          </button>
        )}
      </div>
      {facets.map(facet => (
        <select
          key={facet.key}
          value={facetValues[facet.key] ?? ''}
          onChange={e => setFacet(facet.key, e.target.value)}
          aria-label={facet.label}
          className="px-2.5 py-1.5 text-xs rounded-lg outline-none"
          style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)', color: 'var(--cs-text-base)' }}
        >
          <option value="">{`All ${facet.label}`}</option>
          {facet.options.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      ))}
    </div>
  );
}

export interface ListFooterProps {
  shown: number;
  total: number;
  showMore: () => void;
  showAll: () => void;
  noun?: string;
}

export function ListFooter({ shown, total, showMore, showAll, noun = 'items' }: ListFooterProps): React.ReactElement | null {
  if (shown >= total) return null;
  return (
    <div className="flex items-center justify-center gap-3 py-2 text-xs" style={{ color: 'var(--cs-text-faint)' }}>
      <span>Showing {shown} of {total} {noun}</span>
      <button
        type="button"
        onClick={showMore}
        className="px-2 py-0.5 rounded transition-colors"
        style={{ background: 'rgba(var(--cs-accent-rgb),0.1)', color: 'var(--cs-accent)' }}
      >
        Show more
      </button>
      <button
        type="button"
        onClick={showAll}
        className="px-2 py-0.5 rounded transition-colors"
        style={{ background: 'rgba(var(--cs-accent-rgb),0.1)', color: 'var(--cs-accent)' }}
      >
        Show all
      </button>
    </div>
  );
}
