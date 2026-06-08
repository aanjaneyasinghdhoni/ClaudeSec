import { useEffect, useMemo, useRef, useState } from 'react';
import { Search } from 'lucide-react';
import { docsSearchIndex, docsNav, type DocSearchEntry } from './docsRegistry';

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onSelect: (slug: string) => void;
}

interface RankedResult {
  entry: DocSearchEntry;
  group: string;
  snippet: string;
}

const MAX_RESULTS = 20;

const slugToGroup: Record<string, string> = (() => {
  const map: Record<string, string> = {};
  for (const g of docsNav) {
    for (const p of g.pages) map[p.slug] = g.group;
  }
  return map;
})();

function makeSnippet(text: string, term: string): string {
  const idx = text.toLowerCase().indexOf(term);
  if (idx < 0) return text.slice(0, 120);
  const start = Math.max(0, idx - 40);
  const end = Math.min(text.length, idx + term.length + 80);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return prefix + text.slice(start, end).trim() + suffix;
}

function rank(query: string): RankedResult[] {
  const term = query.trim().toLowerCase();
  if (!term) return [];
  const scored: { entry: DocSearchEntry; score: number; matchedHeading?: string }[] = [];

  for (const entry of docsSearchIndex) {
    const title = entry.title.toLowerCase();
    const desc = entry.description.toLowerCase();
    let score = 0;
    let matchedHeading: string | undefined;

    if (title === term) score = 1000;
    else if (title.startsWith(term)) score = 700;
    else if (title.includes(term)) score = 500;

    if (desc.includes(term)) score = Math.max(score, 250);

    const headingHit = entry.headings.find(h => h.toLowerCase().includes(term));
    if (headingHit) {
      score = Math.max(score, 300);
      matchedHeading = headingHit;
    }

    if (entry.text.toLowerCase().includes(term)) score = Math.max(score, 100);

    if (score > 0) scored.push({ entry, score, matchedHeading });
  }

  scored.sort((a, b) =>
    b.score - a.score || a.entry.title.localeCompare(b.entry.title),
  );

  return scored.slice(0, MAX_RESULTS).map(({ entry, matchedHeading }) => ({
    entry,
    group: slugToGroup[entry.slug] ?? 'Docs',
    snippet: matchedHeading ?? makeSnippet(entry.text || entry.description, term),
  }));
}

export function CommandPalette({ open, onClose, onSelect }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setSelected(0);
      const id = requestAnimationFrame(() => inputRef.current?.focus());
      return () => cancelAnimationFrame(id);
    }
  }, [open]);

  const results = useMemo(() => rank(query), [query]);

  useEffect(() => { setSelected(0); }, [query]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>('[data-selected="true"]');
    el?.scrollIntoView({ block: 'nearest' });
  }, [selected, results]);

  if (!open) return null;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (results.length) setSelected(s => (s + 1) % results.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (results.length) setSelected(s => (s - 1 + results.length) % results.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const hit = results[selected];
      if (hit) onSelect(hit.entry.slug);
    }
  };

  return (
    <div
      className="cs-palette-overlay"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="cs-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Search documentation"
        onKeyDown={handleKeyDown}
      >
        <div className="cs-palette-search">
          <Search className="w-4 h-4 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search documentation…"
            className="cs-palette-input"
            aria-label="Search documentation"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="cs-palette-kbd">Esc</kbd>
        </div>

        <div ref={listRef} className="cs-palette-list" role="listbox">
          {query.trim() === '' && (
            <p className="cs-palette-empty">Type to search across all documentation.</p>
          )}
          {query.trim() !== '' && results.length === 0 && (
            <p className="cs-palette-empty">No results for “{query.trim()}”.</p>
          )}
          {results.map((r, i) => {
            const active = i === selected;
            return (
              <button
                key={r.entry.slug}
                type="button"
                role="option"
                aria-selected={active}
                data-selected={active}
                className="cs-palette-item"
                onMouseEnter={() => setSelected(i)}
                onClick={() => onSelect(r.entry.slug)}
              >
                <div className="cs-palette-item-head">
                  <span className="cs-palette-item-title">{r.entry.title}</span>
                  <span className="cs-palette-item-group">{r.group}</span>
                </div>
                {r.snippet && <div className="cs-palette-item-sub">{r.snippet}</div>}
              </button>
            );
          })}
        </div>

        <div className="cs-palette-foot">
          <span><kbd className="cs-palette-kbd">↑</kbd><kbd className="cs-palette-kbd">↓</kbd> navigate</span>
          <span><kbd className="cs-palette-kbd">↵</kbd> open</span>
          <span><kbd className="cs-palette-kbd">esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
