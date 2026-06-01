import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Search } from 'lucide-react';
import { docsNav, getDocPage, defaultDocSlug } from './docsRegistry';
import { DocsMDX, DocsNavProvider } from './mdxComponents';

const HASH_PREFIX = '#/docs/';

function readHashSlug(): string {
  const h = window.location.hash;
  if (h.startsWith(HASH_PREFIX)) {
    const s = decodeURIComponent(h.slice(HASH_PREFIX.length)).split('#')[0];
    if (s && getDocPage(s)) return s;
  }
  return defaultDocSlug;
}

export function DocsView({ onClose }: { onClose: () => void }) {
  const [slug, setSlug] = useState<string>(() => readHashSlug());
  const [query, setQuery] = useState('');

  useEffect(() => {
    const onHash = () => setSlug(readHashSlug());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    if (slug && window.location.hash !== HASH_PREFIX + slug) {
      window.location.hash = HASH_PREFIX + slug;
    }
  }, [slug]);

  const navigate = (s: string) => { if (getDocPage(s)) setSlug(s); };

  const page = getDocPage(slug);
  const LazyDoc = useMemo(() => (page ? React.lazy(page.load) : null), [slug]);
  const navCtx = useMemo(() => ({ navigate, has: (s: string) => !!getDocPage(s) }), []);

  const filteredNav = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return docsNav;
    return docsNav
      .map(g => ({
        group: g.group,
        pages: g.pages.filter(p => `${p.title} ${p.description}`.toLowerCase().includes(q)),
      }))
      .filter(g => g.pages.length > 0);
  }, [query]);

  return (
    <div className="flex flex-1 min-h-0 min-w-0">
      <div
        className="shrink-0 w-[240px] flex flex-col min-h-0"
        style={{ borderRight: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}
      >
        <div className="p-3 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
          <button
            onClick={onClose}
            className="flex items-center gap-1.5 text-xs font-medium mb-3 transition-colors"
            style={{ color: 'var(--cs-text-faint)' }}
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Dashboard
          </button>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }} />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search docs"
              className="w-full pl-8 pr-12 py-1.5 text-xs rounded-lg outline-none"
              style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)', color: 'var(--cs-text-base)' }}
            />
            <kbd
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono px-1.5 py-0.5 rounded pointer-events-none"
              style={{ border: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)', color: 'var(--cs-text-faint)' }}
            >
              ⌘K
            </kbd>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto p-2">
          {filteredNav.length === 0 && (
            <p className="text-xs px-2 py-3" style={{ color: 'var(--cs-text-faint)' }}>No matching pages.</p>
          )}
          {filteredNav.map(group => (
            <div key={group.group} className="mb-3">
              <div className="text-[10px] font-bold uppercase tracking-wider px-2 mb-1" style={{ color: 'var(--cs-text-faint)' }}>
                {group.group}
              </div>
              {group.pages.map(p => {
                const active = p.slug === slug;
                return (
                  <button
                    key={p.slug}
                    onClick={() => navigate(p.slug)}
                    className="w-full text-left px-2 py-1.5 rounded-lg text-xs transition-colors mb-0.5 truncate"
                    style={{
                      background: active ? 'rgba(var(--cs-accent-rgb),0.1)' : 'transparent',
                      color: active ? 'var(--cs-accent)' : 'var(--cs-text-muted)',
                    }}
                  >
                    {p.title}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto" style={{ background: 'var(--cs-bg-primary)' }}>
        <div className="docs-prose max-w-3xl mx-auto px-8 py-8">
          {page ? (
            <Suspense fallback={<p className="text-sm" style={{ color: 'var(--cs-text-faint)' }}>Loading…</p>}>
              <DocsNavProvider value={navCtx}>
                <DocsMDX>{LazyDoc ? <LazyDoc /> : null}</DocsMDX>
              </DocsNavProvider>
            </Suspense>
          ) : (
            <p className="text-sm" style={{ color: 'var(--cs-text-faint)' }}>Select a page.</p>
          )}
        </div>
      </div>
    </div>
  );
}
