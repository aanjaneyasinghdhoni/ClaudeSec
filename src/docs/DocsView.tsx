import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { docsNav, docsOrder, getDocPage, defaultDocSlug, slugifyHeading } from './docsRegistry';

/** The sidebar group a page belongs to (registry/sidebar structure), or null if ungrouped. */
function groupForSlug(slug: string): string | null {
  for (const g of docsNav) {
    if (g.pages.some(p => p.slug === slug)) return g.group;
  }
  return null;
}
import { DocsMDX, DocsNavProvider } from './mdxComponents';

interface TocEntry {
  id: string;
  text: string;
  level: 2 | 3;
}

function DocsPager({ slug, navigate }: { slug: string; navigate: (s: string) => void }) {
  const index = docsOrder.findIndex(p => p.slug === slug);
  if (index === -1) return null;
  const prev = index > 0 ? docsOrder[index - 1] : null;
  const next = index < docsOrder.length - 1 ? docsOrder[index + 1] : null;
  if (!prev && !next) return null;

  return (
    <nav className="docs-pager">
      {prev ? (
        <button type="button" className="docs-pager-link" data-dir="prev" onClick={() => navigate(prev.slug)}>
          <ChevronLeft className="docs-pager-icon" />
          <span className="docs-pager-text">
            <span className="docs-pager-label">Previous</span>
            <span className="docs-pager-title">{prev.title}</span>
          </span>
        </button>
      ) : (
        <span className="docs-pager-spacer" />
      )}
      {next ? (
        <button type="button" className="docs-pager-link" data-dir="next" onClick={() => navigate(next.slug)}>
          <span className="docs-pager-text">
            <span className="docs-pager-label">Next</span>
            <span className="docs-pager-title">{next.title}</span>
          </span>
          <ChevronRight className="docs-pager-icon" />
        </button>
      ) : (
        <span className="docs-pager-spacer" />
      )}
    </nav>
  );
}

function DocsToc({
  slug,
  scrollRef,
}: {
  slug: string;
  scrollRef: React.RefObject<HTMLDivElement>;
}) {
  const [entries, setEntries] = useState<TocEntry[]>([]);
  const [activeId, setActiveId] = useState<string>('');

  useEffect(() => {
    setEntries([]);
    setActiveId('');
    const root = scrollRef.current;
    if (!root) return;

    const serialize = (list: TocEntry[]) => list.map(e => `${e.level}:${e.id}`).join('|');
    let last = '';
    const collect = () => {
      const nodes = Array.from(root.querySelectorAll<HTMLElement>('.docs-prose h2, .docs-prose h3'));
      const found: TocEntry[] = [];
      const seen = new Map<string, number>();
      for (const node of nodes) {
        const text = (node.textContent ?? '').trim();
        if (!text) continue;
        const base = slugifyHeading(text) || 'section';
        const count = seen.get(base) ?? 0;
        seen.set(base, count + 1);
        const id = count === 0 ? base : `${base}-${count}`;
        if (node.id !== id) node.id = id;
        found.push({ id, text, level: node.tagName === 'H3' ? 3 : 2 });
      }
      const sig = serialize(found);
      if (sig !== last) {
        last = sig;
        setEntries(found);
      }
    };

    collect();
    const mo = new MutationObserver(collect);
    mo.observe(root, { childList: true, subtree: true });
    return () => mo.disconnect();
  }, [slug, scrollRef]);

  useEffect(() => {
    const root = scrollRef.current;
    if (!root || entries.length === 0) return;
    const targets = entries
      .map(e => root.querySelector<HTMLElement>(`#${CSS.escape(e.id)}`))
      .filter((n): n is HTMLElement => n !== null);
    if (targets.length === 0) return;

    const observer = new IntersectionObserver(
      observed => {
        const visible = observed
          .filter(o => o.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length > 0) {
          setActiveId(visible[0].target.id);
        }
      },
      { root, rootMargin: '0px 0px -70% 0px', threshold: 0 },
    );
    targets.forEach(t => observer.observe(t));
    return () => observer.disconnect();
  }, [entries, scrollRef]);

  const onClick = (id: string) => {
    const root = scrollRef.current;
    const target = root?.querySelector<HTMLElement>(`#${CSS.escape(id)}`);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActiveId(id);
    }
  };

  return (
    <aside className="docs-toc" aria-label="On this page">
      {entries.length >= 2 && (
        <>
          <div className="docs-toc-label">On this page</div>
          <ul className="docs-toc-list">
            {entries.map(e => (
              <li key={e.id}>
                <button
                  type="button"
                  className="docs-toc-item"
                  data-level={e.level}
                  data-active={e.id === activeId ? 'true' : 'false'}
                  onClick={() => onClick(e.id)}
                >
                  {e.text}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </aside>
  );
}

function DocsBreadcrumb({
  slug,
  canGoBack,
  navigate,
}: {
  slug: string;
  canGoBack: boolean;
  navigate: (s: string) => void;
}) {
  const page = getDocPage(slug);
  if (!page) return null;
  const group = groupForSlug(slug);
  const isLanding = slug === defaultDocSlug;

  const crumb = 'transition-colors hover:text-[var(--cs-text-base)]';

  return (
    <div className="flex items-center gap-3 mb-6 flex-wrap">
      <button
        type="button"
        onClick={() => window.history.back()}
        disabled={!canGoBack}
        className="flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded-lg transition-colors shrink-0"
        style={{
          border: '1px solid var(--cs-border)',
          background: 'var(--cs-bg-surface)',
          color: canGoBack ? 'var(--cs-text-muted)' : 'var(--cs-text-faint)',
          opacity: canGoBack ? 1 : 0.45,
          cursor: canGoBack ? 'pointer' : 'not-allowed',
        }}
        aria-label="Go back"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        Back
      </button>

      <nav
        className="flex items-center gap-1.5 text-xs min-w-0 flex-wrap"
        style={{ color: 'var(--cs-text-faint)' }}
        aria-label="Breadcrumb"
      >
        {isLanding ? (
          <span aria-current="page" style={{ color: 'var(--cs-text-base)' }}>Docs</span>
        ) : (
          <button type="button" onClick={() => navigate(defaultDocSlug)} className={crumb}>
            Docs
          </button>
        )}
        {!isLanding && group && (
          <>
            <ChevronRight className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />
            <span>{group}</span>
          </>
        )}
        {!isLanding && (
          <>
            <ChevronRight className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />
            <span aria-current="page" className="truncate" style={{ color: 'var(--cs-text-base)' }}>
              {page.title}
            </span>
          </>
        )}
      </nav>
    </div>
  );
}

export function DocsView({ slug: routeSlug, onClose, onNavigate }: {
  slug: string;
  onClose: () => void;
  onNavigate: (slug: string) => void;
}) {
  // The router owns the URL; resolve the route's slug to a real page, falling back
  // to the landing doc for an empty or unknown slug so a bad link never blanks.
  const slug = routeSlug && getDocPage(routeSlug) ? routeSlug : defaultDocSlug;
  const [query, setQuery] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  // Count slug changes within this docs session. Each intra-docs navigation pushes
  // a history entry, so after the first one window.history.back() returns to a
  // docs page rather than leaving the docs view entirely.
  const visitsRef = useRef(0);
  const [canGoBack, setCanGoBack] = useState(false);

  useEffect(() => {
    visitsRef.current += 1;
    if (visitsRef.current > 1) setCanGoBack(true);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [slug]);

  // Intra-docs links go through the router (push) so the Back button walks docs
  // history. Ignore unknown slugs so a stray link can't navigate to a blank page.
  const navigate = useCallback((s: string) => { if (getDocPage(s)) onNavigate(s); }, [onNavigate]);

  // Use the registry's stable lazy component — creating React.lazy here on
  // each slug change deadlocks under startTransition navigation (the suspended
  // transition never commits, so a per-render lazy is recreated forever and
  // the URL moves while the page doesn't).
  const page = getDocPage(slug);
  const LazyDoc = page?.Component ?? null;
  const navCtx = useMemo(() => ({ navigate, has: (s: string) => !!getDocPage(s) }), [navigate]);

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

      <div ref={scrollRef} className="flex-1 overflow-y-auto" style={{ background: 'var(--cs-bg-primary)' }}>
        <div className="docs-layout">
          <div className="docs-main">
            <div className="docs-prose max-w-3xl mx-auto px-8 py-8">
              {page ? (
                <>
                  <DocsBreadcrumb slug={slug} canGoBack={canGoBack} navigate={navigate} />
                  <Suspense fallback={<p className="text-sm" style={{ color: 'var(--cs-text-faint)' }}>Loading…</p>}>
                    <DocsNavProvider value={navCtx}>
                      <DocsMDX>{LazyDoc ? <LazyDoc /> : null}</DocsMDX>
                    </DocsNavProvider>
                  </Suspense>
                  <DocsPager slug={slug} navigate={navigate} />
                </>
              ) : (
                <p className="text-sm" style={{ color: 'var(--cs-text-faint)' }}>Select a page.</p>
              )}
            </div>
          </div>
          {page && <DocsToc slug={slug} scrollRef={scrollRef} />}
        </div>
      </div>
    </div>
  );
}
