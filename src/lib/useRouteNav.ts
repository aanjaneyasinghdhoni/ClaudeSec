import { useCallback, useEffect, useRef } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import type { Category } from '../CategoryNav';
import type { Tab } from '../dashboardTypes';
import { CATEGORY_TABS, categoryForTab } from '../dashboardTypes';

// The dashboard view shown when a route is missing, malformed, or typo'd. A bad
// URL must never white-screen the app, so every resolver falls back here.
const DEFAULT_CATEGORY: Category = 'observe';
const DEFAULT_TAB: Tab = 'timeline';
const DEFAULT_ROUTE = `/${DEFAULT_CATEGORY}/${DEFAULT_TAB}`;

function isCategory(value: string | undefined): value is Category {
  return value !== undefined && value in CATEGORY_TABS;
}

function isTab(value: string | undefined): value is Tab {
  if (value === undefined) return false;
  return Object.values(CATEGORY_TABS).some(tabs => tabs.some(t => t.id === value));
}

export interface RouteNav {
  activeTab: Tab;
  activeCategory: Category;
  docsOpen: boolean;
  /** The current docs slug when in docs mode (`/docs/<slug>`), else null. */
  docsSlug: string | null;
  navigateTab: (tab: Tab) => void;
  navigateCategory: (cat: Category) => void;
  openDocs: (slug: string) => void;
  closeDocs: () => void;
}

/**
 * Derives all navigation state (category, tab, docs) from the URL so the address
 * bar is the single source of truth — every view becomes deep-linkable and
 * refresh-stable. Filters and selections stay in component state on purpose:
 * they change constantly and a trace id is meaningless in another operator's DB.
 *
 * Routes (under HashRouter, so `#/<...>`):
 *   /<category>/<tab>  — a dashboard tab
 *   /docs/<slug>       — the in-app docs (legacy `#/docs/<slug>` links still work)
 *
 * An unknown category or tab resolves to observe/timeline rather than erroring.
 */
export function useRouteNav(): RouteNav {
  const navigate = useNavigate();
  const location = useLocation();
  const params = useParams();

  const path = location.pathname;
  const docsOpen = path === '/docs' || path.startsWith('/docs/');

  // Remember the last dashboard route so leaving docs returns to where the
  // operator was (matching the old replace-not-push "close docs" behaviour).
  const lastDashboardRoute = useRef(DEFAULT_ROUTE);
  useEffect(() => {
    if (!docsOpen) lastDashboardRoute.current = path;
  }, [docsOpen, path]);

  // Resolve the active category/tab from the URL. When in docs mode the URL
  // carries no category/tab, so fall back to the last dashboard location's
  // values — that keeps the rail highlight stable while docs are open.
  let activeCategory: Category;
  let activeTab: Tab;
  if (docsOpen) {
    const [, lastCat, lastTab] = lastDashboardRoute.current.split('/');
    activeCategory = isCategory(lastCat) ? lastCat : DEFAULT_CATEGORY;
    activeTab = isTab(lastTab) ? lastTab : DEFAULT_TAB;
  } else if (isTab(params.tab) && isCategory(params.category) && categoryForTab(params.tab) === params.category) {
    activeTab = params.tab;
    activeCategory = params.category;
  } else {
    activeCategory = DEFAULT_CATEGORY;
    activeTab = DEFAULT_TAB;
  }

  const docsSlug = docsOpen ? (params['*'] ? params['*'].split('#')[0] : '') || null : null;

  const navigateTab = useCallback((tab: Tab) => {
    navigate(`/${categoryForTab(tab)}/${tab}`);
  }, [navigate]);

  const navigateCategory = useCallback((cat: Category) => {
    const firstTab = CATEGORY_TABS[cat]?.[0]?.id ?? DEFAULT_TAB;
    navigate(`/${cat}/${firstTab}`);
  }, [navigate]);

  // Intra-docs navigation pushes so the browser Back button walks docs history.
  const openDocs = useCallback((slug: string) => {
    navigate(`/docs/${slug}`);
  }, [navigate]);

  // Leaving docs replaces (not pushes) so Back doesn't bounce straight into docs,
  // matching the old history.replaceState-based closeDocs.
  const closeDocs = useCallback(() => {
    navigate(lastDashboardRoute.current || DEFAULT_ROUTE, { replace: true });
  }, [navigate]);

  return { activeTab, activeCategory, docsOpen, docsSlug, navigateTab, navigateCategory, openDocs, closeDocs };
}
