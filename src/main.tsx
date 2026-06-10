import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {HashRouter, Routes, Route, Navigate, useParams} from 'react-router-dom';
import App from './App.tsx';
import {CATEGORY_TABS} from './dashboardTypes';
import type {Category} from './CategoryNav';
import './index.css';

// The URL fragment is the single source of truth for navigation. HashRouter (not
// BrowserRouter) keeps the route in the fragment, so it never reaches Express —
// no deep path can collide with an `/api` route — and the existing
// `#/docs/<slug>` deep links keep working unchanged.
//
// App is one big shell component; it reads category/tab/docs from the route via
// useRouteNav. The catch-all route renders that shell; the redirect routes below
// only resolve incomplete URLs to a concrete tab before App ever mounts state.

const DEFAULT_ROUTE = '/observe/timeline';

function firstTabRoute(category: string): string {
  const tabs = CATEGORY_TABS[category as Category];
  return tabs?.[0] ? `/${category}/${tabs[0].id}` : DEFAULT_ROUTE;
}

/** A bare `#/<category>` (no tab) lands on that category's first tab. */
function CategoryRedirect() {
  const {category} = useParams();
  return <Navigate to={firstTabRoute(category ?? '')} replace />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <HashRouter>
      <Routes>
        <Route path="/" element={<Navigate to={DEFAULT_ROUTE} replace />} />
        <Route path="/docs/*" element={<App />} />
        <Route path="/:category/:tab" element={<App />} />
        <Route path="/:category" element={<CategoryRedirect />} />
        <Route path="*" element={<Navigate to={DEFAULT_ROUTE} replace />} />
      </Routes>
    </HashRouter>
  </StrictMode>,
);
