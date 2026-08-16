import React from 'react';
import { AlertTriangle, Bookmark, Eye, Scale, Settings, Shield } from 'lucide-react';

/**
 * The six top-level groups of the product. This file holds only the data —
 * the rail that renders it lives in `src/shell/NavRail.tsx`, because the shape
 * of the navigation is a layout concern and this list is not.
 *
 * `Category` is imported as a type by the router, the route resolver and the
 * tab map, so it stays here rather than moving into the shell.
 *
 * `govern` sits between Review and Manage on purpose: Protect holds the
 * implementation (Rules, Enforce, MCP Scan); Govern is a different job —
 * proving what Protect actually did, not doing it. It is the one screen a
 * non-engineer opens, so it gets its own stop rather than living inside
 * Protect where the premise (a readable layer sitting *over* the machinery)
 * would be buried beside its own implementation.
 */
export type Category = 'observe' | 'detect' | 'protect' | 'review' | 'govern' | 'manage';

export const CATEGORIES: { id: Category; label: string; icon: React.ReactNode }[] = [
  { id: 'observe', label: 'Observe', icon: <Eye className="size-4 shrink-0" /> },
  { id: 'detect',  label: 'Detect',  icon: <AlertTriangle className="size-4 shrink-0" /> },
  { id: 'protect', label: 'Protect', icon: <Shield className="size-4 shrink-0" /> },
  { id: 'review',  label: 'Review',  icon: <Bookmark className="size-4 shrink-0" /> },
  { id: 'govern',  label: 'Govern',  icon: <Scale className="size-4 shrink-0" /> },
  { id: 'manage',  label: 'Manage',  icon: <Settings className="size-4 shrink-0" /> },
];
