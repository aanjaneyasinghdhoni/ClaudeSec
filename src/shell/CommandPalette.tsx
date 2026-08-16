import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  BookOpen, Compass, FolderGit2, Layers, Palette, Shield, Filter,
} from 'lucide-react';
import {
  Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList,
  CommandSeparator, CommandShortcut,
} from '../components/ui/command';
import { docsSearchIndex } from '../docs/docsRegistry';
import {
  CATEGORY_TABS, repoLabel, sessionDisplayLabel, type Repo, type Session, type Tab,
} from '../dashboardTypes';
import { THEMES, type ThemeId } from '../ThemeSwitcher';
import { SAVED_VIEWS } from './filterState';

const RECENTS_KEY = 'claudesec.paletteRecents';
const MAX_RECENTS = 5;
/** cmdk's own filter is O(n) over every mounted item; 6,500 sessions would make
 *  each keystroke crawl. Results are ranked and capped here instead. */
const MAX_PER_GROUP = 8;

interface Action {
  id: string;
  label: string;
  hint?: string;
  /** Extra text the ranker matches but no row ever shows, stored pre-lowercased.
   *  A session's displayed label is derived from its repo, so without this you
   *  could no longer find a session by the name it is actually stored under. */
  alias?: string;
  group: string;
  icon: React.ReactNode;
  run: () => void;
}

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sessions: Session[];
  repos: Repo[];
  theme: ThemeId;
  enforceMode: 'enforce' | 'monitor' | null;
  onSelectSession: (traceId: string | null) => void;
  onSelectRepo: (repo: string) => void;
  onNavigateTab: (tab: Tab) => void;
  onApplyView: (id: string) => void;
  onThemeChange: (theme: ThemeId) => void;
  onOpenDocs: (slug: string) => void;
  onToggleEnforce: () => void;
}

function readRecents(): string[] {
  try { return JSON.parse(localStorage.getItem(RECENTS_KEY) ?? '[]') as string[]; }
  catch { return []; }
}

/**
 * ⌘K. Two things here are deliberate and neither is the default.
 *
 * `shouldFilter={false}`: cmdk filters by mounting every item and scoring it in
 * the client, which does not survive six thousand sessions. Ranking happens
 * below and only the top few per group are mounted.
 *
 * Recents lead. The single most common reason to open a palette is to go back
 * somewhere you just were, and making that the first thing under the cursor
 * turns the shortcut into a one-keystroke jump most of the time.
 */
export function CommandPalette({
  open, onOpenChange, sessions, repos, theme, enforceMode,
  onSelectSession, onSelectRepo, onNavigateTab, onApplyView, onThemeChange, onOpenDocs, onToggleEnforce,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [recents, setRecents] = useState<string[]>(readRecents);

  useEffect(() => { if (!open) setQuery(''); }, [open]);

  const remember = useCallback((id: string) => {
    setRecents(prev => {
      const next = [id, ...prev.filter(p => p !== id)].slice(0, MAX_RECENTS);
      try { localStorage.setItem(RECENTS_KEY, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  }, []);

  // Deriving a session label formats a timestamp, and the action list below is
  // rebuilt whenever the dashboard re-renders — six thousand Intl calls a frame.
  // The labels only change when the session list does, so key them to that alone.
  const sessionLabels = useMemo(
    () => sessions.map(session => {
      const label = sessionDisplayLabel(session);
      // A renamed session already displays its stored name; no alias needed.
      return { label, alias: label === session.name ? undefined : session.name.toLowerCase() };
    }),
    [sessions],
  );

  const actions = useMemo<Action[]>(() => {
    const list: Action[] = [];

    for (const [category, tabs] of Object.entries(CATEGORY_TABS)) {
      for (const tab of tabs) {
        list.push({
          id: `tab:${tab.id}`,
          label: tab.label,
          hint: category,
          group: 'Go to',
          icon: <Compass className="size-3.5" />,
          run: () => onNavigateTab(tab.id),
        });
      }
    }

    for (const view of SAVED_VIEWS) {
      list.push({
        id: `view:${view.id}`,
        label: view.label,
        hint: view.description,
        group: 'Saved views',
        icon: <Filter className="size-3.5" />,
        run: () => onApplyView(view.id),
      });
    }

    for (const [i, session] of sessions.entries()) {
      list.push({
        id: `session:${session.traceId}`,
        label: sessionLabels[i].label,
        alias: sessionLabels[i].alias,
        hint: `${session.spanCount} spans`,
        group: 'Sessions',
        icon: <Layers className="size-3.5" />,
        run: () => onSelectSession(session.traceId),
      });
    }

    for (const repo of repos) {
      list.push({
        id: `repo:${repo.repo}`,
        label: repoLabel(repo.repo),
        hint: `${repo.sessionCount} sessions`,
        group: 'Repositories',
        icon: <FolderGit2 className="size-3.5" />,
        run: () => onSelectRepo(repo.repo),
      });
    }

    for (const doc of docsSearchIndex) {
      list.push({
        id: `doc:${doc.slug}`,
        label: doc.title,
        hint: doc.description,
        group: 'Docs',
        icon: <BookOpen className="size-3.5" />,
        run: () => onOpenDocs(doc.slug),
      });
    }

    for (const t of THEMES) {
      list.push({
        id: `theme:${t.id}`,
        label: `Theme — ${t.name}`,
        hint: t.id === theme ? 'current' : t.mode,
        group: 'Preferences',
        icon: <Palette className="size-3.5" />,
        run: () => onThemeChange(t.id),
      });
    }

    if (enforceMode) {
      list.push({
        id: 'enforce:toggle',
        label: enforceMode === 'enforce' ? 'Switch to monitor mode' : 'Switch to enforce mode',
        hint: 'Enforcement',
        group: 'Preferences',
        icon: <Shield className="size-3.5" />,
        run: onToggleEnforce,
      });
    }

    return list;
  }, [sessions, sessionLabels, repos, theme, enforceMode, onNavigateTab, onApplyView, onSelectSession, onSelectRepo, onOpenDocs, onThemeChange, onToggleEnforce]);

  const byId = useMemo(() => new Map(actions.map(a => [a.id, a])), [actions]);

  // Prefix beats substring beats alias beats hint — cheap, predictable, and it
  // puts an exact repo or session name at the top where muscle memory expects
  // it. Alias sits below the visible label so a match you can actually see on
  // the row always outranks one you cannot.
  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return actions.filter(a => a.group === 'Go to' || a.group === 'Saved views');
    }
    const scored: { action: Action; score: number }[] = [];
    for (const action of actions) {
      const label = action.label.toLowerCase();
      let score = 0;
      if (label === needle) score = 1000;
      else if (label.startsWith(needle)) score = 700;
      else if (label.includes(needle)) score = 400;
      else if (action.alias?.includes(needle)) score = 250;
      else if (action.hint?.toLowerCase().includes(needle)) score = 150;
      if (score > 0) scored.push({ action, score });
    }
    scored.sort((a, b) => b.score - a.score);
    return scored.map(s => s.action);
  }, [actions, query]);

  const grouped = useMemo(() => {
    const map = new Map<string, Action[]>();
    for (const action of results) {
      const bucket = map.get(action.group) ?? [];
      if (bucket.length < MAX_PER_GROUP) bucket.push(action);
      map.set(action.group, bucket);
    }
    return [...map.entries()];
  }, [results]);

  const recentActions = useMemo(
    () => (query ? [] : recents.map(id => byId.get(id)).filter((a): a is Action => !!a)),
    [recents, byId, query],
  );

  const choose = (action: Action) => {
    remember(action.id);
    onOpenChange(false);
    action.run();
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} className="max-w-xl">
      {/* CommandDialog is only the dialog chrome — cmdk's root has to be mounted
          inside it, which is also where shouldFilter belongs. */}
      <Command shouldFilter={false}>
      <CommandInput
        value={query}
        onValueChange={setQuery}
        placeholder="Jump to a session, repo, view or doc…"
      />
      <CommandList className="max-h-[60svh]">
        <CommandEmpty>Nothing matches “{query}”.</CommandEmpty>

        {recentActions.length > 0 && (
          <>
            <CommandGroup heading="Recents">
              {recentActions.map(action => (
                <CommandItem key={`recent-${action.id}`} value={`recent-${action.id}`} onSelect={() => choose(action)}>
                  {action.icon}
                  <span className="truncate">{action.label}</span>
                  {action.hint && <CommandShortcut className="truncate">{action.hint}</CommandShortcut>}
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        {grouped.map(([group, items]) => (
          <CommandGroup key={group} heading={group}>
            {items.map(action => (
              <CommandItem key={action.id} value={action.id} onSelect={() => choose(action)}>
                {action.icon}
                <span className="truncate">{action.label}</span>
                {action.hint && <CommandShortcut className="truncate">{action.hint}</CommandShortcut>}
              </CommandItem>
            ))}
          </CommandGroup>
        ))}
      </CommandList>
      </Command>
    </CommandDialog>
  );
}
