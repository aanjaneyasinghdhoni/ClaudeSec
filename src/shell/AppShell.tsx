import React, { useEffect, useMemo, useState } from 'react';
import { Command as CommandIcon, PanelLeft } from 'lucide-react';
import { CATEGORIES, type Category } from '../CategoryNav';
import { CATEGORY_TABS, type Repo, type Session, type Tab } from '../dashboardTypes';
import {
  Sidebar, SidebarContent, SidebarInset, SidebarProvider, useSidebar,
} from '../components/ui/sidebar';
import { TooltipProvider } from '../components/ui/tooltip';
import { Button } from '../components/ui/button';
import { NavRail, Wordmark } from './NavRail';
import { SessionList, ComparePrompt, type SessionActions } from './SessionList';
import { RepoTree } from './RepoTree';
import { DetectPanel, GovernPanel, ManagePanel, ProtectPanel, ReviewPanel } from './CategoryPanels';
import { DetailPane, type DetailTarget } from './DetailPane';
import { hasDetailColumn, useTier } from './breakpoints';

const RAIL_KEY = 'claudesec.railCollapsed';

/**
 * Reads the rail's persisted state before first paint.
 *
 * shadcn ships this as a cookie read on the server in Next; in a Vite SPA there
 * is no server render, so reading it here and handing SidebarProvider a
 * `defaultOpen` is what stops the rail from flashing open on every load. The key
 * is the one the previous rail already used, so nobody's preference is reset.
 */
function initialRailOpen(narrow: boolean): boolean {
  let stored: string | null = null;
  try { stored = localStorage.getItem(RAIL_KEY); } catch { /* private mode */ }
  if (stored !== null) return stored !== 'true';
  // No stored preference: labels are affordable from 1440 up, and below that the
  // 256px list column matters more than seeing the word "Observe".
  return !narrow;
}

export interface AppShellProps extends SessionActions {
  activeCategory: Category;
  activeTab: Tab;
  docsOpen: boolean;
  onCategoryChange: (category: Category) => void;
  onTabChange: (tab: Tab) => void;
  onOpenDocs: () => void;
  onOpenPalette: () => void;

  alertCount: number;
  sessions: Session[];
  repos: Repo[];
  activeSession: string | null;
  spanTotal: number;
  comparePending: string | null;
  onCancelCompare: () => void;
  editingSession: string | null;
  editName: string;
  notesSession: string | null;
  notesText: string;

  /** Repo keys currently filtering, and the toggle that writes them to the URL. */
  selectedRepos: string[];
  onToggleRepo: (repo: string) => void;

  /** The one filter bar. Built by the caller because only it has the counts. */
  filterBar?: React.ReactNode;
  headerActions?: React.ReactNode;
  statusBar?: React.ReactNode;
  banner?: React.ReactNode;

  detail: DetailTarget | null;
  onCloseDetail: () => void;

  children: React.ReactNode;
}

export function AppShell(props: AppShellProps) {
  const tier = useTier();
  const narrow = tier === 'lg' || tier === 'xl';
  const [railOpen, setRailOpen] = useState(() => initialRailOpen(narrow));

  useEffect(() => {
    try { localStorage.setItem(RAIL_KEY, String(!railOpen)); } catch { /* ignore */ }
  }, [railOpen]);

  // Between 1024 and 1279 there is no width to spend on labels: the rail is
  // pinned to icons regardless of preference, and the preference is restored the
  // moment the window grows again.
  const open = tier === 'lg' ? false : railOpen;

  return (
    <TooltipProvider delayDuration={200}>
      <div
        className="flex min-h-svh w-full flex-col overflow-x-hidden lg:h-svh lg:overflow-hidden"
        style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}
      >
        <SidebarProvider
          open={open}
          onOpenChange={setRailOpen}
          className="min-h-0! flex-1 flex-col"
          style={{
            // The rail and the list column share one Sidebar (the nested
            // composition), so its width is the sum of both — collapsing shrinks
            // the rail to icons and leaves the list exactly where it was. These
            // have to sit on the provider: the Sidebar's own `style` lands on the
            // fixed container, while the spacer that reserves the column reads
            // them from this wrapper.
            '--sidebar-width': 'calc(var(--cs-rail-w) + var(--cs-list-w))',
            '--sidebar-width-icon': 'calc(3rem + var(--cs-list-w))',
          } as React.CSSProperties}
        >
          <ShellHeader
            onOpenPalette={props.onOpenPalette}
            actions={props.headerActions}
          />
          {props.banner}
          <div className="flex min-h-0 w-full flex-1">
            <Sidebar
              collapsible="icon"
              className="overflow-hidden *:data-[sidebar=sidebar]:flex-row lg:top-(--cs-header-h)! lg:h-[calc(100svh-var(--cs-header-h))]!"
            >
              <NavRail
                activeCategory={props.activeCategory}
                activeTab={props.activeTab}
                docsActive={props.docsOpen}
                alertCount={props.alertCount}
                onCategoryChange={props.onCategoryChange}
                onTabChange={props.onTabChange}
                onOpenDocs={props.onOpenDocs}
              />
              <ContextColumn {...props} />
            </Sidebar>

            <SidebarInset className="flex min-h-0 min-w-0 flex-col overflow-hidden">
              <SubTabStrip
                activeCategory={props.activeCategory}
                activeTab={props.activeTab}
                alertCount={props.alertCount}
                onTabChange={props.onTabChange}
              />
              {props.filterBar}
              {/* Past 2560 an unbounded content column turns every table row into
                  a 2,000px line the eye has to track back across. */}
              <div className="min-h-0 flex-1 overflow-y-auto">
                <div className="mx-auto flex w-full flex-col 4xl:max-w-[110rem]">{props.children}</div>
              </div>
              {props.statusBar}
            </SidebarInset>

            <DetailPane
              target={props.detail}
              persistent={hasDetailColumn(tier)}
              onClose={props.onCloseDetail}
            />
          </div>
        </SidebarProvider>
      </div>
    </TooltipProvider>
  );
}

/** Full-width, sticky, and the only thing above the two columns. */
function ShellHeader({ onOpenPalette, actions }: { onOpenPalette: () => void; actions?: React.ReactNode }) {
  const { toggleSidebar } = useSidebar();
  return (
    <header
      className="sticky top-0 z-50 flex h-(--cs-header-h) w-full shrink-0 items-center gap-2 px-3"
      style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
    >
      <Button
        variant="ghost"
        size="icon-sm"
        onClick={toggleSidebar}
        aria-label="Toggle navigation"
        className="lg:hidden"
      >
        <PanelLeft />
      </Button>
      <Wordmark />
      <Button
        variant="ghost"
        size="sm"
        onClick={onOpenPalette}
        className="ml-2 hidden xl:flex"
        style={{ color: 'var(--cs-text-faint)' }}
      >
        <CommandIcon className="size-3.5" />
        Search everything
        <kbd className="ml-2 rounded px-1 font-mono text-[10px]" style={{ background: 'var(--cs-bg-raised)' }}>⌘K</kbd>
      </Button>
      <div className="ml-auto flex items-center gap-0.5">{actions}</div>
    </header>
  );
}

/** Zone two. One list, never a stack of five equal-weight boxes. */
function ContextColumn(props: AppShellProps) {
  const {
    activeCategory, activeTab, alertCount, sessions, repos, activeSession, spanTotal,
    comparePending, onCancelCompare, editingSession, editName, notesSession, notesText,
    selectedRepos, onToggleRepo, onTabChange,
  } = props;

  const sessionActions: SessionActions = {
    onSelect: props.onSelect,
    onCompare: props.onCompare,
    onTogglePin: props.onTogglePin,
    onStartRename: props.onStartRename,
    onCommitRename: props.onCommitRename,
    onEditNameChange: props.onEditNameChange,
    onToggleNotes: props.onToggleNotes,
    onNotesChange: props.onNotesChange,
    onNotesCommit: props.onNotesCommit,
    onLabelChange: props.onLabelChange,
  };

  return (
    <Sidebar
      collapsible="none"
      data-cs-list=""
      className="flex min-w-0 flex-1"
      style={{ borderRight: '1px solid var(--cs-rule)' }}
    >
      {comparePending && <ComparePrompt onCancel={onCancelCompare} />}
      <SidebarContent>
        {activeCategory === 'observe' && (
          <>
            <SessionList
              sessions={sessions}
              activeSession={activeSession}
              comparePending={comparePending}
              editingSession={editingSession}
              editName={editName}
              notesSession={notesSession}
              notesText={notesText}
              spanTotal={spanTotal}
              {...sessionActions}
            />
            <RepoTree repos={repos} selected={selectedRepos} onToggle={onToggleRepo} />
          </>
        )}
        {activeCategory === 'detect' && <DetectPanel alertCount={alertCount} />}
        {activeCategory === 'protect' && <ProtectPanel />}
        {activeCategory === 'review' && <ReviewPanel />}
        {activeCategory === 'govern' && <GovernPanel />}
        {activeCategory === 'manage' && <ManagePanel activeTab={activeTab} onTabChange={onTabChange} />}
      </SidebarContent>
    </Sidebar>
  );
}

function SubTabStrip({ activeCategory, activeTab, alertCount, onTabChange }: {
  activeCategory: Category;
  activeTab: Tab;
  alertCount: number;
  onTabChange: (tab: Tab) => void;
}) {
  return (
    <div
      className="cs-scroll-x flex shrink-0 flex-nowrap items-center gap-0.5 overflow-x-auto px-2"
      style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
    >
      <span
        className="mr-1 shrink-0 rounded-md px-2 py-1 text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: 'var(--cs-text-faint)', background: 'var(--cs-bg-raised)' }}
      >
        {CATEGORIES.find(c => c.id === activeCategory)?.label}
      </span>
      {CATEGORY_TABS[activeCategory].map(tab => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            aria-current={isActive ? 'page' : undefined}
            className="relative flex shrink-0 items-center gap-1.5 whitespace-nowrap px-2.5 py-2 text-[11px] font-medium"
            style={{ color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
          >
            {tab.label}
            {tab.id === 'alerts' && alertCount > 0 && (
              <span
                className="flex h-4 min-w-4 items-center justify-center rounded-full px-1 font-mono text-[10px] font-bold leading-none"
                style={{ background: 'var(--cs-sev-critical)', color: 'var(--cs-text-invert)' }}
              >
                {alertCount > 999 ? '999+' : alertCount}
              </span>
            )}
            {isActive && (
              <span className="absolute inset-x-1 bottom-0 h-[2px] rounded-t-full" style={{ background: 'var(--cs-accent)' }} />
            )}
          </button>
        );
      })}
    </div>
  );
}
