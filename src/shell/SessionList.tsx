import React, { useMemo, useState } from 'react';
import { ChevronDown, Edit2, FileText, Layers, Star, StickyNote, X } from 'lucide-react';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible';
import {
  HARNESS_COLORS, LABEL_COLORS, SEV_RANK, primarySessionHarness, sessionDisplayLabel,
  sessionHarnessTitle, type Session, type SessionLabel,
} from '../dashboardTypes';
import type { Severity } from '../shared/types';
import {
  SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarInput,
  SidebarMenu, SidebarMenuItem,
} from '../components/ui/sidebar';
import { Button } from '../components/ui/button';

// How many rows the list paints before asking for a click. Sixty was enough to
// bury everything below it: the repository tree sits under this list, and with
// 6,500 sessions all named "Claude Code · <time>" those sixty rows are almost
// indistinguishable from each other, so the scroll bought nothing. Twenty fills
// the column once and leaves the rest of the panel reachable.
const PAGE = 20;
/** Hard ceiling on a search — past this the answer is "refine the query". */
const SEARCH_CAP = 500;

export interface SessionActions {
  onSelect: (traceId: string | null) => void;
  onCompare: (traceId: string) => void;
  onTogglePin: (session: Session) => void;
  onStartRename: (session: Session) => void;
  onCommitRename: () => void;
  onEditNameChange: (value: string) => void;
  onToggleNotes: (session: Session) => void;
  onNotesChange: (value: string) => void;
  onNotesCommit: (session: Session) => void;
  onLabelChange: (session: Session, label: SessionLabel) => void;
}

export interface SessionListProps extends SessionActions {
  sessions: Session[];
  activeSession: string | null;
  comparePending: string | null;
  editingSession: string | null;
  editName: string;
  notesSession: string | null;
  notesText: string;
  /** Span total across the whole (unscoped) graph, for the "All sessions" row. */
  spanTotal: number;
}

function severityOf(session: Session): Severity {
  return SEV_RANK[session.maxSeverityRank] ?? 'none';
}

/**
 * Zone two, Observe: the session list.
 *
 * Six thousand sessions is not a rendering problem, it is a finding problem, so
 * this is search-first rather than virtualised: a search box at the top, pinned
 * sessions above everything, then the most recent, then a "show more" for the
 * tail. Ranking and capping is what five of the six products I looked at do;
 * only one virtualises, and virtualising here would cost the native find-in-page
 * that makes a long list usable in the first place.
 */
export function SessionList({
  sessions, activeSession, comparePending, editingSession, editName,
  notesSession, notesText, spanTotal, ...actions
}: SessionListProps) {
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(PAGE);

  const { pinned, recent, total } = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const matches = needle
      ? sessions.filter(s =>
          s.name.toLowerCase().includes(needle) ||
          (s.repo ?? '').toLowerCase().includes(needle) ||
          s.traceId.toLowerCase().includes(needle),
        ).slice(0, SEARCH_CAP)
      : sessions;
    return {
      pinned: matches.filter(s => s.pinned),
      recent: matches.filter(s => !s.pinned),
      total: matches.length,
    };
  }, [sessions, query]);

  const shown = recent.slice(0, limit);

  return (
    <>
      <div className="p-1.5" style={{ borderBottom: '1px solid var(--cs-rule)' }}>
        <SidebarInput
          value={query}
          onChange={e => { setQuery(e.target.value); setLimit(PAGE); }}
          placeholder={`Find in ${sessions.length.toLocaleString()} sessions…`}
          aria-label="Find a session"
          className="h-7 text-xs"
        />
      </div>

      <SidebarGroup className="p-1.5">
        <SidebarGroupContent>
          <SidebarMenu>
            <SidebarMenuItem>
              <button
                type="button"
                onClick={() => actions.onSelect(null)}
                className="flex h-7 w-full items-center gap-2 rounded-md px-2 text-left text-xs transition-colors hover:bg-sidebar-accent"
                style={activeSession === null
                  ? { background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)' }
                  : { color: 'var(--cs-text-muted)' }}
              >
                <Layers className="size-3 shrink-0" />
                <span className="truncate">All sessions</span>
                <span className="ml-auto font-mono text-[10px] tabular-nums">{spanTotal.toLocaleString()}</span>
              </button>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>

      {pinned.length > 0 && (
        <SessionGroup label="Pinned">
          {pinned.map(session => (
            <SessionRow
              key={session.traceId}
              session={session}
              activeSession={activeSession}
              comparePending={comparePending}
              editingSession={editingSession}
              editName={editName}
              notesSession={notesSession}
              notesText={notesText}
              {...actions}
            />
          ))}
        </SessionGroup>
      )}

      <SessionGroup label={query ? 'Matches' : 'Recent'} count={total}>
        {shown.map(session => (
          <SessionRow
            key={session.traceId}
            session={session}
            activeSession={activeSession}
            comparePending={comparePending}
            editingSession={editingSession}
            editName={editName}
            notesSession={notesSession}
            notesText={notesText}
            {...actions}
          />
        ))}
        {recent.length > shown.length && (
          <div className="px-2 pt-1">
            <Button variant="ghost" size="xs" className="w-full" onClick={() => setLimit(l => l + PAGE * 2)}>
              Show {Math.min(PAGE * 2, recent.length - shown.length)} more
            </Button>
          </div>
        )}
        {query && total >= SEARCH_CAP && (
          <p className="px-2 pt-1 text-[10px]" style={{ color: 'var(--cs-text-faint)' }}>
            Showing the first {SEARCH_CAP} matches — narrow the search to see the rest.
          </p>
        )}
        {shown.length === 0 && pinned.length === 0 && (
          <p className="px-2 py-3 text-center text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
            {query ? 'No session matches that.' : 'No sessions yet.'}
          </p>
        )}
      </SessionGroup>
    </>
  );
}

// Collapsible because this list sits directly above the repository tree, and a
// long run of near-identical session rows is the only thing standing between the
// reader and the panel below it. The header stays a real button so the count is
// still visible when the body is shut.
function SessionGroup({ label, count, children }: { label: string; count?: number; children: React.ReactNode }) {
  const [open, setOpen] = useState(true);
  return (
    <SidebarGroup className="p-1.5">
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger asChild>
          <SidebarGroupLabel className="h-6 w-full cursor-pointer text-[10px] font-semibold uppercase tracking-wider">
            <ChevronDown className={`mr-1 size-3 transition-transform ${open ? '' : '-rotate-90'}`} aria-hidden="true" />
            {label}
            {count !== undefined && <span className="ml-auto font-mono tabular-nums">{count.toLocaleString()}</span>}
          </SidebarGroupLabel>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarGroupContent>
            <SidebarMenu className="cs-rows">{children}</SidebarMenu>
          </SidebarGroupContent>
        </CollapsibleContent>
      </Collapsible>
    </SidebarGroup>
  );
}

function SessionRow({
  session, activeSession, comparePending, editingSession, editName, notesSession, notesText,
  onSelect, onCompare, onTogglePin, onStartRename, onCommitRename, onEditNameChange,
  onToggleNotes, onNotesChange, onNotesCommit, onLabelChange,
}: { session: Session } & Omit<SessionListProps, 'sessions' | 'spanTotal'>) {
  const isActive = activeSession === session.traceId;
  const isEditing = editingSession === session.traceId;
  const notesOpen = notesSession === session.traceId;
  const severity = severityOf(session);
  const label = (session.label ?? 'normal') as SessionLabel;

  return (
    <SidebarMenuItem>
      <div
        className="group/session flex items-center gap-1.5 rounded-md pr-1 transition-colors hover:bg-sidebar-accent"
        style={{
          height: 'var(--cs-row-h)',
          background: isActive ? 'var(--cs-accent-soft)'
            : comparePending === session.traceId ? 'var(--cs-bg-raised)' : undefined,
        }}
      >
        {/* The severity spine — one vertical line down the whole list, so a
            column of rows can be triaged without reading a word. */}
        <span className="h-4 w-[3px] shrink-0 rounded-full" style={{ background: `var(--cs-sev-${severity})` }} />

        {isEditing ? (
          <form
            className="min-w-0 flex-1"
            onSubmit={e => { e.preventDefault(); onCommitRename(); }}
          >
            <input
              autoFocus
              value={editName}
              onChange={e => onEditNameChange(e.target.value)}
              onBlur={onCommitRename}
              aria-label="Session name"
              className="w-full rounded px-1 py-0.5 text-xs outline-none"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-strong)' }}
            />
          </form>
        ) : (
          <>
            {/* The label below trades the harness name for the repo it ran
                against — the thing that actually tells 6,500 near-identical
                sessions apart — so this dot is what still says Claude Code vs
                Codex vs Copilot at a glance. */}
            <span
              className="size-1.5 shrink-0 rounded-full"
              style={{ background: HARNESS_COLORS[primarySessionHarness(session.harnesses)] ?? HARNESS_COLORS.unknown }}
              title={sessionHarnessTitle(session.harnesses)}
              aria-hidden="true"
            />
            <button
              type="button"
              className="min-w-0 flex-1 truncate text-left text-xs"
              style={{ color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-body)' }}
              title={`${session.name} · Click to scope · Ctrl-click to compare`}
              onClick={e => {
                if (e.ctrlKey || e.metaKey) onCompare(session.traceId);
                else onSelect(isActive ? null : session.traceId);
              }}
            >
              {sessionDisplayLabel(session)}
            </button>
            {label !== 'normal' && (
              <span className="size-1.5 shrink-0 rounded-full" style={{ background: LABEL_COLORS[label].dot }} title={`Label: ${label}`} />
            )}
            <span className="shrink-0 font-mono text-[10px] tabular-nums" style={{ color: 'var(--cs-text-faint)' }}>
              {session.spanCount}
            </span>
            <RowAction
              label={session.pinned ? 'Unpin session' : 'Pin session'}
              always={!!session.pinned}
              onClick={() => onTogglePin(session)}
            >
              <Star className="size-3" fill={session.pinned ? 'currentColor' : 'none'} />
            </RowAction>
            <RowAction label="Rename session" onClick={() => onStartRename(session)}>
              <Edit2 className="size-3" />
            </RowAction>
            <a
              href={`/api/sessions/${encodeURIComponent(session.traceId)}/report`}
              target="_blank"
              rel="noreferrer"
              title="Download HTML report"
              className="shrink-0 rounded p-0.5 opacity-0 transition-opacity group-hover/session:opacity-100 focus-visible:opacity-100"
              style={{ color: 'var(--cs-text-faint)' }}
            >
              <FileText className="size-3" />
            </a>
            <RowAction label="Session notes and label" always={notesOpen} onClick={() => onToggleNotes(session)}>
              <StickyNote className="size-3" />
            </RowAction>
          </>
        )}
      </div>

      {notesOpen && (
        <div className="mt-1 mb-1 space-y-2 rounded-lg p-2" style={{ background: 'var(--cs-bg-raised)' }}>
          <div>
            <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>Label</p>
            <div className="flex flex-wrap gap-1">
              {(Object.keys(LABEL_COLORS) as SessionLabel[]).map(option => (
                <button
                  key={option}
                  type="button"
                  onClick={() => onLabelChange(session, option)}
                  className="rounded px-1.5 py-0.5 text-[11px] capitalize transition-opacity"
                  style={{
                    background: `${LABEL_COLORS[option].dot}22`,
                    color: LABEL_COLORS[option].dot,
                    border: label === option ? `1px solid ${LABEL_COLORS[option].dot}` : '1px solid transparent',
                    opacity: label === option ? 1 : 0.65,
                  }}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>Notes</p>
            <textarea
              value={notesText}
              onChange={e => onNotesChange(e.target.value)}
              onBlur={() => onNotesCommit(session)}
              placeholder="Add investigation notes…"
              rows={3}
              className="w-full resize-none rounded px-2 py-1 text-xs outline-none"
              style={{ background: 'var(--cs-bg-canvas)', border: '1px solid var(--cs-rule)', color: 'var(--cs-text-body)' }}
            />
          </div>
        </div>
      )}
    </SidebarMenuItem>
  );
}

/** Hover-revealed row action that stays visible on keyboard focus. */
function RowAction({ label, onClick, always = false, children }: {
  label: string;
  onClick: () => void;
  always?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`shrink-0 rounded p-0.5 transition-opacity focus-visible:opacity-100 ${always ? 'opacity-70' : 'opacity-0 group-hover/session:opacity-100'}`}
      style={{ color: 'var(--cs-text-faint)' }}
    >
      {children}
    </button>
  );
}

/** Small banner shown while a comparison is half-picked. */
export function ComparePrompt({ onCancel }: { onCancel: () => void }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-[11px]" style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)' }}>
      Pick a second session to compare…
      <button type="button" onClick={onCancel} aria-label="Cancel comparison" className="ml-auto rounded p-0.5">
        <X className="size-3" />
      </button>
    </div>
  );
}
