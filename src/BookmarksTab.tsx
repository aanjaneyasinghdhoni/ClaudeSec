/**
 * BookmarksTab — the things I decided were worth keeping.
 *
 * Everywhere else in this app the list is written by the machine and my job is
 * to triage it. This one is the opposite: every row here exists because a human
 * deliberately put it there, and there are rarely more than a couple of dozen.
 * So it is built as a curated list rather than a table dump — no column
 * headers, no density switch, room for the note to be read — while still
 * borrowing the design system's spine, planes and states so it belongs to the
 * same product as the alert log.
 *
 * The one place severity shows up is a pinned session's health score, which is
 * a real risk signal, so it gets a real spine. A span bookmark carries no
 * severity of its own and deliberately gets none: an invented colour would
 * teach the wrong thing about what colour means here.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Bookmark, Trash2, ExternalLink, Edit2, Check, X, Star, BookmarkPlus } from 'lucide-react';
import { socket } from './socket';
import type { Severity } from './shared/types';
import {
  SeveritySpine, severityText, EmptyState, ErrorState, TableSkeleton,
} from './components/data';

interface BookmarkRow {
  id: number;
  spanId: string;
  traceId: string;
  note: string;
  createdAt: string;
}

interface PinnedSession {
  traceId: string;
  name: string;
  pinned: number;
  healthScore?: number;
  threatCount?: number;
  spanCount?: number;
}

/**
 * A session's health score onto the severity ramp.
 *
 * The score is already a risk statement, so it reuses the one colour language
 * the product teaches instead of inventing a green/amber/red of its own. The
 * number itself always renders next to the spine, so the level never depends on
 * the colour alone.
 */
function healthSeverity(score: number): Severity {
  if (score >= 80) return 'none';
  if (score >= 60) return 'low';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'high';
  return 'critical';
}

/** A section eyebrow. Furniture — it names the group and then gets out of the way. */
function SectionHeader({ icon, label, count }: { icon: React.ReactNode; label: string; count: number }) {
  return (
    <div className="flex items-center gap-2 px-1 pb-1.5">
      <span style={{ color: 'var(--cs-text-faint)' }}>{icon}</span>
      <h3
        className="uppercase"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          fontWeight: 'var(--cs-weight-bold)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {label}
      </h3>
      <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
        {count}
      </span>
    </div>
  );
}

/** A small square action button. Ground on hover, never an outline. */
function IconButton({
  danger = false,
  style,
  ...props
}: React.ComponentProps<'button'> & { danger?: boolean }) {
  return (
    <button
      type="button"
      {...props}
      className="p-1.5 rounded transition-colors shrink-0 hover:bg-[var(--cs-bg-raised)]"
      style={{ color: danger ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-faint)', ...style }}
    />
  );
}

export function BookmarksTab({
  onSelectSession,
}: {
  // `spanId` is optional: passed for a span bookmark so the caller can select
  // and highlight that span once the scoped graph loads.
  onSelectSession?: (traceId: string, spanId?: string) => void;
}) {
  const [bookmarks,      setBookmarks]      = useState<BookmarkRow[]>([]);
  const [pinnedSessions, setPinnedSessions] = useState<PinnedSession[]>([]);
  const [editingId,      setEditingId]      = useState<number | null>(null);
  const [editNote,       setEditNote]       = useState('');
  const [sessionFilter,  setSessionFilter]  = useState('');
  const [loading,        setLoading]        = useState(true);
  const [loadError,      setLoadError]      = useState<string | null>(null);

  // The list is one tab stop and the arrow keys walk it, the same contract the
  // shared table gives its rows — so moving between saved items never means
  // tabbing through three controls per row.
  const listRef = useRef<HTMLDivElement>(null);

  const fetchBookmarks = useCallback((filter = sessionFilter) => {
    const params = new URLSearchParams();
    if (filter) params.set('session', filter);
    fetch(`/api/bookmarks?${params}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: { bookmarks?: BookmarkRow[] } | BookmarkRow[]) => {
        const rows = Array.isArray(data) ? data : (data.bookmarks ?? []);
        setBookmarks(rows);
        setLoadError(null);
      })
      // Saved work quietly disappearing is the worst failure this tab has, so a
      // failed load says so instead of rendering an empty, reassuring list.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, [sessionFilter]);

  const fetchPinnedSessions = useCallback(() => {
    fetch('/api/sessions')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: { sessions?: PinnedSession[] }) => {
        const rows = data.sessions ?? [];
        setPinnedSessions(rows.filter(s => s.pinned));
      })
      .catch((e: Error) => setLoadError(prev => prev ?? (e.message || 'Request failed')));
  }, []);

  useEffect(() => { fetchBookmarks(); fetchPinnedSessions(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { fetchBookmarks(sessionFilter); }, [sessionFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const handler = () => fetchBookmarks(sessionFilter);
    socket.on('bookmarks-update', handler);
    return () => { socket.off('bookmarks-update', handler); };
  }, [sessionFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const handler = () => fetchPinnedSessions();
    socket.on('sessions-update', handler);
    return () => { socket.off('sessions-update', handler); };
  }, [fetchPinnedSessions]);

  const unpinSession = async (traceId: string) => {
    await fetch(`/api/sessions/${encodeURIComponent(traceId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pinned: false }),
    });
    fetchPinnedSessions();
  };

  const deleteBookmark = async (id: number) => {
    await fetch(`/api/bookmarks/${id}`, { method: 'DELETE' });
    fetchBookmarks();
  };

  const startEdit = (bm: BookmarkRow) => {
    setEditingId(bm.id);
    setEditNote(bm.note);
  };

  const saveEdit = async (id: number) => {
    await fetch(`/api/bookmarks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: editNote }),
    });
    setEditingId(null);
    fetchBookmarks();
  };

  const cancelEdit = () => { setEditingId(null); };

  const formatTime = (ts: string) => {
    try { return new Date(ts).toLocaleString(); }
    catch { return ts; }
  };

  // Roving focus across every saved item, in the order they are rendered.
  const moveFocus = (from: HTMLElement, delta: number | 'first' | 'last') => {
    const all = Array.from(listRef.current?.querySelectorAll<HTMLElement>('[data-nav-item]') ?? []);
    if (all.length === 0) return;
    const here = all.indexOf(from);
    const next =
      delta === 'first' ? 0 :
      delta === 'last'  ? all.length - 1 :
      Math.min(all.length - 1, Math.max(0, here + delta));
    all[next]?.focus();
  };

  const onItemKeyDown = (e: React.KeyboardEvent<HTMLDivElement>, activate?: () => void) => {
    // Let a button or input inside the item handle its own keys first.
    if (e.target !== e.currentTarget) return;
    switch (e.key) {
      case 'Enter':
      case ' ':
        if (activate) { e.preventDefault(); activate(); }
        break;
      case 'ArrowDown': e.preventDefault(); moveFocus(e.currentTarget, 1); break;
      case 'ArrowUp':   e.preventDefault(); moveFocus(e.currentTarget, -1); break;
      case 'Home':      e.preventDefault(); moveFocus(e.currentTarget, 'first'); break;
      case 'End':       e.preventDefault(); moveFocus(e.currentTarget, 'last'); break;
      default: break;
    }
  };

  // One tab stop for the whole list: the first item, until focus moves.
  const [focusedKey, setFocusedKey] = useState<string | null>(null);
  const firstKey = pinnedSessions[0] ? `s:${pinnedSessions[0].traceId}` : bookmarks[0] ? `b:${bookmarks[0].id}` : null;
  const tabIndexFor = (key: string) => ((focusedKey ?? firstKey) === key ? 0 : -1);

  const nothingSaved = pinnedSessions.length === 0 && bookmarks.length === 0;
  const filtered = !!sessionFilter;

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-2 xl:gap-3 px-3 py-1.5 shrink-0 flex-wrap"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        <div className="flex items-center gap-2 shrink-0">
          <Bookmark className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          <h2 style={{ fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
            Saved
          </h2>
          <span
            className="cs-mono"
            title={`${pinnedSessions.length} pinned sessions, ${bookmarks.length} saved spans`}
            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
          >
            {pinnedSessions.length} · {bookmarks.length}
          </span>
        </div>

        <div className="ml-auto flex items-center gap-1">
          <input
            type="search"
            aria-label="Filter saved spans by session trace ID"
            placeholder="Filter by session…"
            value={sessionFilter}
            onChange={e => setSessionFilter(e.target.value)}
            className="cs-mono w-44 xl:w-56 rounded-md px-2 py-1 outline-none focus-visible:outline-2"
            style={{
              background: 'var(--cs-bg-raised)',
              color: 'var(--cs-text-body)',
              fontSize: 'var(--cs-text-xs)',
              outlineColor: 'var(--cs-accent)',
            }}
          />
        </div>
      </div>

      {/* ── The list ─────────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        {loading ? (
          <TableSkeleton rows={6} columns={3} rowHeight="var(--cs-row-comfy)" />
        ) : loadError ? (
          <ErrorState
            title="Could not load what you saved"
            description={`The bookmark store did not respond (${loadError}). Nothing has been lost — this is only the view.`}
            onRetry={() => { setLoading(true); setLoadError(null); fetchBookmarks(sessionFilter); fetchPinnedSessions(); }}
          />
        ) : nothingSaved ? (
          filtered ? (
            <EmptyState
              icon={<Bookmark className="w-6 h-6" aria-hidden="true" />}
              title="No saved spans in that session"
              description="Nothing saved matches this trace ID. Clear the filter above to see everything you have kept."
            />
          ) : (
            <EmptyState
              icon={<BookmarkPlus className="w-6 h-6" aria-hidden="true" />}
              title="Nothing saved yet"
              description="Pin a session with the ★ in the session list, or select a span in the Timeline and click the bookmark icon. Anything you keep — plus the note you wrote on it — shows up here."
            />
          )
        ) : (
          <div ref={listRef} className="max-w-4xl px-3 py-3 space-y-5">

            {pinnedSessions.length > 0 && (
              <section>
                <SectionHeader
                  icon={<Star className="w-3.5 h-3.5" aria-hidden="true" />}
                  label="Pinned sessions"
                  count={pinnedSessions.length}
                />
                <div
                  role="list"
                  className="rounded-lg overflow-hidden"
                  style={{ background: 'var(--cs-bg-surface)' }}
                >
                  {pinnedSessions.map(ps => {
                    const hs  = ps.healthScore;
                    const sev = hs === undefined ? 'none' : healthSeverity(hs);
                    const key = `s:${ps.traceId}`;
                    const open = () => onSelectSession?.(ps.traceId);
                    return (
                      <div
                        key={ps.traceId}
                        role="listitem"
                        data-nav-item
                        tabIndex={tabIndexFor(key)}
                        onFocus={() => setFocusedKey(key)}
                        onClick={open}
                        onKeyDown={e => onItemKeyDown(e, open)}
                        title="Open this session in the Timeline"
                        className="flex items-stretch gap-3 px-3 py-2.5 cursor-pointer transition-colors hover:bg-[var(--cs-bg-raised)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
                        style={{ borderBottom: '1px solid var(--cs-rule)' }}
                      >
                        <SeveritySpine severity={sev} />
                        <div className="flex-1 min-w-0 flex flex-col justify-center">
                          <span
                            className="truncate"
                            style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-medium)' }}
                          >
                            {ps.name || `${ps.traceId.slice(0, 12)}…`}
                          </span>
                          <span
                            className="cs-mono truncate"
                            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
                          >
                            {ps.traceId}
                            {ps.spanCount != null && ` · ${ps.spanCount.toLocaleString()} spans`}
                          </span>
                        </div>

                        {/* The score is the word that travels with the colour. */}
                        {hs !== undefined && (
                          <span
                            className="cs-mono self-center shrink-0 tabular-nums"
                            title={`Health score ${hs}/100 — ${sev} risk`}
                            style={{ color: severityText(sev), fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-bold)' }}
                          >
                            {hs}
                          </span>
                        )}
                        {!!ps.threatCount && (
                          <span
                            className="cs-mono self-center shrink-0"
                            title={`${ps.threatCount} detections in this session`}
                            style={{ color: 'var(--cs-sev-high-fg)', fontSize: 'var(--cs-text-xs)' }}
                          >
                            {ps.threatCount} threats
                          </span>
                        )}
                        <IconButton
                          onClick={e => { e.stopPropagation(); unpinSession(ps.traceId); }}
                          onKeyDown={e => e.stopPropagation()}
                          title="Unpin this session"
                          aria-label="Unpin this session"
                          style={{ alignSelf: 'center' }}
                        >
                          <X className="w-3.5 h-3.5" aria-hidden="true" />
                        </IconButton>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {bookmarks.length > 0 && (
              <section>
                <SectionHeader
                  icon={<Bookmark className="w-3.5 h-3.5" aria-hidden="true" />}
                  label="Saved spans"
                  count={bookmarks.length}
                />
                <div
                  role="list"
                  className="rounded-lg overflow-hidden"
                  style={{ background: 'var(--cs-bg-surface)' }}
                >
                  {bookmarks.map(bm => {
                    const key  = `b:${bm.id}`;
                    const open = bm.traceId ? () => onSelectSession?.(bm.traceId, bm.spanId) : undefined;
                    const editing = editingId === bm.id;
                    return (
                      <div
                        key={bm.id}
                        role="listitem"
                        data-nav-item
                        tabIndex={tabIndexFor(key)}
                        onFocus={() => setFocusedKey(key)}
                        onKeyDown={e => onItemKeyDown(e, open)}
                        className="px-3 py-2.5 transition-colors hover:bg-[var(--cs-bg-raised)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
                        style={{ borderBottom: '1px solid var(--cs-rule)' }}
                      >
                        <div className="flex items-start gap-2 min-w-0">
                          <div className="flex-1 min-w-0">
                            {/* Identity line: the ids are compared and copied,
                                so they are mono and they do not wrap. */}
                            <div className="flex items-center gap-2 flex-wrap min-w-0">
                              <code
                                className="cs-mono truncate"
                                title={`Span ${bm.spanId}`}
                                style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-sm)' }}
                              >
                                {bm.spanId}
                              </code>
                              {bm.traceId && (
                                <button
                                  type="button"
                                  onClick={() => onSelectSession?.(bm.traceId, bm.spanId)}
                                  className="inline-flex items-center gap-1 rounded px-1 transition-colors"
                                  style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
                                  title={`Open span ${bm.spanId} inside session ${bm.traceId}`}
                                >
                                  <ExternalLink className="w-3 h-3" aria-hidden="true" />
                                  <span className="cs-mono">{bm.traceId.slice(0, 12)}…</span>
                                </button>
                              )}
                              <span
                                className="cs-mono"
                                style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
                              >
                                {formatTime(bm.createdAt)}
                              </span>
                            </div>

                            {/* The note is the only human sentence in the row,
                                so it is the only thing allowed to reflow. */}
                            {editing ? (
                              <div className="mt-1.5 flex items-center gap-1">
                                <input
                                  autoFocus
                                  value={editNote}
                                  onChange={e => setEditNote(e.target.value)}
                                  onKeyDown={e => {
                                    e.stopPropagation();
                                    if (e.key === 'Enter')  saveEdit(bm.id);
                                    if (e.key === 'Escape') cancelEdit();
                                  }}
                                  placeholder="Why did you keep this?"
                                  aria-label="Bookmark note"
                                  className="flex-1 rounded-md px-2 py-1 outline-2"
                                  style={{
                                    background: 'var(--cs-bg-raised)',
                                    color: 'var(--cs-text-body)',
                                    fontSize: 'var(--cs-text-sm)',
                                    outlineColor: 'var(--cs-accent)',
                                  }}
                                />
                                <IconButton
                                  onClick={() => saveEdit(bm.id)}
                                  title="Save note (Enter)"
                                  aria-label="Save note"
                                  style={{ color: 'var(--cs-accent)' }}
                                >
                                  <Check className="w-3.5 h-3.5" aria-hidden="true" />
                                </IconButton>
                                <IconButton onClick={cancelEdit} title="Cancel (Esc)" aria-label="Cancel editing">
                                  <X className="w-3.5 h-3.5" aria-hidden="true" />
                                </IconButton>
                              </div>
                            ) : (
                              <p
                                onClick={() => startEdit(bm)}
                                title="Click to edit this note"
                                className="mt-0.5 cursor-text"
                                style={{
                                  color: bm.note ? 'var(--cs-text-muted)' : 'var(--cs-text-faint)',
                                  fontSize: 'var(--cs-text-sm)',
                                  lineHeight: 'var(--cs-leading-normal)',
                                  fontStyle: bm.note ? undefined : 'italic',
                                }}
                              >
                                {bm.note || 'Add a note…'}
                              </p>
                            )}
                          </div>

                          <div className="flex items-center gap-0.5 shrink-0">
                            <IconButton
                              onClick={() => startEdit(bm)}
                              title="Edit the note"
                              aria-label="Edit the note"
                            >
                              <Edit2 className="w-3 h-3" aria-hidden="true" />
                            </IconButton>
                            <IconButton
                              danger
                              onClick={() => deleteBookmark(bm.id)}
                              title="Delete this bookmark"
                              aria-label="Delete this bookmark"
                            >
                              <Trash2 className="w-3 h-3" aria-hidden="true" />
                            </IconButton>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
