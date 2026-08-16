import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Bookmark, PanelRightClose, PanelRightOpen, Plus, X } from 'lucide-react';
import type { Severity } from '../shared/types';
import { SEVERITY_LABEL } from '../dashboardTypes';
import { formatSpanName } from '../lib/format';
import { apiSend, reportApiFailure } from '../lib/api';
import { SpanAttributes } from '../SpanAttributes';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '../components/ui/sheet';

export interface DetailTarget {
  spanId: string;
  traceId: string;
  label: string;
  severity: Severity;
  reason: string;
  attributes: Record<string, unknown>;
}

interface Annotation { id: number; spanId: string; text: string; author: string; createdAt: string }

/** Same shape as `claudesec.railCollapsed`: the string 'true' means collapsed. */
const DETAIL_KEY = 'claudesec.detailCollapsed';

/**
 * The collapsed column keeps a 36px strip rather than vanishing. A pane that
 * disappears completely is a pane nobody finds again, and 36px is a comfortable
 * hit target that still returns ~90% of the column to the table.
 */
const EDGE_W = '2.25rem';

/**
 * `null` means "follow the selection" — the state a fresh install starts in.
 * `true`/`false` only exist once I have explicitly collapsed or expanded the
 * pane myself, which is what makes the preference worth persisting.
 */
type CollapsePref = boolean | null;

function readPref(): CollapsePref {
  try {
    const stored = localStorage.getItem(DETAIL_KEY);
    if (stored === 'true') return true;
    if (stored === 'false') return false;
  } catch { /* private mode */ }
  return null;
}

/**
 * Zone three: span detail.
 *
 * Below 1920 there is not enough width for a third persistent column without
 * squeezing the table under the ~12 rows a 1366×768 laptop can show, so detail
 * arrives as an overlay sheet and gives the width back the moment it closes. At
 * 1920 and up it becomes a real column — but only when it has something to say.
 *
 * The collapse rule, in precedence order:
 *
 *   1. An explicit choice of mine wins, and keeps winning across reloads. If I
 *      collapsed the pane to read a wide table, the next row I click must not
 *      shove it back open — that would make the button feel broken and would
 *      fight me on every selection. The collapsed strip tints itself with the
 *      selected span's severity instead, so the information is signalled
 *      without stealing the width back.
 *   2. With no explicit choice, the selection drives it: something selected
 *      opens the pane, nothing selected collapses it. An empty pane parking
 *      360px of placeholder prose on a 1920 screen is pure waste.
 *
 * Closing with the header ✕ clears the selection *and* drops back to (2), since
 * "close" reads as dismiss, not as "never show me this again".
 */
export function DetailPane({ target, persistent, onClose }: {
  target: DetailTarget | null;
  persistent: boolean;
  onClose: () => void;
}) {
  const [pref, setPref] = useState<CollapsePref>(readPref);
  const open = pref === null ? !!target : !pref;

  const paneRef = useRef<HTMLDivElement>(null);
  const railRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  // Only a deliberate toggle (button or shortcut) moves focus. Opening because a
  // table row was clicked must leave the caret in the table, or arrow-key
  // triage would break on every selection.
  const deliberateRef = useRef(false);
  const openRef = useRef(open);
  openRef.current = open;

  useEffect(() => {
    try {
      if (pref === null) localStorage.removeItem(DETAIL_KEY);
      else localStorage.setItem(DETAIL_KEY, String(pref));
    } catch { /* ignore */ }
  }, [pref]);

  const toggle = useCallback(() => {
    deliberateRef.current = true;
    setPref(openRef.current);
  }, []);

  /** ✕ dismisses the whole thing: drop the selection and the manual override. */
  const dismiss = useCallback(() => {
    // Nothing to hand focus back to if the pane was already collapsed.
    deliberateRef.current = openRef.current;
    setPref(null);
    onClose();
  }, [onClose]);

  // ⌘] / Ctrl+] — the ⌘K palette and ⌘B rail already own their letters, and the
  // bracket pair is the established "toggle a side panel" key in editors.
  useEffect(() => {
    if (!persistent) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === ']') {
        e.preventDefault();
        toggle();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [persistent, toggle]);

  useEffect(() => {
    if (!persistent || !deliberateRef.current) { deliberateRef.current = false; return; }
    deliberateRef.current = false;
    if (open) {
      restoreFocusRef.current = document.activeElement as HTMLElement | null;
      paneRef.current?.focus();
    } else {
      // Back where I came from, or onto the strip that replaced the pane — never
      // dropped on <body>, which would restart tabbing from the top of the page.
      const back = restoreFocusRef.current;
      restoreFocusRef.current = null;
      if (back && document.contains(back)) back.focus();
      else railRef.current?.focus();
    }
  }, [open, persistent]);

  if (persistent) {
    return (
      <aside
        className="relative hidden shrink-0 overflow-hidden 3xl:block motion-reduce:transition-none"
        style={{
          width: open ? 'var(--cs-detail-w)' : EDGE_W,
          transition: 'width var(--cs-motion-base) var(--cs-ease-in-out)',
          borderLeft: '1px solid var(--cs-rule)',
          background: 'var(--cs-bg-surface)',
        }}
        aria-label="Span detail"
      >
        {/* Held at full width and clipped by the aside so the body wipes in and
            out instead of reflowing its attribute table on every frame. */}
        <div
          id="cs-detail-pane"
          ref={paneRef}
          tabIndex={-1}
          inert={!open}
          onKeyDown={e => { if (e.key === 'Escape') { e.stopPropagation(); toggle(); } }}
          className="absolute inset-y-0 left-0 w-(--cs-detail-w) overflow-y-auto outline-none motion-reduce:transition-none"
          style={{
            opacity: open ? 1 : 0,
            transition: 'opacity var(--cs-motion-fast) var(--cs-ease-out)',
          }}
        >
          {target
            ? <DetailBody target={target} onClose={dismiss} onCollapse={toggle} />
            : (
              // The empty pane carries its own collapse control. Only DetailBody
              // renders the header buttons, so without this a pane expanded with
              // nothing selected had no way back — the placeholder was a dead end
              // holding 400px hostage.
              <>
                <header
                  className="flex items-center justify-end gap-1 px-2 py-1.5"
                  style={{ borderBottom: '1px solid var(--cs-rule)' }}
                >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    onClick={toggle}
                    aria-label="Collapse detail pane"
                    title="Collapse detail pane (⌘])"
                  >
                    <PanelRightClose />
                  </Button>
                </header>
                <p className="p-4 text-[11px] leading-relaxed" style={{ color: 'var(--cs-text-faint)' }}>
                  Select a span to inspect its attributes, notes and tags here.
                </p>
              </>
            )}
        </div>

        <button
          ref={railRef}
          type="button"
          onClick={toggle}
          tabIndex={open ? -1 : 0}
          aria-expanded={open}
          aria-controls="cs-detail-pane"
          aria-label="Show span detail"
          title="Show span detail (⌘])"
          className="absolute inset-y-0 left-0 flex w-9 cursor-pointer flex-col items-center gap-2 pt-3 motion-reduce:transition-none"
          style={{
            background: 'var(--cs-bg-surface)',
            color: 'var(--cs-text-faint)',
            opacity: open ? 0 : 1,
            pointerEvents: open ? 'none' : 'auto',
            transition: 'opacity var(--cs-motion-fast) var(--cs-ease-out)',
          }}
        >
          <PanelRightOpen className="size-3.5 shrink-0" />
          {/* A selection I chose to keep hidden still gets signalled, so the
              strip never looks like an empty decoration. */}
          {target && (
            <span
              className="size-1.5 shrink-0 rounded-full"
              style={{ background: `var(--cs-sev-${target.severity})` }}
            />
          )}
          <span
            className="text-[10px] font-semibold uppercase tracking-wider"
            style={{ writingMode: 'vertical-rl' }}
          >
            Detail
          </span>
        </button>
      </aside>
    );
  }

  return (
    <Sheet open={!!target} onOpenChange={open => { if (!open) onClose(); }}>
      {/* `!` because SheetContent's own `data-[side=right]:sm:max-w-sm` would
          otherwise pin every right-hand sheet to 384px, which is too narrow to
          read a span's attribute table without wrapping every value. */}
      <SheetContent side="right" className="w-[min(80vw,40rem)]! max-w-none! gap-0 p-0">
        <SheetHeader className="sr-only">
          <SheetTitle>Span detail</SheetTitle>
          <SheetDescription>Attributes, notes and tags for the selected span.</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto">
          {target && <DetailBody target={target} onClose={onClose} />}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function DetailBody({ target, onClose, onCollapse }: {
  target: DetailTarget;
  onClose: () => void;
  /** Only the persistent column can collapse; the sheet just closes. */
  onCollapse?: () => void;
}) {
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [annotationText, setAnnotationText] = useState('');
  const [saving, setSaving] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [bookmarked, setBookmarked] = useState(false);

  const { spanId, traceId } = target;

  useEffect(() => {
    const id = encodeURIComponent(spanId);
    setAnnotationText('');
    setTagInput('');
    fetch(`/api/spans/${id}/annotations`).then(r => r.json())
      .then(({ annotations: a }) => setAnnotations(a ?? [])).catch(() => {});
    fetch(`/api/spans/${id}/tags`).then(r => r.json())
      .then(({ tags: t }: { tags: string[] }) => setTags(t ?? [])).catch(() => {});
    fetch(`/api/bookmarks?session=${encodeURIComponent(traceId)}`).then(r => r.json())
      .then(({ bookmarks }: { bookmarks: { spanId: string }[] }) =>
        setBookmarked((bookmarks ?? []).some(b => b.spanId === spanId)))
      .catch(() => {});
  }, [spanId, traceId]);

  // The star follows the server, not the click: a refused save used to leave a
  // filled star for a bookmark that was never stored.
  const toggleBookmark = async () => {
    const next = !bookmarked;
    try {
      if (next) await apiSend('/api/bookmarks', 'POST', { spanId, traceId });
      else await apiSend(`/api/bookmarks/span/${encodeURIComponent(spanId)}`, 'DELETE');
      setBookmarked(next);
    } catch (err: unknown) {
      reportApiFailure(err, next ? 'Failed to save bookmark' : 'Failed to remove bookmark');
    }
  };

  const addAnnotation = async () => {
    const text = annotationText.trim();
    if (!text) return;
    setSaving(true);
    try {
      // The route replies with the stored row itself, not a wrapper.
      const row = await apiSend<Annotation>(
        `/api/spans/${encodeURIComponent(spanId)}/annotations`, 'POST', { text },
      );
      if (row?.id) setAnnotations(prev => [...prev, row]);
      setAnnotationText('');
    } catch (err: unknown) {
      // Leave the text in place so the note is not lost, and say why it did
      // not save — silently clearing the box was the worst of both.
      reportApiFailure(err, 'Failed to save annotation');
    }
    setSaving(false);
  };

  const addTag = async () => {
    const tag = tagInput.trim();
    if (!tag) return;
    // The server normalises the tag (lowercase, restricted charset), so take the
    // stored value back rather than showing what was typed.
    try {
      const { tag: stored } = await apiSend<{ tag?: string }>(
        `/api/spans/${encodeURIComponent(spanId)}/tags`, 'POST', { tag },
      );
      if (stored) setTags(prev => (prev.includes(stored) ? prev : [...prev, stored]));
      setTagInput('');
    } catch (err: unknown) {
      reportApiFailure(err, 'Failed to add tag');
    }
  };

  return (
    <div className="flex flex-col">
      <header
        className="sticky top-0 z-10 flex items-start gap-2 px-3 py-2.5"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        <span className="mt-0.5 h-8 w-[3px] shrink-0 rounded-full" style={{ background: `var(--cs-sev-${target.severity})` }} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-[15px] font-semibold" style={{ color: 'var(--cs-text-strong)' }}>
            {formatSpanName(target.label)}
          </p>
          <p className="truncate font-mono text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>{spanId}</p>
        </div>
        {onCollapse && (
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onCollapse}
            aria-label="Collapse detail pane"
            title="Collapse detail pane (⌘])"
          >
            <PanelRightClose />
          </Button>
        )}
        <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label="Close detail">
          <X />
        </Button>
      </header>

      <div className="space-y-4 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant="secondary" style={{ color: `var(--cs-sev-${target.severity}-fg)`, background: `var(--cs-sev-${target.severity}-bg)` }}>
            {SEVERITY_LABEL[target.severity]}
          </Badge>
          <Button variant="ghost" size="xs" onClick={toggleBookmark}
            style={{ color: bookmarked ? 'var(--cs-accent)' : undefined }}>
            <Bookmark className="size-3" fill={bookmarked ? 'currentColor' : 'none'} />
            {bookmarked ? 'Bookmarked' : 'Bookmark'}
          </Button>
        </div>

        {target.reason && target.reason !== '—' && (
          <p className="text-xs leading-relaxed" style={{ color: 'var(--cs-text-muted)' }}>{target.reason}</p>
        )}

        <Section title="Attributes">
          <SpanAttributes attrs={target.attributes} />
        </Section>

        <Section title="Tags">
          <div className="flex flex-wrap items-center gap-1.5">
            {tags.map(tag => <Badge key={tag} variant="outline">{tag}</Badge>)}
            <form className="flex items-center gap-1" onSubmit={e => { e.preventDefault(); addTag(); }}>
              <Input
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                placeholder="Add tag"
                aria-label="Add tag"
                className="h-6 w-24 text-xs"
              />
              <Button type="submit" variant="ghost" size="icon-xs" aria-label="Add tag"><Plus /></Button>
            </form>
          </div>
        </Section>

        <Section title="Notes">
          <ul className="mb-2 space-y-1.5">
            {annotations.map(a => (
              <li key={a.id} className="rounded-md p-2 text-xs" style={{ background: 'var(--cs-bg-sunken)', color: 'var(--cs-text-muted)' }}>
                {a.text}
                <span className="mt-0.5 block font-mono text-[10px]" style={{ color: 'var(--cs-text-faint)' }}>
                  {a.author} · {a.createdAt}
                </span>
              </li>
            ))}
          </ul>
          <form className="flex items-start gap-1.5" onSubmit={e => { e.preventDefault(); addAnnotation(); }}>
            <Input
              value={annotationText}
              onChange={e => setAnnotationText(e.target.value)}
              placeholder="Add a note…"
              aria-label="Add a note"
              className="h-7 text-xs"
            />
            <Button type="submit" size="sm" disabled={saving || !annotationText.trim()}>Save</Button>
          </form>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>{title}</h3>
      {children}
    </section>
  );
}
