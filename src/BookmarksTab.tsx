import React, { useEffect, useState } from 'react';
import { Bookmark, Trash2, ExternalLink, Edit2, Check, X } from 'lucide-react';
import { socket } from './socket';

interface BookmarkRow {
  id: number;
  spanId: string;
  traceId: string;
  note: string;
  createdAt: string;
}

export function BookmarksTab({
  onSelectSession,
}: {
  onSelectSession?: (traceId: string) => void;
}) {
  const [bookmarks,    setBookmarks]    = useState<BookmarkRow[]>([]);
  const [editingId,    setEditingId]    = useState<number | null>(null);
  const [editNote,     setEditNote]     = useState('');
  const [sessionFilter, setSessionFilter] = useState('');

  const fetchBookmarks = (filter = sessionFilter) => {
    const params = new URLSearchParams();
    if (filter) params.set('session', filter);
    fetch(`/api/bookmarks?${params}`)
      .then(r => r.json())
      .then((data: { bookmarks?: BookmarkRow[] } | BookmarkRow[]) => {
        const rows = Array.isArray(data) ? data : (data.bookmarks ?? []);
        setBookmarks(rows);
      })
      .catch(() => {});
  };

  useEffect(() => { fetchBookmarks(); }, []);
  useEffect(() => { fetchBookmarks(sessionFilter); }, [sessionFilter]);

  useEffect(() => {
    const handler = () => fetchBookmarks(sessionFilter);
    socket.on('bookmarks-update', handler);
    return () => { socket.off('bookmarks-update', handler); };
  }, [sessionFilter]);

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

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ background: 'var(--cs-bg-primary)' }}>

      {/* Toolbar */}
      <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-800 bg-slate-900/40 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <Bookmark className="w-4 h-4 text-yellow-400" />
          <span className="text-sm font-bold text-slate-200">Bookmarks</span>
          <span className="text-[11px] font-mono text-slate-500">{bookmarks.length} saved</span>
        </div>

        {/* Session filter */}
        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter by session trace ID…"
            value={sessionFilter}
            onChange={e => setSessionFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 w-60"
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-5">
        {bookmarks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 gap-3">
            <Bookmark className="w-8 h-8 text-slate-700" />
            <p className="text-sm font-medium text-slate-500">No bookmarks yet</p>
            <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
              Bookmark any span from the graph view to save it here for quick reference.
            </p>
          </div>
        ) : (
          <div className="space-y-2 max-w-3xl">
            {bookmarks.map(bm => (
              <div
                key={bm.id}
                className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 flex items-start gap-3 group hover:border-slate-700 transition-colors"
              >
                {/* Bookmark icon */}
                <Bookmark className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-[11px] font-mono break-all" style={{ color: '#00d4aa' }}>
                      {bm.spanId}
                    </code>
                    {bm.traceId && (
                      <button
                        onClick={() => onSelectSession?.(bm.traceId)}
                        className="flex items-center gap-1 text-xs text-slate-500 hover:text-blue-400 transition-colors"
                        title="Jump to session"
                      >
                        <ExternalLink className="w-3 h-3" />
                        <span className="font-mono truncate max-w-[120px]">{bm.traceId.slice(0, 12)}…</span>
                      </button>
                    )}
                    <span className="text-xs text-slate-600">{formatTime(bm.createdAt)}</span>
                  </div>

                  {/* Note editing */}
                  {editingId === bm.id ? (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        autoFocus
                        value={editNote}
                        onChange={e => setEditNote(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') saveEdit(bm.id); if (e.key === 'Escape') cancelEdit(); }}
                        className="flex-1 px-2 py-1 bg-slate-800 border border-blue-700/50 rounded text-xs text-slate-200 focus:outline-none"
                        placeholder="Add a note…"
                      />
                      <button onClick={() => saveEdit(bm.id)} className="p-1 text-green-400 hover:text-green-300 transition-colors">
                        <Check className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={cancelEdit} className="p-1 text-slate-500 hover:text-slate-300 transition-colors">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ) : (
                    <p
                      className={`mt-1 text-xs cursor-pointer ${
                        bm.note ? 'text-slate-400 hover:text-slate-200' : 'text-slate-700 hover:text-slate-500'
                      } transition-colors`}
                      onClick={() => startEdit(bm)}
                      title="Click to edit note"
                    >
                      {bm.note || 'Click to add a note…'}
                    </p>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  <button
                    onClick={() => startEdit(bm)}
                    className="p-1.5 text-slate-500 hover:text-slate-200 hover:bg-slate-700 rounded transition-colors"
                    title="Edit note"
                  >
                    <Edit2 className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => deleteBookmark(bm.id)}
                    className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-900/30 rounded transition-colors"
                    title="Delete bookmark"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
