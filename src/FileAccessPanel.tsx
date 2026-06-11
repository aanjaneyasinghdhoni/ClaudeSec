import React, { useEffect, useMemo, useRef, useState } from 'react';
import { FileText, AlertTriangle, Eye, Edit2, Folder, FolderOpen, GitBranch, List, FolderTree } from 'lucide-react';
import { useListControls, FilterBar, ListFooter, ServerLoadFooter, type FacetConfig } from './FilterControls';
import { SpanSearchDrawer, type SpanSearchTarget } from './SpanSearchDrawer';

interface FileEntry {
  path:      string;
  reads:     number;
  writes:    number;
  total:     number;
  agents:    string[];
  threats:   number;
  sensitive: boolean;
  folder?:   string;
  branch?:   string;
}

interface FolderGroup {
  folder:    string;
  branch:    string;
  files:     FileEntry[];
  fileCount: number;
  reads:     number;
  writes:    number;
  total:     number;
  threats:   number;
  sensitive: number;
  agents:    string[];
}

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

// Per-section row cap before a "show more" appears (keeps a huge repo section
// from rendering thousands of rows at once).
const SECTION_PAGE = 200;

const fileSearchText = (f: FileEntry) => f.path;

const FILE_FACETS: FacetConfig<FileEntry>[] = [
  {
    key: 'type',
    label: 'Files',
    accessor: f => (f.sensitive ? 'sensitive' : 'normal'),
    options: [
      { value: 'sensitive', label: 'Sensitive' },
      { value: 'normal',    label: 'Normal' },
    ],
  },
];

// Trim a long absolute path to its trailing segments for a readable section header.
function shortFolder(folder: string): string {
  if (folder === '(unknown)' || !folder) return '(unknown)';
  const parts = folder.replace(/\/+$/, '').split('/').filter(Boolean);
  if (parts.length <= 2) return folder;
  return '…/' + parts.slice(-2).join('/');
}

// ── A single file row (shared between flat and grouped views) ────────────────
function FileRow({
  f, maxAccess, onOpen,
}: {
  f: FileEntry;
  maxAccess: number;
  onOpen: (f: FileEntry) => void;
}) {
  const pct = Math.round((f.total / maxAccess) * 100);
  return (
    <button
      type="button"
      onClick={() => onOpen(f)}
      className={`w-full text-left relative bg-slate-900 border rounded-lg px-3 py-2 overflow-hidden hover:border-slate-600 transition-colors cursor-pointer ${
        f.sensitive ? 'border-red-700/40' : 'border-slate-800'
      }`}
      title="View spans that touched this file"
    >
      {/* Heat bar background */}
      <div
        className="absolute inset-y-0 left-0 opacity-10"
        style={{ width: `${pct}%`, background: f.sensitive ? '#ef4444' : f.threats > 0 ? '#f97316' : '#3b82f6' }}
      />

      <div className="relative flex items-center gap-3">
        {/* File path */}
        <code className="text-[11px] font-mono text-slate-300 flex-1 truncate" title={f.path}>
          {f.sensitive && <AlertTriangle className="w-3 h-3 text-red-400 inline mr-1" />}
          {f.path}
        </code>

        {/* Read/Write counts */}
        <div className="flex items-center gap-3 shrink-0">
          <span className="flex items-center gap-1 text-xs text-green-400 font-mono">
            <Eye className="w-3 h-3" /> {f.reads}
          </span>
          <span className="flex items-center gap-1 text-xs text-orange-400 font-mono">
            <Edit2 className="w-3 h-3" /> {f.writes}
          </span>
        </div>

        {/* Agent dots */}
        <div className="flex items-center gap-1 shrink-0">
          {f.agents.map(a => (
            <span
              key={a}
              className="w-2 h-2 rounded-full"
              style={{ background: HARNESS_COLORS[a] ?? '#64748b' }}
              title={a}
            />
          ))}
        </div>

        {/* Threat badge */}
        {f.threats > 0 && (
          <span className="px-1.5 py-0.5 bg-red-900/40 text-red-300 text-[11px] font-bold rounded shrink-0">
            {f.threats} threat{f.threats > 1 ? 's' : ''}
          </span>
        )}
      </div>
    </button>
  );
}

// ── A collapsible folder/repo section ────────────────────────────────────────
function FolderSection({
  group, onOpen,
}: {
  group: FolderGroup;
  onOpen: (f: FileEntry) => void;
}) {
  const [open, setOpen] = useState(false); // collapsed by default
  const [count, setCount] = useState(SECTION_PAGE);
  const maxAccess = useMemo(() => Math.max(...group.files.map(x => x.total), 1), [group.files]);
  const shown = group.files.slice(0, count);

  return (
    <div className="border border-slate-800 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 bg-slate-800/40 hover:bg-slate-800/70 transition-colors text-left"
      >
        {open
          ? <FolderOpen className="w-4 h-4 text-slate-400 shrink-0" />
          : <Folder className="w-4 h-4 text-slate-500 shrink-0" />}
        <span className="text-xs font-mono text-slate-200 truncate flex-1" title={group.folder}>
          {shortFolder(group.folder)}
        </span>
        {group.branch && (
          <span className="hidden sm:flex items-center gap-1 text-[11px] text-slate-500 font-mono shrink-0">
            <GitBranch className="w-3 h-3" /> {group.branch}
          </span>
        )}
        <span className="text-[11px] text-slate-500 font-mono shrink-0">{group.fileCount} files</span>
        <span className="flex items-center gap-1 text-[11px] text-green-400 font-mono shrink-0">
          <Eye className="w-3 h-3" /> {group.reads}
        </span>
        <span className="flex items-center gap-1 text-[11px] text-orange-400 font-mono shrink-0">
          <Edit2 className="w-3 h-3" /> {group.writes}
        </span>
        {group.sensitive > 0 && (
          <span className="px-1.5 py-0.5 bg-red-900/30 text-red-400 text-[10px] font-medium rounded shrink-0">
            {group.sensitive} sensitive
          </span>
        )}
        {group.threats > 0 && (
          <span className="px-1.5 py-0.5 bg-red-900/40 text-red-300 text-[10px] font-bold rounded shrink-0">
            {group.threats} threat{group.threats > 1 ? 's' : ''}
          </span>
        )}
      </button>

      {open && (
        <div className="p-2 space-y-1.5 bg-slate-950/30">
          {shown.map(f => (
            <FileRow key={f.path} f={f} maxAccess={maxAccess} onOpen={onOpen} />
          ))}
          {count < group.files.length && (
            <div className="flex items-center justify-center gap-3 py-1.5 text-xs" style={{ color: 'var(--cs-text-faint)' }}>
              <span>Showing {shown.length} of {group.files.length} files</span>
              <button
                type="button"
                onClick={() => setCount(c => c + SECTION_PAGE)}
                className="px-2 py-0.5 rounded transition-colors"
                style={{ background: 'rgba(var(--cs-accent-rgb),0.1)', color: 'var(--cs-accent)' }}
              >
                Show more
              </button>
              <button
                type="button"
                onClick={() => setCount(Infinity)}
                className="px-2 py-0.5 rounded transition-colors"
                style={{ background: 'rgba(var(--cs-accent-rgb),0.1)', color: 'var(--cs-accent)' }}
              >
                Show all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function FileAccessPanel() {
  const [files, setFiles]           = useState<FileEntry[]>([]);
  const [groups, setGroups]         = useState<FolderGroup[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  // Re-entry guard for loadMore. State alone lags a render, so a double-click
  // could start two overlapping page walks; the ref closes that window.
  const loadingRef = useRef(false);
  const [view, setView]             = useState<'flat' | 'folder'>('flat');
  const [drawer, setDrawer]         = useState<SpanSearchTarget | null>(null);

  // Flat view: default limit 500 (the server caps at 5000); reports the true
  // total so we know whether more files exist than we fetched.
  useEffect(() => {
    fetch('/api/file-access?limit=500')
      .then(r => r.json())
      .then(d => { setFiles(d.files ?? []); setTotalCount(d.total ?? 0); })
      .catch(() => {});
  }, []);

  // Walks the server's offset paging so the flat view (and its search/filters)
  // can reach every accessed file, not just the first fetch. Dedupe by path —
  // fresh spans can reshuffle the access-sorted pages between requests.
  const loadMore = async (all: boolean) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoadingMore(true);
    try {
      let next = files;
      for (;;) {
        const r = await fetch(`/api/file-access?limit=2000&offset=${next.length}`);
        const d = await r.json();
        const seen = new Set(next.map(f => f.path));
        const fresh = (d.files ?? []).filter((f: FileEntry) => !seen.has(f.path));
        next = next.concat(fresh);
        setTotalCount(d.total ?? next.length);
        if (!all || fresh.length === 0 || next.length >= (d.total ?? 0)) break;
      }
      setFiles(next);
    } catch {
      // Same policy as the initial fetch: a failed page leaves the list as-is.
    } finally {
      loadingRef.current = false;
      setLoadingMore(false);
    }
  };

  // Grouped view is fetched lazily the first time the user switches to it.
  useEffect(() => {
    if (view !== 'folder' || groups.length > 0) return;
    fetch('/api/file-access?groupBy=folder')
      .then(r => r.json())
      .then(d => { setGroups(d.groups ?? []); })
      .catch(() => {});
  }, [view, groups.length]);

  const { query, setQuery, facetValues, setFacet, visible, total, shown, showMore, showAll } =
    useListControls(files, { searchText: fileSearchText, facets: FILE_FACETS, pageSize: 40 });

  const sensitiveCount = files.filter(f => f.sensitive).length;
  const maxAccess = useMemo(() => Math.max(...files.map(x => x.total), 1), [files]);

  const openDrawer = (f: FileEntry) =>
    setDrawer({ query: f.path, title: f.path, kind: 'File' });

  return (
    <div className="space-y-4 mt-3">
      {/* Summary */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4" style={{ color: 'var(--cs-accent)' }} />
          <span className="text-xs font-bold text-slate-200">File Access</span>
          <span className="text-xs font-mono text-slate-500">{totalCount} files accessed</span>
        </div>
        {sensitiveCount > 0 && (
          <span className="flex items-center gap-1 px-2 py-0.5 bg-red-900/30 border border-red-700/30 rounded-lg text-xs text-red-400 font-medium">
            <AlertTriangle className="w-3 h-3" /> {sensitiveCount} sensitive
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {view === 'flat' && (
            <FilterBar
              query={query}
              setQuery={setQuery}
              facetValues={facetValues}
              setFacet={setFacet}
              facets={FILE_FACETS}
              placeholder="Filter files..."
            />
          )}
          {/* View toggle */}
          <div className="flex items-center bg-slate-800 rounded-lg p-0.5">
            <button
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${view !== 'flat' ? 'text-slate-400 hover:text-slate-200' : ''}`}
              style={view === 'flat' ? { background: 'var(--cs-accent)', color: '#fff' } : undefined}
              onClick={() => setView('flat')}
              title="Flat list"
            >
              <List className="w-3 h-3" /> Flat
            </button>
            <button
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${view !== 'folder' ? 'text-slate-400 hover:text-slate-200' : ''}`}
              style={view === 'folder' ? { background: 'var(--cs-accent)', color: '#fff' } : undefined}
              onClick={() => setView('folder')}
              title="Group by repo / folder"
            >
              <FolderTree className="w-3 h-3" /> By folder
            </button>
          </div>
        </div>
      </div>

      {/* ── Folder / repo grouped view ────────────────────────────────────── */}
      {view === 'folder' ? (
        groups.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            <Folder className="w-6 h-6 text-slate-700" />
            <p className="text-xs text-slate-500">No file access recorded</p>
          </div>
        ) : (
          <div className="space-y-2">
            {groups.map(g => (
              <FolderSection key={g.folder} group={g} onOpen={openDrawer} />
            ))}
          </div>
        )
      ) : /* ── Flat view ──────────────────────────────────────────────────── */
        total === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            <FileText className="w-6 h-6 text-slate-700" />
            <p className="text-xs text-slate-500">{files.length > 0 ? 'No matching files' : 'No file access recorded'}</p>
            <ServerLoadFooter
              loaded={files.length} total={totalCount} loading={loadingMore}
              onLoadMore={() => loadMore(false)} onLoadAll={() => loadMore(true)} noun="files"
            />
          </div>
        ) : (
          <div className="space-y-1.5">
            {visible.map(f => (
              <FileRow key={f.path} f={f} maxAccess={maxAccess} onOpen={openDrawer} />
            ))}
            <ListFooter shown={shown} total={total} showMore={showMore} showAll={showAll} noun="files" />
            {shown >= total && (
              <ServerLoadFooter
                loaded={files.length} total={totalCount} loading={loadingMore}
                onLoadMore={() => loadMore(false)} onLoadAll={() => loadMore(true)} noun="files"
              />
            )}
          </div>
        )}

      <SpanSearchDrawer target={drawer} onClose={() => setDrawer(null)} />
    </div>
  );
}
