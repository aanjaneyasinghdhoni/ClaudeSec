/**
 * GraphSearch — floating in-graph search overlay (Ctrl/Cmd+F to open)
 * Renders inside a ReactFlow <Panel> so it has access to useReactFlow().
 * Props are controlled from App.tsx.
 */
import React, { useEffect, useRef, useCallback } from 'react';
import { useReactFlow, Panel } from '@xyflow/react';
import { Search, X, ChevronUp, ChevronDown } from 'lucide-react';

export interface GraphSearchProps {
  query: string;
  setQuery: (q: string) => void;
  open: boolean;
  setOpen: (o: boolean) => void;
  matchIds: string[];
  matchIndex: number;
  setMatchIndex: (i: number) => void;
}

export function GraphSearch({
  query, setQuery, open, setOpen,
  matchIds, matchIndex, setMatchIndex,
}: GraphSearchProps) {
  const { fitView } = useReactFlow();
  const inputRef    = useRef<HTMLInputElement>(null);

  // Focus input when panel opens
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  // Center on current match
  useEffect(() => {
    if (matchIds.length > 0 && matchIds[matchIndex]) {
      fitView({ nodes: [{ id: matchIds[matchIndex] }], duration: 300, padding: 0.5, maxZoom: 1.5 });
    }
  }, [matchIndex, matchIds, fitView]);

  const goNext = useCallback(() => {
    if (matchIds.length === 0) return;
    setMatchIndex((matchIndex + 1) % matchIds.length);
  }, [matchIds.length, matchIndex, setMatchIndex]);

  const goPrev = useCallback(() => {
    if (matchIds.length === 0) return;
    setMatchIndex((matchIndex - 1 + matchIds.length) % matchIds.length);
  }, [matchIds.length, matchIndex, setMatchIndex]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { setOpen(false); setQuery(''); }
    if (e.key === 'Enter') {
      if (e.shiftKey) goPrev(); else goNext();
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); goNext(); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); goPrev(); }
  };

  if (!open) return null;

  return (
    <Panel position="top-left" className="z-30" style={{ marginTop: 8, marginLeft: 8 }}>
      <div className="bg-slate-900/95 backdrop-blur-md border border-slate-700 rounded-xl shadow-2xl p-2 flex items-center gap-1.5 min-w-[260px]">
        <Search className="w-3.5 h-3.5 text-slate-500 shrink-0 ml-1" />
        <input
          ref={inputRef}
          value={query}
          onChange={e => { setQuery(e.target.value); setMatchIndex(0); }}
          onKeyDown={handleKey}
          placeholder="Search nodes… (Enter to cycle)"
          className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-600 outline-none min-w-0"
        />
        {query && (
          <span className="text-[10px] text-slate-500 shrink-0 font-mono">
            {matchIds.length > 0 ? `${matchIndex + 1}/${matchIds.length}` : '0'}
          </span>
        )}
        <div className="flex gap-0.5">
          <button
            onClick={goPrev}
            disabled={matchIds.length === 0}
            className="p-0.5 rounded hover:bg-slate-700 text-slate-500 disabled:opacity-30"
            title="Previous (Shift+Enter)"
          >
            <ChevronUp className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={goNext}
            disabled={matchIds.length === 0}
            className="p-0.5 rounded hover:bg-slate-700 text-slate-500 disabled:opacity-30"
            title="Next (Enter)"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => { setOpen(false); setQuery(''); }}
            className="p-0.5 rounded hover:bg-slate-700 text-slate-500"
            title="Close (Esc)"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </Panel>
  );
}
