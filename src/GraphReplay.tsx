/**
 * GraphReplay — animates spans appearing in chronological order on the graph.
 * Renders as a Panel inside ReactFlow. Controlled entirely by App.tsx via props.
 */
import React, { useEffect, useRef, useCallback } from 'react';
import { Panel } from '@xyflow/react';
import { Play, Pause, SkipBack, X } from 'lucide-react';

export interface ReplayState {
  active: boolean;
  playing: boolean;
  speed: 1 | 2 | 5;
  progress: number;   // 0..1
  currentStep: number;
  totalSteps: number;
}

interface Props {
  replay: ReplayState;
  onPlay:     () => void;
  onPause:    () => void;
  onRestart:  () => void;
  onStop:     () => void;
  onSetSpeed: (s: 1 | 2 | 5) => void;
  onScrub:    (frac: number) => void;
}

export function GraphReplay({ replay, onPlay, onPause, onRestart, onStop, onSetSpeed, onScrub }: Props) {
  if (!replay.active) return null;

  const barRef = useRef<HTMLDivElement>(null);

  const handleBarClick = useCallback((e: React.MouseEvent) => {
    if (!barRef.current) return;
    const rect = barRef.current.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    onScrub(frac);
  }, [onScrub]);

  const pct = Math.round(replay.progress * 100);

  return (
    <Panel position="bottom-center" className="z-30 mb-4">
      <div className="bg-slate-900/95 backdrop-blur-md border border-slate-700 rounded-2xl shadow-2xl px-4 py-3 flex flex-col gap-2 min-w-[340px]">
        {/* Title row */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
            <span className="text-xs font-bold text-slate-200">Replay Mode</span>
            <span className="text-[10px] text-slate-500 font-mono">
              {replay.currentStep} / {replay.totalSteps} spans
            </span>
          </div>
          <button onClick={onStop} className="p-0.5 rounded hover:bg-slate-700 text-slate-500 hover:text-slate-300">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Scrubber */}
        <div
          ref={barRef}
          className="relative h-2 bg-slate-800 rounded-full cursor-pointer"
          onClick={handleBarClick}
        >
          <div
            className="absolute inset-y-0 left-0 bg-blue-500 rounded-full transition-all"
            style={{ width: `${pct}%` }}
          />
          <div
            className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-white shadow border border-blue-400"
            style={{ left: `${pct}%` }}
          />
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1">
            <button
              onClick={onRestart}
              className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
              title="Restart"
            >
              <SkipBack className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={replay.playing ? onPause : onPlay}
              className="p-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
              title={replay.playing ? 'Pause' : 'Play'}
            >
              {replay.playing
                ? <Pause className="w-3.5 h-3.5" />
                : <Play  className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Speed selector */}
          <div className="flex gap-1">
            {([1, 2, 5] as const).map(s => (
              <button
                key={s}
                onClick={() => onSetSpeed(s)}
                className={`px-2 py-0.5 rounded text-[11px] font-bold transition-colors ${
                  replay.speed === s
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-500 hover:text-slate-300 border border-slate-700'
                }`}
              >
                {s}×
              </button>
            ))}
          </div>

          <span className="text-[10px] text-slate-500 font-mono w-8 text-right">{pct}%</span>
        </div>
      </div>
    </Panel>
  );
}
