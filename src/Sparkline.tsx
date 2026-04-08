/**
 * ActivitySparkline — real-time mini chart showing spans/min and tokens/min
 * over the last 60 seconds, rendered as an inline SVG (no extra chart library).
 */
import React, { useEffect, useState, useCallback } from 'react';
import { socket } from './socket';

interface ActivityBucket {
  ts: number;
  spans: number;
  tokensIn: number;
  tokensOut: number;
}

const W = 120;
const H = 28;
const BUCKETS = 60;

function buildPath(values: number[], maxVal: number): string {
  if (values.length === 0 || maxVal === 0) return '';
  const step = W / (values.length - 1 || 1);
  return values
    .map((v, i) => {
      const x = i * step;
      const y = H - (v / maxVal) * (H - 2) - 1;
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

export function ActivitySparkline() {
  const [buckets, setBuckets] = useState<ActivityBucket[]>([]);

  const fetchActivity = useCallback(() => {
    fetch('/api/activity')
      .then(r => r.json())
      .then(({ buckets: b }: { buckets: ActivityBucket[] }) => setBuckets(b ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchActivity();
    socket.on('graph-update', fetchActivity);
    return () => { socket.off('graph-update', fetchActivity); };
  }, [fetchActivity]);

  const spanValues  = buckets.map(b => b.spans);
  const tokenValues = buckets.map(b => b.tokensIn + b.tokensOut);

  const maxSpans  = Math.max(1, ...spanValues);
  const maxTokens = Math.max(1, ...tokenValues);

  const totalSpansLastMin  = spanValues.reduce((s, v) => s + v, 0);
  const totalTokensLastMin = tokenValues.reduce((s, v) => s + v, 0);

  const spansPath  = buildPath(spanValues,  maxSpans);
  const tokensPath = buildPath(tokenValues, maxTokens);

  return (
    <div className="flex items-center gap-3">
      {/* Spans sparkline */}
      <div className="flex items-center gap-1.5">
        <svg width={W} height={H} className="overflow-visible">
          {/* Background grid */}
          <line x1={0} y1={H - 1} x2={W} y2={H - 1} stroke="#334155" strokeWidth={1} />
          {spansPath && (
            <>
              <defs>
                <linearGradient id="spGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path
                d={`${spansPath} L${W},${H} L0,${H} Z`}
                fill="url(#spGrad)"
              />
              <path d={spansPath} stroke="#3b82f6" strokeWidth={1.5} fill="none" strokeLinejoin="round" />
            </>
          )}
        </svg>
        <div className="text-right">
          <div className="text-xs font-bold text-blue-400 leading-none">{totalSpansLastMin}</div>
          <div className="text-[11px] text-slate-500 leading-none mt-0.5">spans/min</div>
        </div>
      </div>

      <div className="w-px h-5 bg-slate-700" />

      {/* Tokens sparkline */}
      <div className="flex items-center gap-1.5">
        <svg width={W} height={H} className="overflow-visible">
          <line x1={0} y1={H - 1} x2={W} y2={H - 1} stroke="#334155" strokeWidth={1} />
          {tokensPath && (
            <>
              <defs>
                <linearGradient id="tkGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a855f7" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path
                d={`${tokensPath} L${W},${H} L0,${H} Z`}
                fill="url(#tkGrad)"
              />
              <path d={tokensPath} stroke="#a855f7" strokeWidth={1.5} fill="none" strokeLinejoin="round" />
            </>
          )}
        </svg>
        <div className="text-right">
          <div className="text-xs font-bold text-purple-400 leading-none">
            {totalTokensLastMin > 999 ? `${(totalTokensLastMin / 1000).toFixed(1)}k` : totalTokensLastMin}
          </div>
          <div className="text-[11px] text-slate-500 leading-none mt-0.5">tokens/min</div>
        </div>
      </div>
    </div>
  );
}
