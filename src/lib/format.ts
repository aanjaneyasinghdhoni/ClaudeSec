// ---------------------------------------------------------------------------
// Pure formatters
// ---------------------------------------------------------------------------

export function toMs(nano: string): number {
  try { return Number(BigInt(nano) / 1_000_000n); }
  catch { return 0; }
}

export function formatDuration(startNano: string, endNano: string): string {
  try {
    const ms = Number((BigInt(endNano) - BigInt(startNano)) / 1_000_000n);
    if (ms < 0)       return '—';
    if (ms < 1000)    return `${ms}ms`;
    if (ms < 60_000)  return `${(ms / 1000).toFixed(2)}s`;
    return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  } catch { return '—'; }
}

export function formatSpanName(raw: string): string {
  if (raw === 'tool_call/unknown') return 'Tool Call';
  if (raw.startsWith('tool_call/')) return raw.slice('tool_call/'.length);
  if (raw.startsWith('process/')) return raw;
  return raw;
}

// Compact token counts (e.g. 140,839,947 → "140.84M") so large numbers stay
// readable. Keep the exact value in a `title` tooltip at the call site.
export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}
