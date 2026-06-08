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
