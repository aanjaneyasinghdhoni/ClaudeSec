/**
 * SpanAttributes — enriched display of OTel semantic convention attributes.
 * Groups attrs by namespace with icons + human-readable labels.
 * Replaces the raw key→value list in the span detail panel.
 *
 * This is where an operator reads a command, a file path, a token count — the
 * DESIGN.md mono rule ("machine-authored strings you compare or copy") governs
 * every value rendered here. Two truncation layers apply, and they are kept
 * distinct rather than conflated:
 *   - write-time: the server caps an attribute value at 4KiB and appends an
 *     inline marker (see `capSpanAttributes` in server/db.ts). That marker is
 *     rendered honestly, as its own line, never stripped or hidden.
 *   - read-time: a value that fits within the cap can still be large enough to
 *     make a row unreadable, so anything over the UI threshold collapses
 *     behind a "Show full value" toggle rather than being cut off silently.
 */
import React, { useState } from 'react';
import {
  Bot, Globe, Database, FileText, Terminal, Wrench, Package, ShieldAlert,
  ChevronDown, ChevronRight, Copy, Check,
} from 'lucide-react';

type AttrMap = Record<string, unknown>;

// ── Semantic group definitions ──────────────────────────────────────────────
//
// Groups are a filing scheme, not a risk signal, so — unlike severity — they
// deliberately do not each get their own hue. A rainbow of category colours is
// exactly what DESIGN.md's audit called out ("purple badges, teal accents...
// competing with severity"), so every group icon reads in one quiet tone and
// the grouping itself carries the information.

interface AttrGroup {
  prefix: string;
  label: string;
  icon: React.ReactNode;
  humanLabel: Record<string, string>;
}

const GROUPS: AttrGroup[] = [
  {
    prefix: 'gen_ai',
    label: 'AI / LLM',
    icon: <Bot className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'gen_ai.request.model':   'Model',
      'gen_ai.response.model':  'Response Model',
      'gen_ai.usage.input_tokens':  'Input Tokens',
      'gen_ai.usage.output_tokens': 'Output Tokens',
      'gen_ai.tool.name':       'Tool Called',
      'gen_ai.system':          'AI System',
      'gen_ai.operation.name':  'Operation',
    },
  },
  {
    prefix: 'llm',
    label: 'AI / LLM',
    icon: <Bot className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'llm.request.model':   'Model',
      'llm.usage.input_tokens':  'Input Tokens',
      'llm.usage.output_tokens': 'Output Tokens',
      'llm.temperature':     'Temperature',
    },
  },
  {
    prefix: 'http',
    label: 'HTTP',
    icon: <Globe className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'http.request.method':  'Method',
      'http.response.status_code': 'Status',
      'http.url':             'URL',
      'http.method':          'Method',
      'http.status_code':     'Status',
      'url.full':             'URL',
      'url.path':             'Path',
      'server.address':       'Host',
      'server.port':          'Port',
    },
  },
  {
    prefix: 'db',
    label: 'Database',
    icon: <Database className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'db.system':        'DB System',
      'db.name':          'Database',
      'db.operation':     'Operation',
      'db.statement':     'Statement',
      'db.table':         'Table',
    },
  },
  {
    prefix: 'file',
    label: 'File I/O',
    icon: <FileText className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'file.path':        'Path',
      'file.name':        'Name',
      'file.operation':   'Operation',
      'file.size':        'Size',
    },
  },
  {
    prefix: 'process',
    label: 'Process',
    icon: <Terminal className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'process.executable.name': 'Executable',
      'process.command_line':    'Command',
      'process.pid':             'PID',
      'process.runtime.name':    'Runtime',
    },
  },
  {
    prefix: 'tool',
    label: 'Tool',
    icon: <Wrench className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'tool.name':         'Name',
      'tool.input':        'Input',
      'tool.output':       'Output',
    },
  },
  {
    // Scoped to 'claudesec.threat' rather than the whole 'claudesec' namespace
    // so it picks up only this attribute's sibling (claudesec.threat.rule,
    // hidden below) and leaves claudesec.sequence.* / claudesec.outcome.*
    // alone.
    prefix: 'claudesec.threat',
    label: 'Detection',
    icon: <ShieldAlert className="w-3 h-3" aria-hidden="true" />,
    humanLabel: {
      'claudesec.threat.matches': 'Rules Matched',
    },
  },
];

// Keys to always hide from the attributes panel (shown elsewhere in detail)
const HIDDEN_KEYS = new Set([
  'claudesec.threat.rule',
  'protocol',
  'reason',
]);

// ── Value rendering: truncation (both layers) + copy ────────────────────────

// The exact suffix `capSpanAttributes` (server/db.ts) appends when a value is
// cut at write time. Matched verbatim so the marker can be split out and
// rendered as its own honest line rather than read as part of the value.
const WRITE_TIME_TRUNCATION =
  /\n… \[ClaudeSec truncated (\d+) characters — detection ran on the full value\]$/;

function splitWriteTimeTruncation(value: string): { kept: string; droppedChars: number | null } {
  const m = value.match(WRITE_TIME_TRUNCATION);
  if (!m) return { kept: value, droppedChars: null };
  return { kept: value.slice(0, m.index), droppedChars: Number(m[1]) };
}

// Read-time collapse threshold. Independent of the 4KiB write-time cap — a
// value well under 4KiB can still be too long to read as a table row.
const UI_TRUNCATE_AT = 220;

function AttrValue({ value }: { value: unknown }) {
  const raw = typeof value === 'string' ? value : String(value);
  const { kept, droppedChars } = splitWriteTimeTruncation(raw);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const overLength = kept.length > UI_TRUNCATE_AT;
  const shown = overLength && !expanded ? kept.slice(0, UI_TRUNCATE_AT) + '…' : kept;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard can be unavailable (permissions, insecure context). Not
      // worth surfacing — the value is still fully visible to select by hand.
    }
  };

  return (
    <div className="min-w-0 group/attr">
      <div className="flex items-start gap-1.5">
        <p
          className="cs-mono flex-1 min-w-0"
          style={{
            color: 'var(--cs-text-body)',
            fontSize: 'var(--cs-text-xs)',
            whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere',
            wordBreak: 'break-word',
          }}
        >
          {shown}
        </p>
        <button
          type="button"
          onClick={copy}
          className="shrink-0 p-0.5 rounded opacity-0 group-hover/attr:opacity-100 focus-visible:opacity-100 transition-opacity"
          style={{ color: copied ? 'var(--cs-sev-low-fg)' : 'var(--cs-text-faint)' }}
          title="Copy full value"
          aria-label="Copy full value"
        >
          {copied ? <Check className="w-3 h-3" aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
        </button>
      </div>
      {overLength && (
        <button
          type="button"
          onClick={() => setExpanded(e => !e)}
          className="mt-0.5"
          style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-2xs)' }}
        >
          {expanded ? 'Show less' : `Show full value (${kept.length.toLocaleString()} chars)`}
        </button>
      )}
      {droppedChars != null && (
        <p
          className="italic mt-0.5"
          style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}
        >
          Truncated at write time — {droppedChars.toLocaleString()} more character{droppedChars === 1 ? '' : 's'} were
          captured but not stored here; detection ran on the full value.
        </p>
      )}
    </div>
  );
}

// ── Token gauge ─────────────────────────────────────────────────────────────

function TokenGauge({ input, output }: { input: number; output: number }) {
  const total = input + output || 1;
  const inPct  = Math.round((input  / total) * 100);
  const outPct = Math.round((output / total) * 100);
  return (
    <div className="mt-1.5">
      <div className="flex h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--cs-bg-sunken)' }}>
        <div style={{ width: `${inPct}%`,  background: 'rgba(var(--cs-accent-rgb), 0.65)' }} title={`Input: ${input}`} />
        <div style={{ width: `${outPct}%`, background: 'rgba(var(--cs-accent-rgb), 0.28)' }} title={`Output: ${output}`} />
      </div>
      <div className="flex justify-between mt-1" style={{ fontSize: 'var(--cs-text-2xs)' }}>
        <span style={{ color: 'var(--cs-text-body)' }}>↓ {input.toLocaleString()} in</span>
        <span style={{ color: 'var(--cs-text-faint)' }}>{output.toLocaleString()} out ↑</span>
      </div>
    </div>
  );
}

// ── HTTP badge ───────────────────────────────────────────────────────────────

function HttpStatusBadge({ code }: { code: number | string }) {
  const n = Number(code);
  // Reuses the severity ramp's foreground tokens rather than inventing a
  // fourth colour language for "ok / client error / server error" — the same
  // move AlertsTab makes for the LLM judge's verdict.
  const color = n >= 500 ? 'var(--cs-sev-critical-fg)'
              : n >= 400 ? 'var(--cs-sev-medium-fg)'
              : 'var(--cs-text-body)';
  return (
    <span
      className="cs-mono px-1.5 py-0.5 rounded"
      style={{ background: 'var(--cs-bg-raised)', color, fontWeight: 'var(--cs-weight-bold)', fontSize: 'var(--cs-text-xs)' }}
    >
      {code}
    </span>
  );
}

// ── Attribute group section ──────────────────────────────────────────────────

function AttrSection({ group, entries }: { group: AttrGroup; entries: [string, unknown][]; key?: React.Key }) {
  const [open, setOpen] = useState(true);

  // Special rendering for AI group
  const tokensIn  = Number(entries.find(([k]) => k.includes('input_tokens'))?.[1]  ?? 0);
  const tokensOut = Number(entries.find(([k]) => k.includes('output_tokens'))?.[1] ?? 0);
  const hasTokens = tokensIn > 0 || tokensOut > 0;

  // Special rendering for HTTP group
  const httpStatus = entries.find(([k]) => k.includes('status_code') || k.includes('status'))?.[1];

  return (
    <div className="rounded-md overflow-hidden mb-2" style={{ background: 'var(--cs-bg-raised)' }}>
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 transition-colors text-left"
        style={{ background: 'var(--cs-bg-surface)' }}
      >
        <span style={{ color: 'var(--cs-text-faint)' }}>{group.icon}</span>
        <span
          className="uppercase flex-1"
          style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)', letterSpacing: 'var(--cs-tracking-wide)' }}
        >
          {group.label}
        </span>
        <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>{entries.length}</span>
        {open
          ? <ChevronDown className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          : <ChevronRight className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}
      </button>

      {open && (
        <div className="px-2.5 py-2 space-y-2">
          {hasTokens && (group.prefix === 'gen_ai' || group.prefix === 'llm') && (
            <TokenGauge input={tokensIn} output={tokensOut} />
          )}
          {entries
            .filter(([k]) => !k.includes('input_tokens') && !k.includes('output_tokens') || (!hasTokens))
            .map(([key, value]) => {
              const label = group.humanLabel[key] ?? key.split('.').pop() ?? key;
              const isStatus = key.includes('status_code') || key.includes('status');
              return (
                <div key={key}>
                  <p className="cs-mono mb-0.5" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>{label}</p>
                  {isStatus && httpStatus
                    ? <HttpStatusBadge code={String(value)} />
                    : <AttrValue value={value} />
                  }
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}

// ── Main export ─────────────────────────────────────────────────────────────

export function SpanAttributes({ attrs }: { attrs: AttrMap }) {
  const [otherOpen, setOtherOpen] = useState(false);

  // Partition attributes into groups
  const used = new Set<string>();
  const groupSections: { group: AttrGroup; entries: [string, unknown][] }[] = [];

  const seen = new Set<string>(); // deduplicate across prefixes (gen_ai & llm overlap)
  for (const grp of GROUPS) {
    const entries = Object.entries(attrs).filter(
      ([k]) => k.startsWith(grp.prefix + '.') && !HIDDEN_KEYS.has(k) && !seen.has(k),
    );
    if (entries.length > 0) {
      entries.forEach(([k]) => { used.add(k); seen.add(k); });
      // Merge same-label groups (gen_ai + llm both appear as "AI / LLM")
      const existing = groupSections.find(s => s.group.label === grp.label);
      if (existing) {
        existing.entries.push(...entries);
      } else {
        groupSections.push({ group: grp, entries });
      }
    }
  }

  const otherEntries = Object.entries(attrs).filter(
    ([k]) => !used.has(k) && !HIDDEN_KEYS.has(k),
  );

  if (groupSections.length === 0 && otherEntries.length === 0) {
    return <p className="italic" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>No attributes</p>;
  }

  return (
    <div className="min-w-0">
      {groupSections.map(({ group, entries }) => (
        <AttrSection key={group.prefix + group.label} group={group} entries={entries} />
      ))}

      {otherEntries.length > 0 && (
        <div className="rounded-md overflow-hidden" style={{ background: 'var(--cs-bg-raised)' }}>
          <button
            type="button"
            onClick={() => setOtherOpen(o => !o)}
            aria-expanded={otherOpen}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 transition-colors text-left"
            style={{ background: 'var(--cs-bg-surface)' }}
          >
            <Package className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
            <span
              className="uppercase flex-1"
              style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)', letterSpacing: 'var(--cs-tracking-wide)' }}
            >
              Other
            </span>
            <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>{otherEntries.length}</span>
            {otherOpen
              ? <ChevronDown className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
              : <ChevronRight className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}
          </button>
          {otherOpen && (
            <div className="px-2.5 py-2 space-y-2">
              {otherEntries.map(([key, value]) => (
                <div key={key} className="p-1.5 rounded" style={{ background: 'var(--cs-bg-sunken)' }}>
                  <p className="cs-mono mb-0.5" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>{key}</p>
                  <AttrValue value={value} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
