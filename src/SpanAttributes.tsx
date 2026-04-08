/**
 * SpanAttributes — enriched display of OTel semantic convention attributes.
 * Groups attrs by namespace with icons + human-readable labels.
 * Replaces the raw key→value list in the span detail panel.
 */
import React, { useState } from 'react';
import { Bot, Globe, Database, FileText, Terminal, Wrench, Package, ChevronDown, ChevronRight } from 'lucide-react';

type AttrMap = Record<string, unknown>;

// ── Semantic group definitions ──────────────────────────────────────────────

interface AttrGroup {
  prefix: string;
  label: string;
  icon: React.ReactNode;
  color: string;
  humanLabel: Record<string, string>;
}

const GROUPS: AttrGroup[] = [
  {
    prefix: 'gen_ai',
    label: 'AI / LLM',
    icon: <Bot className="w-3 h-3" />,
    color: 'text-purple-400',
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
    icon: <Bot className="w-3 h-3" />,
    color: 'text-purple-400',
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
    icon: <Globe className="w-3 h-3" />,
    color: 'text-blue-400',
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
    icon: <Database className="w-3 h-3" />,
    color: 'text-green-400',
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
    icon: <FileText className="w-3 h-3" />,
    color: 'text-yellow-400',
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
    icon: <Terminal className="w-3 h-3" />,
    color: 'text-orange-400',
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
    icon: <Wrench className="w-3 h-3" />,
    color: 'text-cyan-400',
    humanLabel: {
      'tool.name':         'Name',
      'tool.input':        'Input',
      'tool.output':       'Output',
    },
  },
];

// Keys to always hide from the attributes panel (shown elsewhere in detail)
const HIDDEN_KEYS = new Set([
  'claudesec.threat.rule',
  'protocol',
  'reason',
]);

// ── Token gauge ─────────────────────────────────────────────────────────────

function TokenGauge({ input, output }: { input: number; output: number }) {
  const total = input + output || 1;
  const inPct  = Math.round((input  / total) * 100);
  const outPct = Math.round((output / total) * 100);
  return (
    <div className="mt-1.5">
      <div className="flex h-2 rounded-full overflow-hidden bg-slate-800 mb-1">
        <div className="bg-blue-500/80"   style={{ width: `${inPct}%` }}  title={`Input: ${input}`} />
        <div className="bg-purple-500/80" style={{ width: `${outPct}%` }} title={`Output: ${output}`} />
      </div>
      <div className="flex justify-between text-[11px] text-slate-600">
        <span className="text-blue-400">↓ {input.toLocaleString()} in</span>
        <span className="text-purple-400">{output.toLocaleString()} out ↑</span>
      </div>
    </div>
  );
}

// ── HTTP badge ───────────────────────────────────────────────────────────────

function HttpStatusBadge({ code }: { code: number | string }) {
  const n = Number(code);
  const color = n < 300 ? 'text-green-400 bg-green-900/40' : n < 500 ? 'text-yellow-400 bg-yellow-900/40' : 'text-red-400 bg-red-900/40';
  return <span className={`px-1.5 py-0.5 rounded text-xs font-bold font-mono ${color}`}>{code}</span>;
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
    <div className="border border-slate-700/60 rounded-lg overflow-hidden mb-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 bg-slate-800/60 hover:bg-slate-800 transition-colors text-left"
      >
        <span className={group.color}>{group.icon}</span>
        <span className="text-xs font-bold text-slate-300 uppercase tracking-wide flex-1">{group.label}</span>
        <span className="text-[11px] text-slate-600">{entries.length}</span>
        {open ? <ChevronDown className="w-3 h-3 text-slate-600" /> : <ChevronRight className="w-3 h-3 text-slate-600" />}
      </button>

      {open && (
        <div className="px-2.5 py-2 space-y-1.5 bg-slate-900/40">
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
                  <p className="text-[11px] text-slate-600 font-mono mb-0.5">{label}</p>
                  {isStatus && httpStatus
                    ? <HttpStatusBadge code={String(value)} />
                    : <p className="text-[11px] text-slate-300 font-mono break-all">{String(value)}</p>
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
    return <p className="text-[11px] text-slate-600 italic">No attributes</p>;
  }

  return (
    <div>
      {groupSections.map(({ group, entries }) => (
        <AttrSection key={group.prefix + group.label} group={group} entries={entries} />
      ))}

      {otherEntries.length > 0 && (
        <div className="border border-slate-700/60 rounded-lg overflow-hidden">
          <button
            onClick={() => setOtherOpen(o => !o)}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 bg-slate-800/60 hover:bg-slate-800 transition-colors text-left"
          >
            <Package className="w-3 h-3 text-slate-500" />
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wide flex-1">Other</span>
            <span className="text-[11px] text-slate-600">{otherEntries.length}</span>
            {otherOpen ? <ChevronDown className="w-3 h-3 text-slate-600" /> : <ChevronRight className="w-3 h-3 text-slate-600" />}
          </button>
          {otherOpen && (
            <div className="px-2.5 py-2 space-y-1.5 bg-slate-900/40">
              {otherEntries.map(([key, value]) => (
                <div key={key} className="p-1.5 bg-slate-950 rounded border border-slate-800">
                  <p className="text-[11px] text-slate-600 font-mono mb-0.5">{key}</p>
                  <p className="text-[11px] text-slate-300 font-mono break-all">{String(value)}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
