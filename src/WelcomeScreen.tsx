import React, { useState, useEffect } from 'react';
import {
  Shield, Eye, Zap, Terminal, Copy, Check, Play,
  Monitor, AlertTriangle, Activity, ChevronRight,
  ArrowRight,
} from 'lucide-react';

const HARNESS_CARDS: {
  name: string; color: string; slug: string;
  envVars: string;
}[] = [
  {
    name: 'Claude Code',
    color: '#00d4aa',
    slug: 'claude-code',
    envVars: `export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'GitHub Copilot',
    color: '#6366f1',
    slug: 'github-copilot',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Cursor',
    color: '#a855f7',
    slug: 'cursor',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Aider',
    color: '#ec4899',
    slug: 'aider',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'OpenHands',
    color: '#22c55e',
    slug: 'openhands',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Cline',
    color: '#14b8a6',
    slug: 'cline',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Goose',
    color: '#f59e0b',
    slug: 'goose',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Windsurf',
    color: '#38bdf8',
    slug: 'windsurf',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Codex CLI',
    color: '#10b981',
    slug: 'codex',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_SERVICE_NAME="codex"`,
  },
  {
    name: 'Continue.dev',
    color: '#0ea5e9',
    slug: 'continue',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/json"`,
  },
  {
    name: 'Amazon Q',
    color: '#f59e0b',
    slug: 'amazon-q',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_SERVICE_NAME="amazon-q"`,
  },
  {
    name: 'Roo-Code',
    color: '#8b5cf6',
    slug: 'roo-code',
    envVars: `export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:3000/v1/traces"
export OTEL_SERVICE_NAME="roo-code"`,
  },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
        copied
          ? 'bg-green-600 text-white'
          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
      }`}
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied!' : 'Copy setup'}
    </button>
  );
}

export function WelcomeScreen({ onDemoLoaded }: { onDemoLoaded: () => void }) {
  const [loading, setLoading]       = useState(false);
  const [expanded, setExpanded]     = useState<string | null>(null);
  const [processes, setProcesses]   = useState<{ harnessName: string; pid: number }[]>([]);
  const [demoResult, setDemoResult] = useState<string | null>(null);
  const [scanning, setScanning]     = useState(true);

  useEffect(() => {
    fetch('/api/processes')
      .then(r => r.json())
      .then(d => { setProcesses(d.processes ?? []); setScanning(false); })
      .catch(() => setScanning(false));
  }, []);

  const runDemo = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/simulate', { method: 'POST' });
      const data = await res.json();
      setDemoResult(`${data.spans} spans, ${data.alerts} alerts across ${data.sessions} sessions`);
      setTimeout(onDemoLoaded, 800);
    } catch {
      setDemoResult('Failed to generate demo traces');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 overflow-auto bg-grain" style={{ background: 'var(--cs-bg-primary)' }}>
      {/* Subtle grid pattern background */}
      <div className="absolute inset-0 opacity-[0.02]" style={{
        backgroundImage: `linear-gradient(var(--cs-border) 1px, transparent 1px), linear-gradient(90deg, var(--cs-border) 1px, transparent 1px)`,
        backgroundSize: '48px 48px',
      }} />

      <div className="max-w-3xl mx-auto px-8 py-16 relative z-10">

        {/* Hero */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-slate-900/60 text-xs text-slate-400 font-mono mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 status-live" />
            v1.0 · Open Source
          </div>
          <div className="flex items-center justify-center gap-4 mb-6">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center glow-teal" style={{ background: 'linear-gradient(135deg, #00d4aa, #009e7f)' }}>
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="font-display text-4xl font-bold tracking-tight mb-4" style={{ color: 'var(--cs-text-base)' }}>
            AI Agent Security<br />
            <span className="text-shimmer">Observatory</span>
          </h1>
          <p className="text-base leading-relaxed max-w-lg mx-auto" style={{ color: 'var(--cs-text-muted)' }}>
            Monitor every AI agent on your machine. Detect threats in real-time.
            Visualize tool calls, LLM requests, and suspicious activity as a live graph.
          </p>
        </div>

        {/* Quick-start CTA */}
        <div className="rounded-2xl p-6 mb-10 text-center border glow-teal" style={{
          background: 'linear-gradient(135deg, rgba(0,212,170,0.06), rgba(59,158,255,0.04))',
          borderColor: 'rgba(0,212,170,0.15)',
        }}>
          <h2 className="font-display text-lg font-semibold mb-2" style={{ color: 'var(--cs-text-base)' }}>
            See it in action
          </h2>
          <p className="text-sm mb-5 max-w-md mx-auto" style={{ color: 'var(--cs-text-muted)' }}>
            Generate 3 realistic demo sessions with threats, costs, and alerts to explore every feature.
          </p>
          <button
            onClick={runDemo}
            disabled={loading || !!demoResult}
            className="inline-flex items-center gap-2.5 px-7 py-3.5 rounded-xl text-sm font-semibold transition-all"
            style={{
              background: demoResult ? '#059669'
                : loading ? '#0e7c64'
                : 'linear-gradient(135deg, #00d4aa, #009e7f)',
              color: '#fff',
              boxShadow: demoResult ? 'none' : '0 4px 24px rgba(0,212,170,0.3)',
              transform: loading ? 'none' : undefined,
            }}
          >
            {demoResult ? (
              <><Check className="w-4 h-4" /> {demoResult}</>
            ) : loading ? (
              <><Activity className="w-4 h-4 animate-spin" /> Generating traces...</>
            ) : (
              <><Play className="w-4 h-4" /> Launch demo traces <ArrowRight className="w-4 h-4" /></>
            )}
          </button>
        </div>

        {/* Value cards — 3 column */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-12">
          {[
            {
              icon: <Eye className="w-5 h-5" />,
              color: '#3b9eff',
              title: 'Full Visibility',
              desc: 'Every tool call, LLM request, file access, and bash command — visualized as an interactive graph.',
            },
            {
              icon: <AlertTriangle className="w-5 h-5" />,
              color: '#ff3b5c',
              title: '153 Threat Rules',
              desc: 'Prompt injection, credential leaks, reverse shells, supply-chain attacks, data exfiltration.',
            },
            {
              icon: <Zap className="w-5 h-5" />,
              color: '#ffb224',
              title: 'Kill Switch',
              desc: 'Kill runaway processes, set budgets, get webhook alerts, auto-export — all from one dashboard.',
            },
          ].map((card, i) => (
            <div
              key={i}
              className="animate-fade-up rounded-xl p-5 border card-hover"
              style={{
                background: 'var(--cs-bg-surface)',
                borderColor: 'var(--cs-border)',
              }}
            >
              <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
                style={{ background: card.color + '15', color: card.color }}>
                {card.icon}
              </div>
              <h3 className="font-display font-semibold text-sm mb-1.5" style={{ color: 'var(--cs-text-base)' }}>
                {card.title}
              </h3>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--cs-text-faint)' }}>
                {card.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Running agents auto-detect */}
        <div className="rounded-xl p-5 mb-10 border" style={{
          background: 'var(--cs-bg-surface)',
          borderColor: processes.length > 0 ? 'rgba(0,212,170,0.2)' : 'var(--cs-border)',
        }}>
          <div className="flex items-center gap-2.5 mb-3">
            <Monitor className={`w-4 h-4 ${processes.length > 0 ? 'text-green-400' : scanning ? 'text-cyan-400 animate-pulse' : ''}`}
              style={!processes.length && !scanning ? { color: 'var(--cs-text-faint)' } : {}} />
            <h3 className="font-display font-semibold text-sm" style={{ color: 'var(--cs-text-base)' }}>
              {scanning
                ? 'Scanning for running AI agents...'
                : processes.length > 0
                  ? `${processes.length} agent${processes.length > 1 ? 's' : ''} detected`
                  : 'No agents detected'}
            </h3>
          </div>
          {processes.length > 0 ? (
            <>
              <div className="flex flex-wrap gap-2">
                {processes.map((p, i) => (
                  <span key={i} className="px-3 py-1.5 rounded-lg text-xs font-mono font-medium border" style={{
                    background: 'rgba(0,212,170,0.08)',
                    borderColor: 'rgba(0,212,170,0.2)',
                    color: '#00d4aa',
                  }}>
                    <span className="inline-block w-1.5 h-1.5 rounded-full mr-2 status-live" style={{ background: '#00d4aa' }} />
                    {p.harnessName} <span style={{ opacity: 0.5 }}>PID {p.pid}</span>
                  </span>
                ))}
              </div>
              <p className="text-[11px] mt-3" style={{ color: 'var(--cs-text-faint)' }}>
                Activity will appear in the graph automatically.
              </p>
            </>
          ) : !scanning && (
            <p className="text-xs" style={{ color: 'var(--cs-text-faint)' }}>
              Start an AI agent and it will be detected automatically. Or use the setup below.
            </p>
          )}
        </div>

        {/* Connect agents */}
        <div className="mb-12">
          <h2 className="font-display text-lg font-semibold mb-1" style={{ color: 'var(--cs-text-base)' }}>
            Connect your agents
          </h2>
          <p className="text-sm mb-5" style={{ color: 'var(--cs-text-faint)' }}>
            Paste these env vars in your terminal, restart the agent. Traces flow in automatically.
          </p>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
            {HARNESS_CARDS.map(h => (
              <div
                key={h.slug}
                className="rounded-lg overflow-hidden border transition-all cursor-pointer card-hover"
                style={{
                  background: expanded === h.slug ? 'var(--cs-bg-elevated)' : 'var(--cs-bg-surface)',
                  borderColor: expanded === h.slug ? h.color + '40' : 'var(--cs-border)',
                }}
                onClick={() => setExpanded(expanded === h.slug ? null : h.slug)}
              >
                <div className="p-3 flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: h.color }} />
                  <span className="text-sm font-medium truncate" style={{ color: 'var(--cs-text-base)' }}>{h.name}</span>
                  <ChevronRight className="w-3 h-3 ml-auto shrink-0 transition-transform"
                    style={{
                      color: 'var(--cs-text-faint)',
                      transform: expanded === h.slug ? 'rotate(90deg)' : 'none',
                    }} />
                </div>

                {expanded === h.slug && (
                  <div className="px-3 pb-3" style={{ borderTop: `1px solid var(--cs-border)` }}>
                    <pre className="text-xs font-mono rounded-lg p-3 mt-2 overflow-x-auto whitespace-pre leading-relaxed"
                      style={{ background: 'var(--cs-bg-primary)', color: 'var(--cs-text-muted)' }}>
                      {h.envVars}
                    </pre>
                    <div className="mt-2">
                      <CopyButton text={h.envVars} />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* How it works — horizontal pipeline */}
        <div className="rounded-xl p-5 mb-10 border" style={{
          background: 'var(--cs-bg-surface)',
          borderColor: 'var(--cs-border)',
        }}>
          <h3 className="font-display font-semibold text-sm mb-4" style={{ color: 'var(--cs-text-base)' }}>
            How it works
          </h3>
          <div className="flex flex-col md:flex-row items-start md:items-center gap-3 md:gap-4 text-xs" style={{ color: 'var(--cs-text-muted)' }}>
            {[
              { n: '1', label: 'Agent emits OTLP traces', color: '#3b9eff' },
              { n: '2', label: 'ClaudeSec ingests & scans', color: '#00d4aa' },
              { n: '3', label: '153 rules detect threats', color: '#ffb224' },
              { n: '4', label: 'Live graph + alerts', color: '#00d4aa' },
            ].map((step, i) => (
              <React.Fragment key={i}>
                {i > 0 && <ArrowRight className="hidden md:block w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }} />}
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-mono font-bold shrink-0"
                    style={{ background: step.color + '15', color: step.color }}>
                    {step.n}
                  </span>
                  <span>{step.label}</span>
                </div>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs font-mono" style={{ color: 'var(--cs-text-faint)' }}>
          ClaudeSec v1.0 · Supports 14+ agent harnesses · MIT License
        </p>
      </div>
    </div>
  );
}
