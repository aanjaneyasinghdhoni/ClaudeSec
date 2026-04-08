import React, { useState, useEffect } from 'react';
import {
  Shield, Eye, Zap, Terminal, Copy, Check, Play,
  Monitor, AlertTriangle, Activity,
} from 'lucide-react';

const HARNESS_CARDS: {
  name: string; color: string; slug: string;
  envVars: string;
}[] = [
  {
    name: 'Claude Code',
    color: '#f97316',
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
          : 'bg-slate-700 hover:bg-slate-600 text-slate-300'
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

  useEffect(() => {
    fetch('/api/processes')
      .then(r => r.json())
      .then(d => setProcesses(d.processes ?? []))
      .catch(() => {});
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
    <div className="flex-1 overflow-auto bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <div className="max-w-4xl mx-auto px-6 py-12">

        {/* Hero */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield className="w-7 h-7 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-3 tracking-tight">
            AI Agent Security Observatory
          </h1>
          <p className="text-lg text-slate-400 max-w-xl mx-auto leading-relaxed">
            Monitor, detect threats, and visualize every AI agent running on your machine in real-time.
            <span className="text-slate-500"> 150+ built-in security rules. Zero configuration needed.</span>
          </p>
        </div>

        {/* Value cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 text-center">
            <div className="w-10 h-10 bg-blue-500/10 rounded-xl flex items-center justify-center mx-auto mb-3">
              <Eye className="w-5 h-5 text-blue-400" />
            </div>
            <h3 className="font-semibold text-white mb-1.5">See Everything</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Every tool call, LLM request, file access, and bash command — visualized as an interactive graph in real-time.
            </p>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 text-center">
            <div className="w-10 h-10 bg-red-500/10 rounded-xl flex items-center justify-center mx-auto mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <h3 className="font-semibold text-white mb-1.5">Catch Threats</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              150+ detection rules catch prompt injection, credential leaks, reverse shells, supply-chain attacks, and data exfiltration.
            </p>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 text-center">
            <div className="w-10 h-10 bg-green-500/10 rounded-xl flex items-center justify-center mx-auto mb-3">
              <Zap className="w-5 h-5 text-green-400" />
            </div>
            <h3 className="font-semibold text-white mb-1.5">Stay in Control</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Kill runaway processes, set resource budgets, get webhook alerts, auto-export data — all from one dashboard.
            </p>
          </div>
        </div>

        {/* Try Demo — THE most important button */}
        <div className="bg-gradient-to-r from-blue-900/30 to-purple-900/30 border border-blue-700/30 rounded-2xl p-6 mb-10 text-center">
          <h2 className="text-lg font-bold text-white mb-2">See it in action</h2>
          <p className="text-sm text-slate-400 mb-5 max-w-md mx-auto">
            Inject 3 realistic demo sessions (Claude Code, Aider, Cursor) with threats, costs, and alerts to explore every feature.
          </p>
          <button
            onClick={runDemo}
            disabled={loading || !!demoResult}
            className={`inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold transition-all shadow-lg ${
              demoResult
                ? 'bg-green-600 text-white shadow-green-600/20'
                : loading
                  ? 'bg-blue-700 text-blue-200 cursor-wait'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-600/30 hover:shadow-blue-500/40 hover:scale-105'
            }`}
          >
            {demoResult ? (
              <><Check className="w-4 h-4" /> {demoResult}</>
            ) : loading ? (
              <><Activity className="w-4 h-4 animate-spin" /> Generating traces...</>
            ) : (
              <><Play className="w-4 h-4" /> Try it now — inject demo traces</>
            )}
          </button>
        </div>

        {/* Running agents auto-detect */}
        {processes.length > 0 && (
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 mb-10">
            <div className="flex items-center gap-2 mb-3">
              <Monitor className="w-4 h-4 text-cyan-400" />
              <h3 className="font-semibold text-white text-sm">
                {processes.length} agent{processes.length > 1 ? 's' : ''} detected on this machine
              </h3>
            </div>
            <div className="flex flex-wrap gap-2">
              {processes.map((p, i) => (
                <span key={i} className="px-2.5 py-1 bg-slate-800 rounded-lg text-xs text-slate-300 border border-slate-700">
                  {p.harnessName} <span className="text-slate-600">PID {p.pid}</span>
                </span>
              ))}
            </div>
            <p className="text-[11px] text-slate-600 mt-3">
              Configure these agents with the env vars below to start seeing their traces.
            </p>
          </div>
        )}

        {/* Quick-start: harness setup cards */}
        <div className="mb-10">
          <h2 className="text-lg font-bold text-white mb-1">Connect your agents</h2>
          <p className="text-sm text-slate-500 mb-5">
            Copy these environment variables into the terminal where you run your agent. Restart the agent. Traces appear here automatically.
          </p>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {HARNESS_CARDS.map(h => (
              <div
                key={h.slug}
                className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all cursor-pointer"
                onClick={() => setExpanded(expanded === h.slug ? null : h.slug)}
              >
                <div className="p-3 flex items-center gap-2.5">
                  <span className="w-3 h-3 rounded-full shrink-0" style={{ background: h.color }} />
                  <span className="text-sm font-medium text-slate-200 truncate">{h.name}</span>
                  <Terminal className="w-3 h-3 text-slate-600 ml-auto shrink-0" />
                </div>

                {expanded === h.slug && (
                  <div className="px-3 pb-3 border-t border-slate-800">
                    <pre className="text-[10px] font-mono text-slate-400 bg-slate-950 rounded-lg p-2.5 mt-2 overflow-x-auto whitespace-pre leading-relaxed">
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

        {/* How it works */}
        <div className="bg-slate-900/50 border border-slate-800/50 rounded-2xl p-5 mb-8">
          <h3 className="font-semibold text-white text-sm mb-3">How it works</h3>
          <div className="flex flex-col md:flex-row items-start md:items-center gap-3 md:gap-6 text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 bg-blue-900/40 rounded-full flex items-center justify-center text-blue-400 text-[10px] font-bold shrink-0">1</span>
              <span>Agent emits OpenTelemetry traces</span>
            </div>
            <span className="hidden md:block text-slate-700">→</span>
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 bg-blue-900/40 rounded-full flex items-center justify-center text-blue-400 text-[10px] font-bold shrink-0">2</span>
              <span>ClaudeSec ingests via POST /v1/traces</span>
            </div>
            <span className="hidden md:block text-slate-700">→</span>
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 bg-blue-900/40 rounded-full flex items-center justify-center text-blue-400 text-[10px] font-bold shrink-0">3</span>
              <span>150+ rules scan for threats in real-time</span>
            </div>
            <span className="hidden md:block text-slate-700">→</span>
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 bg-green-900/40 rounded-full flex items-center justify-center text-green-400 text-[10px] font-bold shrink-0">4</span>
              <span>Live graph, alerts, costs, timeline</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-slate-700">
          ClaudeSec v1.0 · Open source AI agent observatory · Supports 14+ agent harnesses
        </p>
      </div>
    </div>
  );
}
