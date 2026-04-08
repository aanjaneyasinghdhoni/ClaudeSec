import React, { useEffect, useState } from 'react';
import { Activity, X, Zap, Clock } from 'lucide-react';
import { socket } from './socket';
import { motion, AnimatePresence } from 'motion/react';

interface AgentActivity {
  harness:     string;
  harnessName: string;
  color:       string;
  lastSpan:    string;
  tool:        string;
  input:       string;
  model:       string;
  severity:    string;
  traceId:     string;
  secondsAgo:  number;
  active:      boolean;
}

function timeAgo(sec: number): string {
  if (sec < 5)     return 'just now';
  if (sec < 60)    return `${sec}s ago`;
  if (sec < 3600)  return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

export function LiveActivityPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [agents, setAgents] = useState<AgentActivity[]>([]);

  const fetchActivity = () => {
    fetch('/api/live-activity')
      .then(r => r.json())
      .then(d => setAgents(d.agents ?? []))
      .catch(() => {});
  };

  useEffect(() => {
    if (!open) return;
    fetchActivity();
    const handler = () => fetchActivity();
    socket.on('span-added', handler);
    socket.on('graph-update', handler);
    const timer = setInterval(fetchActivity, 5000);
    return () => {
      socket.off('span-added', handler);
      socket.off('graph-update', handler);
      clearInterval(timer);
    };
  }, [open]);

  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: 20 }}
        className="fixed top-16 right-4 z-50 w-80 bg-slate-900/95 backdrop-blur-md border border-slate-800 rounded-2xl shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
          <Zap className="w-4 h-4" style={{ color: '#00d4aa' }} />
          <span className="text-xs font-bold text-slate-200 flex-1">Live Agent Activity</span>
          <span className="text-xs font-mono text-slate-500">{agents.filter(a => a.active).length} active</span>
          <button onClick={onClose} className="p-1 hover:bg-slate-800 rounded-lg text-slate-500 hover:text-slate-300 transition-colors">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Agent list */}
        <div className="max-h-96 overflow-y-auto">
          {agents.length === 0 ? (
            <div className="p-6 text-center">
              <Activity className="w-6 h-6 text-slate-700 mx-auto mb-2" />
              <p className="text-xs text-slate-500">No agent activity yet</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/50">
              {agents.map(agent => (
                <div
                  key={agent.harness}
                  className={`px-4 py-3 transition-colors ${agent.active ? 'bg-slate-800/20' : ''}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ background: agent.color, boxShadow: agent.active ? `0 0 6px ${agent.color}` : 'none' }}
                    />
                    <span className="text-[11px] font-semibold text-slate-200 flex-1 truncate">
                      {agent.harnessName}
                    </span>
                    <span className={`text-[11px] font-mono ${agent.active ? 'text-green-400' : 'text-slate-600'}`}>
                      <Clock className="w-2.5 h-2.5 inline mr-0.5" />
                      {timeAgo(agent.secondsAgo)}
                    </span>
                  </div>

                  {/* What it's doing */}
                  <div className="ml-4">
                    {agent.tool && (
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[11px] font-mono font-medium ${
                          agent.severity === 'high' ? 'bg-red-900/40 text-red-300'
                          : agent.severity === 'medium' ? 'bg-orange-900/40 text-orange-300'
                          : 'bg-slate-800 text-slate-400'
                        }`}>
                          {agent.tool}
                        </span>
                        {agent.model && (
                          <span className="text-[11px] text-slate-600 font-mono truncate">{agent.model}</span>
                        )}
                      </div>
                    )}
                    {agent.input && (
                      <p className="text-xs text-slate-500 font-mono truncate" title={agent.input}>
                        {agent.input}
                      </p>
                    )}
                    {!agent.tool && (
                      <p className="text-xs text-slate-600 truncate">{agent.lastSpan}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
