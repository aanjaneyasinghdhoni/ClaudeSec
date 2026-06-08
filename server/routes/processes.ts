import type { Express } from 'express';
import { db } from '../db.js';
import { scanAgentProcesses } from '../processScan.js';
import type { RouteContext } from './context.js';

export function registerProcessRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Local agent process scanner (s64) ────────────────────────────────────
  app.get('/api/processes', (_req, res) => {
    const procs = scanAgentProcesses();
    // Enrich with active session correlation: find sessions whose harness matches
    const activeSessions = db.prepare(`
      SELECT se.traceId, se.name, se.createdAt, s.harness
      FROM sessions se
      JOIN spans s ON s.traceId = se.traceId
      WHERE se.createdAt > datetime('now', '-2 hours')
      GROUP BY se.traceId
    `).all() as { traceId: string; name: string; createdAt: string; harness: string }[];

    const sessionsByHarness = new Map<string, { traceId: string; name: string }[]>();
    for (const s of activeSessions) {
      if (!sessionsByHarness.has(s.harness)) sessionsByHarness.set(s.harness, []);
      sessionsByHarness.get(s.harness)!.push({ traceId: s.traceId, name: s.name });
    }

    const enriched = procs.map(p => ({
      ...p,
      recentSessions: sessionsByHarness.get(p.harness) ?? [],
    }));

    res.json({
      processes:  enriched,
      total:      enriched.length,
      scannedAt:  new Date().toISOString(),
      platform:   process.platform,
      supported:  process.platform === 'darwin' || process.platform === 'linux',
    });
  });

  // ── Process kill switch (Phase 16 / s71) ──────────────────────────────────
  // SECURITY: Only allow killing PIDs that are confirmed agent processes
  app.delete('/api/processes/:pid', (req, res) => {
    const pid = Number(req.params.pid);
    if (!pid || pid <= 0) return res.status(400).json({ error: 'Invalid PID' }) as any;
    if (process.platform === 'win32') return res.status(501).json({ error: 'Not supported on Windows' }) as any;

    // Validate PID is an actual agent process — prevents arbitrary process kill
    const agentPids = new Set(scanAgentProcesses().map(p => p.pid));
    if (!agentPids.has(pid)) {
      return res.status(403).json({ error: `PID ${pid} is not a recognized agent process. Only detected agent PIDs can be killed.` }) as any;
    }

    try {
      process.kill(pid, 'SIGTERM');
      console.log(`[ClaudeSec] Sent SIGTERM to agent PID ${pid}`);
      res.json({ ok: true, pid, signal: 'SIGTERM' });
    } catch (err: any) {
      if (err.code === 'ESRCH') return res.status(404).json({ error: `Process ${pid} not found` }) as any;
      if (err.code === 'EPERM') return res.status(403).json({ error: `Permission denied for PID ${pid}` }) as any;
      res.status(500).json({ error: err.message });
    }
  });

  // ── Bulk process control ─────────────────────────────────────────────────
  app.post('/api/processes/kill-all', (_req, res) => {
    if (process.platform === 'win32') return res.status(501).json({ error: 'Not supported on Windows' }) as any;
    const procs = scanAgentProcesses();
    const results = procs.map(p => {
      try { process.kill(p.pid, 'SIGTERM'); return { pid: p.pid, name: p.harnessName, ok: true }; }
      catch (e: any) { return { pid: p.pid, name: p.harnessName, ok: false, error: e.message }; }
    });
    const killed = results.filter(r => r.ok).length;
    console.log(`[ClaudeSec] Kill-all: ${killed}/${procs.length} agents terminated`);
    io.emit('processes-update');
    res.json({ killed, failed: results.filter(r => !r.ok).length, total: procs.length, results });
  });

  app.post('/api/processes/pause-all', (_req, res) => {
    if (process.platform === 'win32') return res.status(501).json({ error: 'Not supported on Windows' }) as any;
    const procs = scanAgentProcesses();
    const results = procs.map(p => {
      try { process.kill(p.pid, 'SIGSTOP'); return { pid: p.pid, name: p.harnessName, ok: true }; }
      catch (e: any) { return { pid: p.pid, name: p.harnessName, ok: false, error: e.message }; }
    });
    res.json({ paused: results.filter(r => r.ok).length, results });
  });

  app.post('/api/processes/resume-all', (_req, res) => {
    if (process.platform === 'win32') return res.status(501).json({ error: 'Not supported on Windows' }) as any;
    const procs = scanAgentProcesses();
    const results = procs.map(p => {
      try { process.kill(p.pid, 'SIGCONT'); return { pid: p.pid, name: p.harnessName, ok: true }; }
      catch (e: any) { return { pid: p.pid, name: p.harnessName, ok: false, error: e.message }; }
    });
    res.json({ resumed: results.filter(r => r.ok).length, results });
  });
}
