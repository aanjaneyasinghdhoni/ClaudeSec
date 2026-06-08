import { execSync } from 'child_process';
import { HARNESSES } from '../src/harnesses.js';

// ---------------------------------------------------------------------------
// Local agent process scanner (s64) — detects running CLI agent processes
// ---------------------------------------------------------------------------

export interface AgentProcess {
  pid:        number;
  harness:    string;
  harnessName: string;
  cmd:        string;
  cpuPct:     number;
  memMb:      number;
  startedAt:  string | null;
  user:       string;
}

// Patterns that identify each harness in a process command line
// Note: Electron helper processes (GPU, renderer, network, plugin, audio, crashpad)
// are excluded to avoid counting them as separate agents.
const ELECTRON_HELPER_RE = /Helper\s*\(|helper\s*\(|chrome_crashpad_handler|--type=(gpu|renderer|utility|zygote)|shell-snapshots\/|chrome-native-host|mcp-server\.(cjs|js|mjs)|worker-service\.(cjs|js)|uvx\s+--python/i;

const PROCESS_PATTERNS: { pattern: RegExp; harness: string }[] = [
  { pattern: /\bclaude\b/i, harness: 'claude-code' },
  { pattern: /\bcopilot\b/i, harness: 'copilot' },
  { pattern: /\bcodex\b/i,  harness: 'codex' },
];

export function scanAgentProcesses(): AgentProcess[] {
  try {
    const isLinux  = process.platform === 'linux';
    const isMac    = process.platform === 'darwin';
    if (!isLinux && !isMac) return []; // Windows not supported

    // ps output: PID  USER  %CPU  RSS_KB  LSTART(24)  COMMAND
    const raw = execSync(
      `ps aux 2>/dev/null || ps -eo pid,user,%cpu,rss,lstart,args 2>/dev/null`,
      { maxBuffer: 4 * 1024 * 1024, timeout: 5000 }
    ).toString();

    const results: AgentProcess[] = [];
    const seen = new Set<number>();

    for (const line of raw.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;

      // ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
      // ps -eo: PID USER %CPU RSS LSTART... ARGS
      let pid: number, user: string, cpuPct: number, memKb: number, cmd: string;

      // Detect ps aux format (USER is first column)
      const firstNum = Number(parts[1]);
      if (!isNaN(firstNum) && firstNum > 0) {
        // ps aux format
        user   = parts[0];
        pid    = firstNum;
        cpuPct = parseFloat(parts[2]) || 0;
        memKb  = parseFloat(parts[5]) || 0; // RSS in KB
        cmd    = parts.slice(10).join(' ');
      } else {
        // Fallback
        pid    = parseInt(parts[0]) || 0;
        user   = parts[1] || '';
        cpuPct = parseFloat(parts[2]) || 0;
        memKb  = parseFloat(parts[3]) || 0;
        cmd    = parts.slice(8).join(' ');
      }

      if (!pid || isNaN(pid) || seen.has(pid)) continue;

      // Skip Electron helper sub-processes (GPU, renderer, network, plugin, etc.)
      if (ELECTRON_HELPER_RE.test(cmd)) continue;

      // Match against known agent patterns
      const match = PROCESS_PATTERNS.find(p => p.pattern.test(cmd));
      if (!match) continue;

      seen.add(pid);
      const h = HARNESSES.find(h => h.id === match.harness) ?? HARNESSES[HARNESSES.length - 1];

      results.push({
        pid,
        harness:     match.harness,
        harnessName: h.name,
        cmd:         cmd.replace(/\/Users\/[^/]+/g, '/Users/***').replace(/\/home\/[^/]+/g, '/home/***').slice(0, 200),
        cpuPct:      Math.round(cpuPct * 10) / 10,
        memMb:       Math.round(memKb / 1024 * 10) / 10,
        startedAt:   null, // hard to parse reliably cross-platform
        user:        '***', // SECURITY: never expose OS username
      });
    }

    return results.sort((a, b) => b.cpuPct - a.cpuPct);
  } catch {
    return [];
  }
}
