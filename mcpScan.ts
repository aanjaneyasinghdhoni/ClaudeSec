// mcpScan.ts
//
// Static scanner for installed MCP servers and Claude skills/configs.
//
// Inspects, READ-ONLY, the surfaces an AI agent trusts implicitly:
//   • MCP server configs (~/.claude/settings.json, ~/.claude/settings.local.json,
//     ~/.claude.json, and project .mcp.json) — the `mcpServers` objects.
//   • Skills (~/.claude/skills/**/SKILL.md and plugin skills under
//     ~/.claude/plugins/**/SKILL.md) — frontmatter description + body.
//
// and flags four classes of problem:
//   1. Prompt-injection / hidden instructions in any description or body.
//   2. Tool poisoning / shadowing — descriptions that instruct the agent to
//      perform hidden side-effects (exfiltrate, read secrets, override tools).
//   3. Hardcoded secrets in configs / env / args (reuses scrub.ts patterns).
//   4. Suspicious launch commands (reuses the engine's detectSeverity over
//      command + args — e.g. npx of an untrusted remote, curl | sh).
//
// It NEVER launches an MCP server and NEVER modifies any scanned file.
//
// The detection engine (detectSeverity) is INJECTED rather than imported to
// avoid a circular dependency on server.ts.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { detectSecrets, maskSecret, type SecretFinding } from './scrub.js';

// ── Public types ────────────────────────────────────────────────────────────

export type ScanSeverity = 'low' | 'medium' | 'high';

export interface ScanFinding {
  source:   string;        // human-readable origin, e.g. "MCP server 'foo' (~/.claude.json)"
  sourceId: string;        // stable id for grouping in the UI
  kind:     'prompt-injection' | 'tool-poisoning' | 'hardcoded-secret' | 'suspicious-command';
  severity: ScanSeverity;
  label:    string;        // short rule name
  detail:   string;        // human explanation
  excerpt:  string;        // offending snippet (secrets masked)
}

export interface ScannedSource {
  id:    string;
  type:  'mcp-server' | 'skill';
  name:  string;
  file:  string;           // path the source was read from (home-relative)
}

export interface ScanResult {
  scannedAt: string;
  roots:     string[];
  sources:   ScannedSource[];
  findings:  ScanFinding[];
  summary: {
    mcpServers:  number;
    skills:      number;
    filesScanned: number;
    findings:    number;
    bySeverity:  Record<ScanSeverity, number>;
    byKind:      Record<ScanFinding['kind'], number>;
    truncated:   boolean;  // hit a scan cap (too many files / too large)
  };
}

// Injected detector — matches detectSeverity's return shape (subset we use).
export interface DetectFn {
  (text: string): { severity: 'none' | 'low' | 'medium' | 'high'; matchedLabel: string; matchedText: string };
}

// ── Bounds (the scan must stay fast even with hundreds of skills) ────────────

const MAX_FILE_BYTES   = 256 * 1024;   // skip files larger than this
const MAX_FILES        = 2000;         // total files read across all roots
const MAX_FINDINGS     = 2000;         // stop accumulating beyond this
const MAX_EXCERPT      = 200;          // excerpt length cap
const MAX_SKILL_DIRS   = 4000;         // directory-walk node cap

// ── Tool-poisoning heuristics ───────────────────────────────────────────────
// These describe hidden side-effects a *description* should never instruct the
// agent to perform. Deliberately specific to keep false positives low on the
// hundreds of legitimate skills in a real ~/.claude.
const POISON_PATTERNS: { re: RegExp; severity: ScanSeverity; label: string }[] = [
  { re: /do\s+not\s+(tell|inform|mention|reveal|notify)\s+(the\s+)?(user|human|operator)/i, severity: 'high',   label: 'instructs agent to hide actions from the user' },
  { re: /(without|don'?t)\s+(telling|informing|asking|notifying)\s+(the\s+)?(user|them)/i,    severity: 'high',   label: 'instructs agent to act without informing the user' },
  { re: /\bread\b[^.\n]{0,40}\b(\.env|id_rsa|\.ssh|\.aws|credentials|secrets?|private\s+key|password)/i, severity: 'high', label: 'instructs agent to read secret files' },
  { re: /\b(exfiltrat|leak|send|upload|post|forward)\b[^.\n]{0,60}\b(secret|credential|token|api[_-]?key|password|\.env|conversation|history)\b/i, severity: 'high', label: 'instructs agent to exfiltrate secrets/data' },
  { re: /\b(curl|wget|fetch|http)\b[^.\n]{0,80}\b(\$\{?[A-Z_]+\}?|env|token|secret|key)\b/i, severity: 'medium', label: 'embeds an outbound request carrying environment data' },
  { re: /(override|replace|ignore|disable)\s+(the\s+)?(other\s+)?(tools?|instructions?|system\s+prompt|guidelines?)/i, severity: 'high', label: 'instructs agent to override other tools/instructions' },
  { re: /before\s+(answering|responding|using\s+any\s+(other\s+)?tool)[^.\n]{0,80}(call|invoke|run|execute|read|send)/i, severity: 'medium', label: 'hidden pre-action directive ("before answering, …")' },
  { re: /<important_?(do_not_tell|instructions)>/i, severity: 'high', label: 'hidden-instruction tag in description' },
  { re: /\b(base64|rot13|atob)\b[^.\n]{0,40}(decode|then\s+(run|execute|eval))/i, severity: 'high', label: 'encoded instruction blob (decode-and-run)' },
];

// ── Prompt-injection heuristics (prose) ──────────────────────────────────────
// A CURATED, high-precision subset for free-form prose (descriptions + skill
// bodies). We deliberately do NOT run the full 183-rule engine over prose: rules
// like "Code eval injection" / "Exec injection" / "SQL injection-style" fire on
// any skill body that shows a code example, producing heavy false positives on
// the hundreds of legitimate skills in a real ~/.claude. The full engine IS used
// for launch command+args, where those code-execution rules are exactly right.
const INJECTION_PATTERNS: { re: RegExp; severity: ScanSeverity; label: string }[] = [
  { re: /ignore\s+(all\s+)?(previous|prior)\s+instructions?/i,            severity: 'high',   label: 'ignore-previous-instructions injection' },
  { re: /disregard\s+(your\s+)?(the\s+)?(previous|prior|system)\s+(instructions?|prompt|guidelines?)/i, severity: 'high', label: 'disregard-system injection' },
  { re: /forget\s+(everything|all|your)\s+(previous|prior)\s+(instructions?|context|conversations?)/i, severity: 'high', label: 'memory-wipe injection' },
  { re: /from\s+now\s+on\s+you\s+(must|will|are\s+to)\s+(ignore|disregard|forget)/i, severity: 'high', label: 'from-now-on override injection' },
  { re: /override\s+(all\s+)?(previous\s+)?(the\s+)?(system\s+)?instructions/i, severity: 'high', label: 'override-instructions injection' },
  { re: /you\s+are\s+now\s+DAN\b/i,                                       severity: 'high',   label: 'DAN jailbreak persona injection' },
  { re: /do\s+anything\s+now\b/i,                                         severity: 'high',   label: 'DAN "do anything now" jailbreak' },
  { re: /developer\s+mode\s+(enabled|activated|on)\b/i,                   severity: 'high',   label: 'developer-mode jailbreak activation' },
  { re: /pretend\s+(that\s+)?you\s+have\s+no\s+(restrictions|guidelines|rules|filters)/i, severity: 'high', label: 'pretend-no-restrictions jailbreak' },
  { re: /bypass\s+(your\s+)?(safety|content|ethical)\s+(filter|check|guard|guidelines|restrictions)/i, severity: 'high', label: 'safety-bypass jailbreak' },
  { re: /jailbreak\s+(mode|activated|enabled)\b/i,                        severity: 'high',   label: 'explicit jailbreak mode activation' },
  { re: /new\s+(system\s+)?(instructions?|prompt)\s*:/i,                  severity: 'medium', label: 'new system prompt injection' },
  { re: /system\s*:\s*you\s+are\b/i,                                      severity: 'high',   label: 'fake system prompt injection' },
  { re: /<system>/i,                                                     severity: 'medium', label: 'instruction smuggling via <system> tag' },
  { re: /\[SYSTEM\]\s*override/i,                                         severity: 'high',   label: 'system-override tag injection' },
  { re: /<!--[^>]*\bignore\b[^>]*-->/i,                                   severity: 'high',   label: 'HTML-comment hidden directive' },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function homeRel(p: string): string {
  const home = (() => { try { return os.homedir(); } catch { return ''; } })();
  if (home && p.startsWith(home)) return '~' + p.slice(home.length);
  return p;
}

function clampExcerpt(s: string, around?: { start: number; len: number }): string {
  // Redact full secrets BEFORE slicing the window — otherwise a window clipping
  // into a token's tail could leave an (unmasked) fragment that addFinding's
  // full-token redaction can no longer recognise. Masking first means no
  // fragment can ever form. The `around` indices are computed on the original
  // text; after masking the window may shift slightly (mask is shorter than the
  // secret) — that is purely cosmetic, the content is always safe.
  for (const f of detectSecrets(s)) s = s.split(f.match).join(f.masked);
  let text = s.replace(/\s+/g, ' ').trim();
  if (around && around.len > 0) {
    const ctx = 40;
    const a = Math.max(0, around.start - ctx);
    text = (a > 0 ? '…' : '') + s.slice(a, around.start + around.len + ctx).replace(/\s+/g, ' ').trim();
  }
  if (text.length > MAX_EXCERPT) text = text.slice(0, MAX_EXCERPT) + '…';
  return text;
}

function safeRead(file: string): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function safeJson<T = any>(file: string): T | null {
  const raw = safeRead(file);
  if (raw == null) return null;
  try { return JSON.parse(raw) as T; } catch { return null; }
}

// Minimal, dependency-free YAML-ish frontmatter description extractor.
// Handles `description: ...`, quoted, and block-scalar (`description: |`) forms.
function parseSkill(md: string): { description: string; body: string } {
  const fm = /^---\s*\n([\s\S]*?)\n---\s*\n?/.exec(md);
  if (!fm) return { description: '', body: md };
  const front = fm[1];
  const body = md.slice(fm[0].length);
  let description = '';
  const lines = front.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^description:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    let val = m[1].trim();
    if (val === '|' || val === '>' || val === '|-' || val === '>-' || val === '') {
      // block scalar — gather indented continuation lines
      const collected: string[] = [];
      for (let j = i + 1; j < lines.length; j++) {
        if (/^\S/.test(lines[j]) && lines[j].trim() !== '') break; // dedented key
        collected.push(lines[j].replace(/^\s{0,4}/, ''));
      }
      description = collected.join(' ').trim();
    } else {
      description = val.replace(/^["']|["']$/g, '');
    }
    break;
  }
  return { description, body };
}

// ── Root discovery ───────────────────────────────────────────────────────────

/**
 * The roots the scanner walks. Overridable with CLAUDESEC_MCP_SCAN_ROOTS
 * (colon/comma-separated) so tests can point it at a temp fixture. When set,
 * it fully REPLACES the defaults (does not append) so a fixture scan is not
 * polluted by the real ~/.claude.
 */
export function defaultScanRoots(): string[] {
  const override = process.env.CLAUDESEC_MCP_SCAN_ROOTS;
  if (override && override.trim()) {
    return override.split(/[:,]/).map(s => s.trim()).filter(Boolean);
  }
  const home = (() => { try { return os.homedir(); } catch { return ''; } })();
  const roots: string[] = [];
  if (home) roots.push(path.join(home, '.claude'));
  return roots;
}

// ── MCP server config discovery ──────────────────────────────────────────────

interface McpServerEntry {
  name:    string;
  file:    string;
  command?: string;
  args?:    unknown[];
  env?:     Record<string, unknown>;
  url?:     string;
  type?:    string;
  raw:      Record<string, unknown>;
}

function collectMcpServers(roots: string[]): McpServerEntry[] {
  const out: McpServerEntry[] = [];
  const seen = new Set<string>();
  const home = (() => { try { return os.homedir(); } catch { return ''; } })();

  const pushFromMap = (file: string, map: unknown) => {
    if (!map || typeof map !== 'object' || Array.isArray(map)) return;
    for (const [name, v] of Object.entries(map as Record<string, unknown>)) {
      if (!v || typeof v !== 'object') continue;
      const dedup = `${file}::${name}`;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      const s = v as Record<string, unknown>;
      out.push({
        name,
        file: homeRel(file),
        command: typeof s.command === 'string' ? s.command : undefined,
        args:    Array.isArray(s.args) ? s.args : undefined,
        env:     (s.env && typeof s.env === 'object' && !Array.isArray(s.env)) ? s.env as Record<string, unknown> : undefined,
        url:     typeof s.url === 'string' ? s.url : undefined,
        type:    typeof s.type === 'string' ? s.type : undefined,
        raw:     s,
      });
    }
  };

  // Candidate config files. For each root we look at the well-known names; we
  // also always consult ~/.claude.json (top-level + per-project mcpServers) and
  // any .mcp.json directly under a root, since those are the canonical sources.
  const candidates = new Set<string>();
  for (const root of roots) {
    candidates.add(path.join(root, 'settings.json'));
    candidates.add(path.join(root, 'settings.local.json'));
    candidates.add(path.join(root, '.mcp.json'));
    candidates.add(path.join(root, '.claude.json'));
    // If the root itself is a project dir, its .mcp.json lives at the root.
    candidates.add(path.join(path.dirname(root), '.mcp.json'));
  }
  // The real per-user MCP registry lives at ~/.claude.json (sibling of ~/.claude).
  if (home && !process.env.CLAUDESEC_MCP_SCAN_ROOTS) {
    candidates.add(path.join(home, '.claude.json'));
  }

  for (const file of candidates) {
    const json = safeJson<Record<string, any>>(file);
    if (!json) continue;
    // Top-level mcpServers (settings.json / .mcp.json / .claude.json)
    pushFromMap(file, json.mcpServers);
    // Per-project mcpServers inside .claude.json
    if (json.projects && typeof json.projects === 'object') {
      for (const [proj, pv] of Object.entries(json.projects as Record<string, any>)) {
        if (pv && typeof pv === 'object' && pv.mcpServers) {
          pushFromMap(`${file} [project: ${homeRel(proj)}]`, pv.mcpServers);
        }
      }
    }
  }
  return out;
}

// ── Skill discovery ───────────────────────────────────────────────────────────

function collectSkillFiles(roots: string[]): string[] {
  const files: string[] = [];
  let dirNodes = 0;

  const walk = (dir: string, depth: number) => {
    if (files.length >= MAX_FILES || dirNodes >= MAX_SKILL_DIRS || depth > 12) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    dirNodes++;
    for (const e of entries) {
      if (files.length >= MAX_FILES) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.git') continue;
        walk(full, depth + 1);
      } else if (e.isFile() && e.name === 'SKILL.md') {
        files.push(full);
      }
    }
  };

  for (const root of roots) {
    // Both user skills (<root>/skills) and plugin skills (<root>/plugins) plus
    // any SKILL.md anywhere under the root (covers fixture layouts and the
    // nested plugin cache structure).
    walk(path.join(root, 'skills'), 0);
    walk(path.join(root, 'plugins'), 0);
    // Fixture / fallback: also walk the root itself shallowly for stray SKILL.md.
    walk(root, 0);
  }
  // dedupe
  return Array.from(new Set(files));
}

// ── Main scan ─────────────────────────────────────────────────────────────────

export function scanMcpAndSkills(detect: DetectFn, rootsArg?: string[]): ScanResult {
  const roots = (rootsArg && rootsArg.length ? rootsArg : defaultScanRoots());
  const findings: ScanFinding[] = [];
  const sources: ScannedSource[] = [];
  let filesScanned = 0;
  let truncated = false;

  // Redact any credential that happens to sit inside a finding's excerpt before
  // it leaves the scanner. Secret-kind excerpts are already masked at emit time,
  // but suspicious-command / injection / poisoning excerpts are raw slices of
  // command+args/env/prose that may legitimately contain a token (e.g. a
  // `--token ghp_…` arg). A security tool must never surface live credentials in
  // its own output, the API response, or a screenshot — so we mask at the choke
  // point, covering every kind, present and future.
  const redactSecretsInText = (s: string): string => {
    for (const f of detectSecrets(s)) s = s.split(f.match).join(f.masked);
    return s;
  };

  const addFinding = (f: ScanFinding) => {
    if (findings.length >= MAX_FINDINGS) { truncated = true; return; }
    f.excerpt = redactSecretsInText(f.excerpt);
    findings.push(f);
  };

  // Run injection (always) + tool-poisoning (description surfaces only) over a
  // piece of text.
  //
  // `surface` controls FP-sensitive scope:
  //   • 'description' — frontmatter description, MCP server description/env/args:
  //     the high-trust, low-noise surface the agent reads to decide whether to
  //     invoke a tool. Tool-poisoning heuristics run here.
  //   • 'body' — skill markdown body: legitimately full of prose like "read the
  //     .env", "send the data", code examples, etc. Only the precise injection
  //     patterns run here; tool-poisoning is intentionally suppressed to avoid
  //     flagging every security/QA skill that *describes* such operations.
  const scanText = (
    text: string,
    src: { source: string; sourceId: string },
    surface: 'description' | 'body',
  ) => {
    if (!text) return;
    // 1) Prompt injection — curated, high-precision set (NOT the full engine,
    //    which misclassifies code examples as eval/exec "injection").
    for (const p of INJECTION_PATTERNS) {
      const m = p.re.exec(text);
      if (m) {
        addFinding({
          ...src,
          kind: 'prompt-injection',
          severity: p.severity,
          label: p.label,
          detail: `Prompt-injection / hidden-instruction pattern in the ${surface}.`,
          excerpt: clampExcerpt(text, { start: m.index, len: m[0].length }),
        });
        break; // one injection finding per text is enough signal
      }
    }
    // 2) Tool poisoning / shadowing — description surface only (see above).
    if (surface !== 'description') return;
    for (const p of POISON_PATTERNS) {
      const m = p.re.exec(text);
      if (m) {
        addFinding({
          ...src,
          kind: 'tool-poisoning',
          severity: p.severity,
          label: p.label,
          detail: 'Description instructs the agent to perform a hidden side-effect.',
          excerpt: clampExcerpt(text, { start: m.index, len: m[0].length }),
        });
        break; // one poisoning finding per text is enough signal
      }
    }
  };

  const scanSecrets = (
    text: string,
    src: { source: string; sourceId: string },
    where: string,
  ) => {
    if (!text) return;
    const secrets: SecretFinding[] = detectSecrets(text);
    for (const s of secrets) {
      addFinding({
        ...src,
        kind: 'hardcoded-secret',
        severity: 'high',
        label: `hardcoded ${s.kind}`,
        detail: `A ${s.kind} appears in ${where}. Secrets in MCP/skill configs are world-readable to the agent and any tool it runs.`,
        excerpt: `${where}: ${s.masked}`,
      });
    }
  };

  // ── MCP servers ──
  let mcpCount = 0;
  for (const srv of collectMcpServers(roots)) {
    mcpCount++;
    filesScanned++;
    const sourceId = `mcp:${srv.file}:${srv.name}`;
    const source = `MCP server "${srv.name}" (${srv.file})`;
    const ref = { source, sourceId };
    sources.push({ id: sourceId, type: 'mcp-server', name: srv.name, file: srv.file });

    // 3) Suspicious launch command — detectSeverity over command + args.
    const cmdParts: string[] = [];
    if (srv.command) cmdParts.push(srv.command);
    if (srv.args) cmdParts.push(...srv.args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))));
    const cmdLine = cmdParts.join(' ');
    if (cmdLine) {
      const hit = detect(cmdLine);
      if (hit.severity !== 'none') {
        const idx = hit.matchedText ? cmdLine.indexOf(hit.matchedText) : -1;
        addFinding({
          ...ref,
          kind: 'suspicious-command',
          severity: (hit.severity === 'high' ? 'high' : hit.severity === 'medium' ? 'medium' : 'low'),
          label: hit.matchedLabel,
          detail: `Launch command "${srv.command ?? ''}" matched a threat rule.`,
          excerpt: clampExcerpt(cmdLine, idx >= 0 ? { start: idx, len: hit.matchedText.length } : undefined),
        });
      }
      // Heuristic: npx/uvx/bunx of a remote URL (untrusted remote execution).
      if (/\b(npx|uvx|bunx|pnpm\s+dlx|yarn\s+dlx)\b/i.test(cmdLine) && /\bhttps?:\/\/\S+/i.test(cmdLine)) {
        const um = /https?:\/\/\S+/i.exec(cmdLine);
        addFinding({
          ...ref,
          kind: 'suspicious-command',
          severity: 'high',
          label: 'package-runner executing code from a remote URL',
          detail: 'The launch command pipes a remote URL into npx/uvx/bunx — code is fetched and run unpinned at startup.',
          excerpt: clampExcerpt(cmdLine, um ? { start: um.index, len: um[0].length } : undefined),
        });
      }
    }

    // 4) Hardcoded secrets in args / env values / url.
    if (srv.args) {
      for (const a of srv.args) if (typeof a === 'string') scanSecrets(a, ref, 'args');
    }
    if (srv.env) {
      for (const [k, v] of Object.entries(srv.env)) {
        if (typeof v === 'string') scanSecrets(v, ref, `env.${k}`);
      }
    }
    if (srv.url) scanSecrets(srv.url, ref, 'url');

    // Some configs carry a free-form "description"/"instructions" on the server.
    const desc = typeof srv.raw.description === 'string' ? srv.raw.description
               : typeof (srv.raw as any).instructions === 'string' ? (srv.raw as any).instructions
               : '';
    if (desc) scanText(desc, ref, 'description');

    // Injection / hidden instructions can also be smuggled through env values
    // and string args (the agent may surface these to the model). These are
    // structured config, not free prose, so they're treated as a description
    // surface (low noise — tool-poisoning checks apply too).
    if (srv.env) {
      for (const v of Object.values(srv.env)) if (typeof v === 'string') scanText(v, ref, 'description');
    }
    if (srv.args) {
      for (const a of srv.args) if (typeof a === 'string') scanText(a, ref, 'description');
    }
  }

  // ── Skills ──
  let skillCount = 0;
  for (const file of collectSkillFiles(roots)) {
    if (filesScanned >= MAX_FILES) { truncated = true; break; }
    const md = safeRead(file);
    if (md == null) continue;
    filesScanned++;
    skillCount++;
    const rel = homeRel(file);
    const { description, body } = parseSkill(md);
    const name = path.basename(path.dirname(file));
    const sourceId = `skill:${rel}`;
    const source = `Skill "${name}" (${rel})`;
    const ref = { source, sourceId };
    sources.push({ id: sourceId, type: 'skill', name, file: rel });

    // Injection + tool-poisoning over the description (highest-trust surface).
    // The body gets injection-only scanning — legitimate skill bodies routinely
    // describe reading files / sending data / code examples, so running the
    // poisoning heuristics there produces heavy false positives.
    scanText(description, ref, 'description');
    scanText(body, ref, 'body');
    scanSecrets(description, ref, 'description');
    scanSecrets(body, ref, 'body');
  }

  // ── Summary ──
  const bySeverity: Record<ScanSeverity, number> = { low: 0, medium: 0, high: 0 };
  const byKind: Record<ScanFinding['kind'], number> = {
    'prompt-injection': 0, 'tool-poisoning': 0, 'hardcoded-secret': 0, 'suspicious-command': 0,
  };
  for (const f of findings) { bySeverity[f.severity]++; byKind[f.kind]++; }

  return {
    scannedAt: new Date().toISOString(),
    roots: roots.map(homeRel),
    sources,
    findings,
    summary: {
      mcpServers: mcpCount,
      skills: skillCount,
      filesScanned,
      findings: findings.length,
      bySeverity,
      byKind,
      truncated,
    },
  };
}
