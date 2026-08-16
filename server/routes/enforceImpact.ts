/**
 * enforceImpact.ts — "what would enforce mode actually have blocked?"
 *
 * Flipping the enforcement toggle is a one-click decision with no undo for the
 * command it denies, and until now the only way to learn what enforce mode costs
 * was to turn it on and start getting refused. This endpoint answers the question
 * from evidence instead: it replays the tool calls already recorded in the spans
 * table through the SAME evaluator the enforcer runs, and reports what would have
 * happened.
 *
 * Three properties make the answer worth acting on:
 *
 *   1. It is the real evaluator. `evaluate()` and `evaluateFetch()` from
 *      server/enforceEval.ts are imported and called, not re-implemented. A
 *      preview built from a second copy of the matching logic would drift from
 *      the enforcer within one release and quietly report a fiction.
 *
 *   2. It separates the two populations that a single "N blocked" headline
 *      hides. The catastrophic, self-protection and protected-path floors block
 *      in EVERY mode, so their hits are not a forecast — they are already
 *      happening today, in monitor mode. Only rule-engine matches are conditional
 *      on the toggle. The two are reported separately because the first is a fact
 *      about the present and the second is a choice about the future.
 *
 *   3. It ranks by rule. "437 rules are high severity" is not a decision; "these
 *      seven rules produce 80% of the blocks, and here are three real commands
 *      each of them stopped" is. Per-rule rows carry counts, share, cumulative
 *      share and examples so a human can sort a genuine catch from their own
 *      daily workflow.
 *
 * ── Fidelity: what this replay can and cannot see ───────────────────────────
 * Recorded spans are not tool-call payloads; they are what survived ingestion.
 * The gaps are also listed in the response's `caveats`, so the number is never
 * read as more precise than it is:
 *
 *   • Edit CONTENT is not replayed, so the live-secret (DLP) floor contributes
 *     nothing here. Deliberate on both counts: pulling every edit body through
 *     this loop would read hundreds of megabytes for a floor that could not fire
 *     anyway, because the scrubber replaced every credential shape that floor
 *     looks for before the span was stored.
 *   • Attributes are scrubbed at ingest, so a stored command names the home
 *     directory as `/Users/***`. Every home-anchored floor — the default
 *     protected paths (~/.ssh, ~/.aws/credentials, ~/.npmrc) and the
 *     self-protection prefixes (~/.claude/settings.json, ~/.claudesec/hooks) — is
 *     written against the real home directory and would miss all of them. So the
 *     placeholder is mapped back FOR MATCHING ONLY (see `unscrubHome`); the
 *     examples returned to the client are always the stored, scrubbed text.
 *     Without this the most important number on the screen would round to zero
 *     and the preview would lie by omission.
 *   • Everything else the scrubber redacted (tokens, connection strings) stays
 *     redacted, so a rule keyed on a literal credential under-counts.
 *   • Verdicts use TODAY's rules, overrides and protected-path list against past
 *     commands. That is the intended reading — the question is what the CURRENT
 *     rule set would do — but it is a forecast, not a historical record.
 *
 * ── Cost, and why the read is paginated rather than streamed ────────────────
 * The table is large (a real install is past 278k spans / ~700 MB) and the work
 * per distinct call is a few hundred regexes plus, for the floors, realpath
 * syscalls — around 130 µs measured, split roughly 60/40 between the rule engine
 * and the floors. Over a full 76-day history that is several seconds of pure
 * CPU, which must not be spent in one blocking turn: this process also ingests
 * spans and serves sockets.
 *
 * So the scan yields to the event loop between pages. It cannot do that while a
 * `.iterate()` cursor is open — better-sqlite3 refuses any write on a connection
 * whose statement is still running ("This database connection is busy executing a
 * query"), and `server/db.ts` hands the ingest path the very same connection.
 * Streaming would therefore have made every span arriving during a preview throw.
 * Paging by `rowid` instead lets each page's statement finish before the yield,
 * so the connection is free whenever this handler is not on the stack.
 *
 * Three further things keep the cost bounded:
 *   • SQL-side filtering — only the four tool families the PreToolUse hook is
 *     registered for can produce a verdict, so json_extract discards the rest
 *     inside SQLite and Node never receives, let alone parses, their attributes
 *     blobs. On real data that is ~113k candidate rows out of 278k.
 *   • Memoized verdicts — the evaluator is pure for a given (matchText,
 *     targetPath) within one request, and agents repeat themselves constantly.
 *   • A short result TTL, so re-opening the panel is free rather than a re-scan.
 *
 * The response reports its own `timing`, so the cost is visible rather than
 * asserted.
 */
import type { Express } from 'express';
import os from 'node:os';
import { db } from '../db.js';
import {
  evaluate, evaluateFetch, loadBlockRules, resolveMode,
  type CompiledRule, type EnforceMode,
} from '../enforceEval.js';
import { loadScrubOptions, scrubText } from '../scrub.js';
import type { RouteContext } from './context.js';

// The self-protection floor names the prefix it matched, which is an absolute
// path built from the real home directory (`Self-protection: /Users/<name>/...`).
// Every other free-form string this server stores or broadcasts goes through the
// scrubber, and a label is no exception — so labels and examples are scrubbed on
// the way out, exactly as the enforcement feed scrubs its own. Built once: the
// options are read-only after construction (see loadScrubOptions).
const scrubOptions = loadScrubOptions();
const scrub = (s: string): string => scrubText(s, scrubOptions);

// ── Window + safety limits ──────────────────────────────────────────────────

/** Default lookback when no `days` is given — a month is the usual decision window. */
const DEFAULT_DAYS = 30;

/**
 * Hard ceiling on the lookback. Retention keeps the table well inside a year, so
 * nobody reaches this in practice; it exists so a hand-typed `?days=100000`
 * cannot become an unbounded scan.
 */
const MAX_DAYS = 400;

/**
 * Ceiling on candidate rows examined. Reached only by an install far larger than
 * any seen so far; when it bites, the response says so (`scanned.truncated`)
 * rather than passing a partial answer off as the whole picture.
 */
const MAX_CANDIDATE_ROWS = 400_000;

/**
 * Rows per page. Each page is folded in one synchronous burst, so this is the
 * knob that trades scan throughput against how long the event loop can be held:
 * at the measured ~130 µs per uncached call, 500 rows keeps the measured worst
 * page near 100 ms. (1000 was tried first and peaked at 230 ms on real data.)
 */
const PAGE_SIZE = 500;

/**
 * Verdict-cache ceiling. Distinct calls are what cost; on real data ~100k
 * evaluations collapse to ~68k distinct. The cap bounds worst-case memory on a
 * machine whose agents never repeat themselves.
 */
const MAX_CACHE_ENTRIES = 150_000;

/**
 * Cache keys are built from the command text, so an enormous command would park
 * a proportionally enormous key in the map. Above this length the verdict is
 * computed and used but not remembered — long commands are rare enough (36 of
 * 46k exceed 8 KB on real data) that the lost reuse costs nothing.
 */
const MAX_CACHE_KEY_LEN = 8192;

/**
 * How long a finished report stays servable. The underlying evidence is days of
 * history, so a minute of staleness changes no decision, and it keeps re-opening
 * the panel (or a second browser tab) from paying for the scan again.
 */
const REPORT_TTL_MS = 60_000;

/** Example commands kept per rule — enough to judge a pattern, not a data dump. */
const EXAMPLES_PER_RULE = 3;

/** Examples are for recognition, not reproduction; a line is plenty. */
const EXAMPLE_MAX_LEN = 240;

/**
 * The tool names the PreToolUse hook is actually registered for
 * (cli/installHook.ts: BASH_MATCHER / EDIT_MATCHER / READ_MATCHER /
 * FETCH_MATCHER). Replaying anything else would invent enforcement no installed
 * hook performs. NotebookRead is deliberately absent: the hook's READ_TOOLS set
 * names it, but no matcher registers it, so it never reaches the enforcer.
 */
const BASH_TOOL = 'Bash';
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const READ_TOOLS = new Set(['Read']);
const FETCH_TOOLS = new Set(['WebFetch', 'WebSearch']);
export const IMPACT_TOOLS: readonly string[] = [
  BASH_TOOL, ...EDIT_TOOLS, ...READ_TOOLS, ...FETCH_TOOLS,
];

// ── Shapes ──────────────────────────────────────────────────────────────────

/** One candidate tool call, projected out of a span's attributes by SQLite. */
export interface ImpactRow {
  tool: string | null;
  command: string | null;
  target: string | null;
  url: string | null;
  startNano: string | null;
}

export interface ImpactExample {
  /** The stored (scrubbed) command, fetch URL or file path, truncated. */
  text: string;
  tool: string;
  /** Epoch milliseconds, or null when the span carried no usable timestamp. */
  atMs: number | null;
}

export interface ImpactRule {
  label: string;
  severity: string;
  count: number;
  /**
   * How many distinct call texts this rule stopped. A rule that fired 900 times
   * on one repeated command is a very different proposition from one that caught
   * 900 different commands, and only this column tells them apart.
   */
  distinctCalls: number;
  /** Share of this group's blocks, 0–100. */
  share: number;
  /** Running share once the group is sorted by count, 0–100. */
  cumulativeShare: number;
  examples: ImpactExample[];
}

export interface ImpactGroup {
  total: number;
  /** Blocks by severity, using the matching rule's own severity. */
  bySeverity: Record<string, number>;
  rules: ImpactRule[];
  /** Share of the group produced by its ten most frequent rules, 0–100. */
  top10Share: number;
  /** How many rules, taken most-frequent-first, it takes to cover 80%. */
  rulesToReach80: number;
}

export interface ImpactFold {
  scanned: {
    candidateRows: number;
    evaluated: number;
    distinctCalls: number;
    /** Fraction of evaluations answered from the memo, 0–100. */
    cacheHitRate: number;
    /** True when MAX_CANDIDATE_ROWS cut the scan short. */
    truncated: boolean;
    byTool: Record<string, { evaluated: number; blocked: number }>;
  };
  /**
   * Conditional on the toggle: the rule-engine matches. Turning enforce on adds
   * exactly these denials.
   */
  wouldBlockInEnforce: ImpactGroup;
  /**
   * Mode-independent floors — catastrophic, self-protection, protected paths.
   * Already being denied today, whatever the toggle says.
   */
  blocksTodayAnyMode: ImpactGroup;
  /** Extent of the calls actually seen — the honest span of the evidence. */
  oldestCallMs: number | null;
  newestCallMs: number | null;
}

export interface ImpactReport extends ImpactFold {
  window: { days: number; sinceMs: number };
  /** How many snapshot rules compile to an effective 'block' action right now. */
  blockRulesCompiled: number;
  /** The mode the enforcer currently resolves — context for reading the groups. */
  effectiveMode: EnforceMode;
  timing: { totalMs: number; pages: number };
  /** When this report was computed, and whether it was served from the memo. */
  computedAtMs: number;
  cached: boolean;
  caveats: string[];
}

// ── Replay ──────────────────────────────────────────────────────────────────

/**
 * Map the scrubber's home-directory placeholder back onto this machine's home
 * directory. MATCHING ONLY — see the fidelity note in the file header. Both
 * placeholders are handled because one database can hold spans ingested on either
 * platform (`/Users/***` on macOS, `/home/***` on Linux).
 */
function unscrubHome(text: string): string {
  if (!text || text.indexOf('***') === -1) return text;
  const home = os.homedir();
  return text.replace(/\/Users\/\*\*\*/g, home).replace(/\/home\/\*\*\*/g, home);
}

/** Epoch nanoseconds (stored as TEXT) → epoch milliseconds, or null. */
function nanoToMs(nano: string | null): number | null {
  if (!nano) return null;
  try {
    const ms = Number(BigInt(nano) / 1_000_000n);
    return Number.isFinite(ms) && ms > 0 ? ms : null;
  } catch {
    return null;
  }
}

/** A verdict, reduced to what the aggregation needs. */
interface Verdict {
  label: string | null;
  severity: string;
  /** True when the match was a mode-independent floor rather than a rule. */
  floor: boolean;
}

const NO_HIT: Verdict = { label: null, severity: 'none', floor: false };

/**
 * Classify one fetch URL. Asking the real `evaluateFetch` twice — once as
 * monitor, once as enforce — is what separates the always-on metadata floor from
 * the internal/loopback tier that only bites under enforce. Deriving that split
 * from the class name here would be a second copy of the policy.
 */
function fetchVerdict(url: string): Verdict {
  const asMonitor = evaluateFetch(url, 'monitor');
  if (asMonitor.block) {
    return { label: `SSRF: fetch to ${asMonitor.klass} address`, severity: 'high', floor: true };
  }
  const asEnforce = evaluateFetch(url, 'enforce');
  if (asEnforce.block) {
    return { label: `SSRF: fetch to ${asEnforce.klass} address`, severity: 'high', floor: false };
  }
  return NO_HIT;
}

/** Mutable accumulator for one rule while pages are being folded. */
interface RuleAcc {
  label: string;
  severity: string;
  count: number;
  distinctCalls: number;
  examples: ImpactExample[];
}

function finishGroup(accs: Map<string, RuleAcc>): ImpactGroup {
  const rules = [...accs.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  const total = rules.reduce((sum, r) => sum + r.count, 0);
  const bySeverity: Record<string, number> = {};

  let running = 0;
  let top10 = 0;
  // -1 until a rule crosses 80%; an empty group legitimately needs zero rules.
  let rulesToReach80 = total === 0 ? 0 : -1;

  const out: ImpactRule[] = rules.map((r, i) => {
    bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + r.count;
    running += r.count;
    if (i < 10) top10 += r.count;
    const cumulativeShare = total ? (running / total) * 100 : 0;
    if (rulesToReach80 === -1 && cumulativeShare >= 80) rulesToReach80 = i + 1;
    return {
      // Scrubbed only on the way out — the accumulator is keyed on the raw label
      // so two distinct floors can never merge into one row.
      label: scrub(r.label),
      severity: r.severity,
      count: r.count,
      distinctCalls: r.distinctCalls,
      share: total ? (r.count / total) * 100 : 0,
      cumulativeShare,
      examples: r.examples.map(e => ({ ...e, text: scrub(e.text) })),
    };
  });

  return {
    total,
    bySeverity,
    rules: out,
    top10Share: total ? (top10 / total) * 100 : 0,
    // The last rule is always at 100%, so this fallback is unreachable; it is
    // here so the field is a count rather than a sentinel under any input.
    rulesToReach80: rulesToReach80 === -1 ? out.length : rulesToReach80,
  };
}

/**
 * A replay in progress. Pages are folded in one at a time so the caller can yield
 * to the event loop between them, and the aggregates live here rather than in the
 * caller. `full()` reports whether MAX_CANDIDATE_ROWS has been reached, which is
 * the caller's signal to stop reading.
 */
export interface ImpactSession {
  fold(rows: Iterable<ImpactRow>): void;
  full(): boolean;
  finish(): ImpactFold;
}

export function createImpactSession(blockRules: CompiledRule[]): ImpactSession {
  const cache = new Map<string, Verdict>();
  const enforceOnly = new Map<string, RuleAcc>();
  const everyMode = new Map<string, RuleAcc>();
  const byTool: Record<string, { evaluated: number; blocked: number }> = {};

  let candidateRows = 0;
  let evaluated = 0;
  let cacheHits = 0;
  let truncated = false;
  let oldestCallMs: number | null = null;
  let newestCallMs: number | null = null;

  /** Look a verdict up, computing (and remembering) it only on first sight. */
  function lookup(key: string, compute: () => Verdict): { verdict: Verdict; firstSight: boolean } {
    const cached = cache.get(key);
    if (cached) {
      cacheHits++;
      return { verdict: cached, firstSight: false };
    }
    const verdict = compute();
    if (cache.size < MAX_CACHE_ENTRIES && key.length <= MAX_CACHE_KEY_LEN) cache.set(key, verdict);
    return { verdict, firstSight: true };
  }

  function fold(rows: Iterable<ImpactRow>): void {
    for (const row of rows) {
      if (candidateRows >= MAX_CANDIDATE_ROWS) { truncated = true; return; }
      candidateRows++;

      const tool = row.tool ?? '';
      // The stored text is what goes back to the client; the unscrubbed twin is
      // what the floors are matched against. Keeping both apart is the point —
      // see the fidelity note in the header.
      const storedCommand = row.command ?? '';
      const storedTarget = row.target ?? '';
      const storedUrl = row.url ?? '';

      let verdict: Verdict;
      let firstSight: boolean;
      let exampleText: string;

      if (FETCH_TOOLS.has(tool)) {
        // WebSearch carries no URL and so can never trip the SSRF floor; skipping
        // it mirrors the hook, which leaves its matchText empty.
        if (!storedUrl) continue;
        exampleText = storedUrl;
        ({ verdict, firstSight } = lookup('u ' + storedUrl, () => fetchVerdict(storedUrl)));
      } else {
        // matchText / targetPath exactly as the hook derives them: a Bash command
        // is the execution boundary; an edit is judged on its PATH only, never on
        // the body it writes; a read reaches the floors through its target alone
        // and is never run against the rule engine.
        let matchText = '';
        let targetPath = '';
        if (tool === BASH_TOOL) {
          matchText = unscrubHome(storedCommand);
          exampleText = storedCommand;
        } else if (EDIT_TOOLS.has(tool)) {
          targetPath = unscrubHome(storedTarget);
          matchText = targetPath;
          exampleText = storedTarget;
        } else if (READ_TOOLS.has(tool)) {
          targetPath = unscrubHome(storedTarget);
          exampleText = storedTarget;
        } else {
          continue; // not a tool the hook is registered for
        }
        if (!matchText && !targetPath) continue;

        // Both halves are in the key: an edit and a read of the same path reach
        // different floors, so they must never share a verdict.
        ({ verdict, firstSight } = lookup('c ' + matchText + ' ' + targetPath, () => {
          const r = evaluate(matchText, blockRules, '', targetPath);
          return r.triggered
            ? { label: r.label ?? '(unlabeled)', severity: r.severity, floor: r.kind === 'catastrophic' }
            : NO_HIT;
        }));
      }

      evaluated++;
      const toolStats = byTool[tool] ?? (byTool[tool] = { evaluated: 0, blocked: 0 });
      toolStats.evaluated++;

      const atMs = nanoToMs(row.startNano);
      if (atMs !== null) {
        if (oldestCallMs === null || atMs < oldestCallMs) oldestCallMs = atMs;
        if (newestCallMs === null || atMs > newestCallMs) newestCallMs = atMs;
      }

      if (!verdict.label) continue;
      toolStats.blocked++;

      const group = verdict.floor ? everyMode : enforceOnly;
      let acc = group.get(verdict.label);
      if (!acc) {
        acc = { label: verdict.label, severity: verdict.severity, count: 0, distinctCalls: 0, examples: [] };
        group.set(verdict.label, acc);
      }
      acc.count++;
      // An example slot is spent only on first sight, so the operator is shown
      // three different commands rather than the same one three times.
      if (firstSight) {
        acc.distinctCalls++;
        if (acc.examples.length < EXAMPLES_PER_RULE) {
          acc.examples.push({ text: exampleText.slice(0, EXAMPLE_MAX_LEN), tool, atMs });
        }
      }
    }
  }

  return {
    fold,
    full: () => candidateRows >= MAX_CANDIDATE_ROWS,
    finish: () => ({
      scanned: {
        candidateRows,
        evaluated,
        distinctCalls: cache.size,
        cacheHitRate: evaluated ? (cacheHits / evaluated) * 100 : 0,
        truncated,
        byTool,
      },
      wouldBlockInEnforce: finishGroup(enforceOnly),
      blocksTodayAnyMode: finishGroup(everyMode),
      oldestCallMs,
      newestCallMs,
    }),
  };
}

/**
 * Fold a whole iterable in one go. The convenience form of an ImpactSession, for
 * callers with the rows already in hand (tests, fixtures) rather than a database
 * to page through.
 */
export function replayImpact(rows: Iterable<ImpactRow>, blockRules: CompiledRule[]): ImpactFold {
  const session = createImpactSession(blockRules);
  session.fold(rows);
  return session.finish();
}

// ── SQL ─────────────────────────────────────────────────────────────────────

// Only rows that can produce a verdict cross the SQLite boundary: the tool test
// is an equality set over json_extract, and the four value columns are pulled out
// in SQL too, so Node never receives — let alone JSON.parses — the attributes
// blob of a span it is going to discard.
//
// Paging is by `rowid` (spans' primary key is a TEXT spanId, so the implicit
// rowid is the stable insert-order cursor). Each page's statement runs to
// completion, which is what frees the shared connection for the ingest path
// between yields — see the header note on why this is not a `.iterate()` stream.
//
// `startNano` is epoch nanoseconds stored as TEXT; the window bound is built the
// way every other route builds it (String(BigInt(ms) * 1_000_000n)), which is a
// fixed 19 digits for any date this decade and so compares correctly as text.
const TOOL_PLACEHOLDERS = IMPACT_TOOLS.map(() => '?').join(', ');
const candidateCallPage = db.prepare(`
  SELECT rowid AS rid,
         json_extract(attributes, '$.tool') AS tool,
         json_extract(attributes, '$.command') AS command,
         COALESCE(
           json_extract(attributes, '$.file_path'),
           json_extract(attributes, '$.path'),
           json_extract(attributes, '$.notebook_path')
         ) AS target,
         json_extract(attributes, '$.url') AS url,
         startNano
  FROM spans
  WHERE rowid > ?
    AND startNano >= ?
    AND json_valid(attributes)
    AND json_extract(attributes, '$.tool') IN (${TOOL_PLACEHOLDERS})
  ORDER BY rowid
  LIMIT ?
`);

/** Hand the event loop a turn between pages. */
const yieldToLoop = (): Promise<void> => new Promise(resolve => { setImmediate(resolve); });

// ── Route ───────────────────────────────────────────────────────────────────

interface CachedReport { report: ImpactReport; expiresAt: number }

export function registerEnforceImpactRoutes(app: Express, _ctx: RouteContext): void {
  // Keyed by window, because that is the only input. Entries are small (a few
  // dozen rules with three examples each), and there are at most a handful of
  // windows the UI offers.
  const memo = new Map<number, CachedReport>();

  // A scan in flight, per window. Two tabs opening the panel at the same moment
  // should share one scan rather than run two multi-second replays side by side.
  const inFlight = new Map<number, Promise<ImpactReport>>();

  async function computeReport(days: number): Promise<ImpactReport> {
    const startedAt = Date.now();
    const sinceMs = startedAt - days * 86_400_000;
    const sinceNano = String(BigInt(sinceMs) * 1_000_000n);

    // Compiled fresh per scan so the preview tracks rule and override edits
    // immediately — an operator who has just demoted a rule wants the new number,
    // not the one cached at boot. It is a single 125 KB JSON parse.
    const blockRules = loadBlockRules();
    const session = createImpactSession(blockRules);

    let cursor = 0;
    let pages = 0;
    for (;;) {
      const page = candidateCallPage.all(cursor, sinceNano, ...IMPACT_TOOLS, PAGE_SIZE) as (ImpactRow & { rid: number })[];
      if (page.length === 0) break;
      pages++;
      cursor = page[page.length - 1].rid;
      session.fold(page);
      if (session.full() || page.length < PAGE_SIZE) break;
      await yieldToLoop();
    }

    const folded = session.finish();
    const caveats = [
      'Edit content is not replayed, so the live-secret (DLP) floor contributes nothing here. Spans are scrubbed at ingest, so the credential shapes that floor matches were already removed.',
      'Home paths are mapped back from the scrubber placeholder for matching, so the protected-path and self-protection floors resolve correctly. Other redactions (tokens, connection strings) remain, so rules keyed on a literal credential under-count.',
      "Verdicts use today's rule set, overrides and protected-path list against past commands. This is a forecast for the current configuration, not a record of what happened at the time.",
      'Only the tool families the PreToolUse hook is registered for are replayed (Bash, Edit/Write/MultiEdit/NotebookEdit, Read, WebFetch/WebSearch). MCP calls through the enforcement proxy are not in this window.',
    ];
    if (folded.scanned.truncated) {
      caveats.unshift(`Scan stopped at ${MAX_CANDIDATE_ROWS.toLocaleString()} candidate calls — the window holds more, so these totals are a floor, not the whole picture.`);
    }

    return {
      ...folded,
      window: { days, sinceMs },
      blockRulesCompiled: blockRules.length,
      // The mode the ENFORCER resolves (file → env → default), not the
      // dashboard's configured toggle: the two can disagree, and the reader needs
      // to know which of the two groups is already in force.
      effectiveMode: resolveMode(),
      timing: { totalMs: Date.now() - startedAt, pages },
      computedAtMs: Date.now(),
      cached: false,
      caveats,
    };
  }

  // GET /api/enforce/impact?days=N
  //
  // Read-only in every sense: it opens no transaction, writes no row, and never
  // touches the enforcement control plane. Safe to call in monitor mode precisely
  // because it changes nothing — the point is to learn the consequence before
  // choosing it.
  app.get('/api/enforce/impact', async (req, res) => {
    const rawDays = Number(req.query.days);
    const days = Number.isFinite(rawDays) && rawDays > 0
      ? Math.min(Math.floor(rawDays), MAX_DAYS)
      : DEFAULT_DAYS;

    const hit = memo.get(days);
    if (hit && hit.expiresAt > Date.now()) {
      res.json({ ...hit.report, cached: true });
      return;
    }

    try {
      let pending = inFlight.get(days);
      if (!pending) {
        pending = computeReport(days).finally(() => inFlight.delete(days));
        inFlight.set(days, pending);
      }
      const report = await pending;
      memo.set(days, { report, expiresAt: Date.now() + REPORT_TTL_MS });
      res.json(report);
    } catch (e) {
      // A preview that fails is an inconvenience, never a protection change —
      // report it plainly rather than letting it surface as an unhandled rejection.
      res.status(500).json({ error: (e as Error).message || 'Impact preview failed' });
    }
  });
}
