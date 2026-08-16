/**
 * Retention profiles — the two retention knobs, set as one coherent policy.
 *
 * ── Why profiles instead of two free numbers ──
 * Retention has never been one setting. `CLAUDESEC_RETENTION_DAYS` states how
 * far back you keep data; `CLAUDESEC_MAX_SPANS` states how much data the
 * database will hold. Those two numbers only mean what they say when they agree
 * with each other, and the shipped defaults did not:
 *
 *   183 days × a real ingest rate of ~3,500 spans/day = ~650,000 spans in the
 *   window, against a 50,000-span capacity ceiling.
 *
 * Pruning itself is safe — count-based pruning may only reclaim spans that are
 * ALREADY past the age cutoff, so the day cap is a hard floor that the count cap
 * can never undercut. The damage lands somewhere less obvious: OTLP ingestion
 * has a capacity circuit breaker that returns 503 at 90% of the span ceiling.
 * With a ceiling below the window's own volume, nothing can ever be pruned to
 * relieve it, so the breaker latches on around day 13 and never reopens. The
 * install that was promised six months of logs quietly stops recording after two
 * weeks — not by deleting anything, but by refusing to accept anything more.
 *
 * A profile sets both numbers together so that outcome is unreachable by
 * construction: every named profile's ceiling is sized so the breaker cannot
 * fire before its own window closes.
 *
 * ── Where the numbers come from ──
 * Sized against real usage rather than round figures — 269,386 spans over a
 * 76-day period on a working install, i.e. ~3,545 spans/day sustained (trailing
 * 30 days: ~2,350/day; trailing 7 days: ~4,450/day; busiest single day: 15,785)
 * at ~2.7 KB of database per span. Each profile below states the ingest rate it
 * holds for, so the promise is checkable rather than asserted.
 */

/** Sentinel for "no limit". Used for both knobs; 0 means unbounded, not zero. */
export const RETENTION_UNBOUNDED = 0;

/**
 * Fraction of the span ceiling at which OTLP ingestion trips its circuit breaker
 * (server/index.ts). Profile sizing has to respect this: usable capacity is 90%
 * of the ceiling, not 100%.
 */
export const INGEST_BREAKER_RATIO = 0.9;

/** Rough on-disk cost of one span, including its FTS index entry (measured). */
export const BYTES_PER_SPAN = 2_700;

export type RetentionProfileId = 'minimum' | 'audit-year' | 'forensic' | 'custom';

export interface RetentionProfile {
  id: RetentionProfileId;
  label: string;
  /** Age window in days; RETENTION_UNBOUNDED for "never prune by age". */
  days: number;
  /** Span ceiling; RETENTION_UNBOUNDED for "no ceiling". */
  maxSpans: number;
  /** One-line description, shown wherever retention is reported. */
  summary: string;
}

/**
 * The named profiles. `custom` is not listed — it is what you get when the two
 * numbers do not match any profile, which is a legitimate choice as long as the
 * interaction is reported honestly (see describeRetention).
 */
export const RETENTION_PROFILES: Record<Exclude<RetentionProfileId, 'custom'>, RetentionProfile> = {
  minimum: {
    id: 'minimum',
    label: 'Minimum',
    days: 183,
    maxSpans: 1_000_000,
    // 183 days is the six-month log-retention period the EU AI Act Art. 26(6)
    // expects of a deployer. The ceiling is what makes that period real: at
    // ~3,545 spans/day the window holds ~649,000 spans, so a 1,000,000 ceiling
    // (900,000 usable before the breaker) keeps ingesting for the full 183 days
    // at any rate up to ~4,900 spans/day — above this install's busiest week.
    // Costs roughly 1.8 GB of disk at that rate.
    summary: 'Six-month window sized to keep ingesting the whole way through (~1.8 GB at a typical rate).',
  },
  'audit-year': {
    id: 'audit-year',
    label: 'Audit year',
    days: 400,
    maxSpans: 5_000_000,
    // A year plus a ~35-day tail, so an auditor who samples "day one of the
    // period" 12 months later still finds it instead of missing it by a week.
    // 400 days holds ~1.42M spans at the observed rate; the 5,000,000 ceiling
    // (4.5M usable) covers rates up to ~11,250 spans/day. Budget ~4 GB.
    summary: 'A year plus a 35-day tail, so day one of the period is still there at audit time (~4 GB).',
  },
  forensic: {
    id: 'forensic',
    label: 'Forensic',
    days: RETENTION_UNBOUNDED,
    maxSpans: RETENTION_UNBOUNDED,
    // Nothing is ever pruned and the ingest breaker is disabled. Growth is
    // bounded only by the disk, which is the point — and the risk.
    summary: 'Keep everything, prune nothing. Growth is bounded only by free disk space.',
  },
};

/** The profile a fresh install starts on. */
export const DEFAULT_RETENTION_PROFILE_ID: RetentionProfileId = 'minimum';
export const DEFAULT_RETENTION_DAYS = RETENTION_PROFILES.minimum.days;
export const DEFAULT_MAX_SPANS = RETENTION_PROFILES.minimum.maxSpans;

/** Look up a named profile, or null for an unknown / custom id. */
export function retentionProfile(id: string): RetentionProfile | null {
  return (RETENTION_PROFILES as Record<string, RetentionProfile>)[id] ?? null;
}

/**
 * Which profile a given pair of numbers represents. An existing install that
 * happens to sit exactly on a profile is reported as that profile; anything else
 * is `custom` — we never round someone's configuration to a nearby profile.
 */
export function identifyProfile(retentionDays: number, maxSpans: number): RetentionProfileId {
  for (const p of Object.values(RETENTION_PROFILES)) {
    if (p.days === retentionDays && p.maxSpans === maxSpans) return p.id;
  }
  return 'custom';
}

/** Where an effective value came from. Env silently outranks the UI, so we say so. */
export type RetentionSource = 'env' | 'config' | 'default';

/**
 * Parse one retention value from env or config.
 *
 * 0 is a real value meaning "unbounded", not "unset". The old `Number(x) > 0`
 * test folded 0 back into the default, so a user who set
 * `CLAUDESEC_RETENTION_DAYS=0` to mean "never prune" silently got six months.
 * Returns null for absent / malformed input so the caller falls through.
 */
export function parseRetentionValue(raw: string | undefined | null): number | null {
  if (raw === undefined || raw === null || String(raw).trim() === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/** Read a single knob with the documented precedence: env → stored config → profile default. */
export function resolveKnob(
  envValue: string | undefined,
  configValue: string | undefined,
  fallback: number,
): { value: number; source: RetentionSource } {
  const fromEnv = parseRetentionValue(envValue);
  if (fromEnv !== null) return { value: fromEnv, source: 'env' };
  const fromConfig = parseRetentionValue(configValue);
  if (fromConfig !== null) return { value: fromConfig, source: 'config' };
  return { value: fallback, source: 'default' };
}

/** Minimal shape of a better-sqlite3 handle — keeps this module DB-library-free. */
export interface SpanRateSource {
  prepare(sql: string): { get(...params: unknown[]): unknown };
}

export interface ObservedRate {
  /** Spans per day, or null when there is not enough history to say. */
  spansPerDay: number | null;
  /** Days of history the rate was measured over. */
  sampleDays: number;
  /** Spans counted in that sample. */
  sampleSpans: number;
}

/**
 * Measure the install's own ingest rate from the spans table.
 *
 * Prefers the trailing 14 days, because retention questions are about what
 * happens next, not about a quiet month in the past. Falls back to the whole
 * table when the recent sample is too thin to mean anything, and returns null
 * rather than guessing on a nearly-empty database — an estimate nobody can
 * stand behind is worse than no estimate.
 */
export function observedSpansPerDay(db: SpanRateSource, now: number = Date.now()): ObservedRate {
  const MIN_SAMPLE_SPANS = 100;
  // startNano is a Unix-epoch nanosecond timestamp stored as text. Rows that
  // never carried a real timestamp land on 0 and would drag the range back to
  // 1970, so only rows after ~2001 (1e18 ns) are eligible.
  const FLOOR_NANO = '1000000000000000000';

  const sample = (sinceNano: string | null): { c: number; mn: number | null; mx: number | null } => {
    const where = sinceNano
      ? `CAST(startNano AS INTEGER) > CAST(? AS INTEGER)`
      : `CAST(startNano AS INTEGER) > CAST(${FLOOR_NANO} AS INTEGER)`;
    const row = db.prepare(
      `SELECT COUNT(*) AS c,
              MIN(CAST(startNano AS INTEGER)) AS mn,
              MAX(CAST(startNano AS INTEGER)) AS mx
         FROM spans WHERE ${where}`,
    ).get(...(sinceNano ? [sinceNano] : [])) as { c: number; mn: number | null; mx: number | null };
    return row;
  };

  const recentCutoff = String((now - 14 * 86_400_000) * 1e6);
  let row = sample(recentCutoff);
  if (row.c < MIN_SAMPLE_SPANS) row = sample(null);

  if (row.c < MIN_SAMPLE_SPANS || row.mn === null || row.mx === null) {
    return { spansPerDay: null, sampleDays: 0, sampleSpans: row.c ?? 0 };
  }

  // A sample shorter than a day still tells us something, but dividing by it
  // extrapolates a burst into a permanent rate. Floor the divisor at one day.
  const spanDays = Math.max(1, (row.mx - row.mn) / 86_400_000 / 1e6);
  return {
    spansPerDay: Math.round(row.c / spanDays),
    sampleDays: Math.round(spanDays * 10) / 10,
    sampleSpans: row.c,
  };
}

export interface EffectiveRetention {
  profile: RetentionProfileId;
  profileLabel: string;
  /** Configured age window; null when unbounded. */
  retentionDays: number | null;
  /** Configured span ceiling; null when unbounded. */
  maxSpans: number | null;
  /** Measured ingest rate the estimate is based on; null when unknown. */
  spansPerDay: number | null;
  /** Spans the age window would hold at that rate; null when unknown/unbounded. */
  projectedSpansInWindow: number | null;
  /** Span count at which OTLP ingestion trips its breaker; null when unbounded. */
  ingestStopsAtSpans: number | null;
  /** Days until the breaker trips at the measured rate; null when unknown. */
  ingestStopsAfterDays: number | null;
  /** Which limit governs what you actually end up with. */
  limitingFactor: 'age' | 'capacity' | 'none' | 'unknown';
  /**
   * The window the install really delivers, in days — the smaller of the age
   * window and the day the capacity ceiling stops ingestion. Null when
   * unbounded or unknown.
   */
  effectiveWindowDays: number | null;
  /** Rough disk footprint of a full window; null when unbounded/unknown. */
  estimatedBytes: number | null;
  /** Set when the two knobs disagree — the sentence a user needs to read. */
  warning: string | null;
}

/**
 * Report what a retention configuration actually delivers, rather than what its
 * two numbers claim in isolation.
 *
 * The whole point is the `capacity` case: when the span ceiling is smaller than
 * the age window's own volume, the age window is fiction. Pruning cannot save
 * it (count-based pruning may only touch out-of-window rows), so ingestion stops
 * at 90% of the ceiling and the effective window is however many days it took to
 * get there.
 */
export function describeRetention(input: {
  retentionDays: number;
  maxSpans: number;
  spansPerDay: number | null;
}): EffectiveRetention {
  const { retentionDays, maxSpans } = input;
  const spansPerDay = input.spansPerDay && input.spansPerDay > 0 ? input.spansPerDay : null;

  const ageUnbounded   = retentionDays === RETENTION_UNBOUNDED;
  const countUnbounded = maxSpans === RETENTION_UNBOUNDED;
  const profile = identifyProfile(retentionDays, maxSpans);
  const named = retentionProfile(profile);

  const ingestStopsAtSpans = countUnbounded ? null : Math.floor(maxSpans * INGEST_BREAKER_RATIO);
  const ingestStopsAfterDays =
    ingestStopsAtSpans !== null && spansPerDay ? Math.floor(ingestStopsAtSpans / spansPerDay) : null;
  const projectedSpansInWindow =
    !ageUnbounded && spansPerDay ? Math.round(retentionDays * spansPerDay) : null;

  let limitingFactor: EffectiveRetention['limitingFactor'];
  let effectiveWindowDays: number | null;
  let warning: string | null = null;

  if (ageUnbounded && countUnbounded) {
    limitingFactor = 'none';
    effectiveWindowDays = null;
  } else if (spansPerDay === null) {
    // No measured rate yet — say so instead of inventing a window.
    limitingFactor = 'unknown';
    effectiveWindowDays = ageUnbounded ? null : retentionDays;
  } else if (ingestStopsAfterDays !== null && (ageUnbounded || ingestStopsAfterDays < retentionDays)) {
    limitingFactor = 'capacity';
    effectiveWindowDays = ingestStopsAfterDays;
    const needed = Math.ceil(((ageUnbounded ? 0 : retentionDays) * spansPerDay) / INGEST_BREAKER_RATIO);
    warning = ageUnbounded
      ? `Age-based pruning is off but the span ceiling is ${maxSpans.toLocaleString()}. At ${spansPerDay.toLocaleString()} spans/day, ingestion stops after about ${ingestStopsAfterDays} days and nothing can be pruned to restart it. Use the Forensic profile to remove the ceiling too.`
      : `This keeps about ${effectiveWindowDays} days, not ${retentionDays}. At ${spansPerDay.toLocaleString()} spans/day the ${retentionDays}-day window holds about ${projectedSpansInWindow!.toLocaleString()} spans, but ingestion stops at ${ingestStopsAtSpans!.toLocaleString()} (90% of the ${maxSpans.toLocaleString()}-span ceiling) and pruning cannot free in-window data. Raise the ceiling to at least ${needed.toLocaleString()} spans, or pick a profile.`;
  } else {
    limitingFactor = 'age';
    effectiveWindowDays = ageUnbounded ? null : retentionDays;
  }

  const estimatedBytes =
    effectiveWindowDays !== null && spansPerDay
      ? Math.round(effectiveWindowDays * spansPerDay * BYTES_PER_SPAN)
      : null;

  return {
    profile,
    profileLabel: named ? named.label : 'Custom',
    retentionDays: ageUnbounded ? null : retentionDays,
    maxSpans: countUnbounded ? null : maxSpans,
    spansPerDay,
    projectedSpansInWindow,
    ingestStopsAtSpans,
    ingestStopsAfterDays,
    limitingFactor,
    effectiveWindowDays,
    estimatedBytes,
    warning,
  };
}

export interface ResolvedRetention extends EffectiveRetention {
  /** The raw effective numbers, with 0 still meaning unbounded. */
  configured: { retentionDays: number; maxSpans: number };
  sources: { retentionDays: RetentionSource; maxSpans: RetentionSource };
  /** Set when an env var is silently overriding a value saved from the dashboard. */
  envOverride: string | null;
}

/**
 * Cached ingest rate, per database handle.
 *
 * Measuring the rate is a covering-index scan of the spans table — ~7 ms on a
 * 270,000-span database and linear from there. The dashboard polls the endpoints
 * that report retention, so without a cache that scan runs on every poll for a
 * number that barely moves. A 30-second TTL keeps the reading honest and the
 * polling free. Keyed weakly so a test's throwaway handle can be collected.
 */
const _rateCache = new WeakMap<SpanRateSource, { rate: ObservedRate; at: number }>();
const RATE_TTL_MS = 30_000;

function cachedSpansPerDay(db: SpanRateSource, now: number): ObservedRate {
  const hit = _rateCache.get(db);
  if (hit && now - hit.at < RATE_TTL_MS) return hit.rate;
  const rate = observedSpansPerDay(db, now);
  _rateCache.set(db, { rate, at: now });
  return rate;
}

/**
 * The one place retention is resolved and explained: precedence, profile
 * identity, the measured ingest rate, and the window the install really
 * delivers. Both the server and the /api/db-stats route call this so the
 * dashboard and the runtime can never disagree about what is configured.
 */
export function resolveRetention(deps: {
  env: Record<string, string | undefined>;
  readConfig: (key: string) => string | undefined;
  db: SpanRateSource;
  now?: number;
}): ResolvedRetention {
  const days = resolveKnob(
    deps.env.CLAUDESEC_RETENTION_DAYS,
    deps.readConfig('retention.days'),
    DEFAULT_RETENTION_DAYS,
  );
  const spans = resolveKnob(
    deps.env.CLAUDESEC_MAX_SPANS,
    deps.readConfig('retention.max_spans'),
    DEFAULT_MAX_SPANS,
  );
  const { spansPerDay } = cachedSpansPerDay(deps.db, deps.now ?? Date.now());

  // An env var that shadows a saved dashboard value is invisible in the UI: the
  // field shows what was saved while the server runs on something else. Name it.
  const shadowed: string[] = [];
  if (days.source === 'env' && parseRetentionValue(deps.readConfig('retention.days')) !== null) {
    shadowed.push('CLAUDESEC_RETENTION_DAYS');
  }
  if (spans.source === 'env' && parseRetentionValue(deps.readConfig('retention.max_spans')) !== null) {
    shadowed.push('CLAUDESEC_MAX_SPANS');
  }

  return {
    ...describeRetention({ retentionDays: days.value, maxSpans: spans.value, spansPerDay }),
    configured: { retentionDays: days.value, maxSpans: spans.value },
    sources: { retentionDays: days.source, maxSpans: spans.source },
    envOverride: shadowed.length
      ? `${shadowed.join(' and ')} ${shadowed.length === 1 ? 'is' : 'are'} set in the environment and ${shadowed.length === 1 ? 'overrides' : 'override'} the value saved from the dashboard. Unset ${shadowed.length === 1 ? 'it' : 'them'} for the saved setting to take effect.`
      : null,
  };
}
