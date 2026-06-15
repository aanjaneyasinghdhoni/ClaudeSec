import type { Request } from 'express';
import type { Server } from 'socket.io';
import type { Severity } from '../../src/shared/types.js';
import type { DetectFn } from '../mcpScan.js';

/** Per-model token pricing (owned by index.ts). */
export interface ModelPricing {
  inputPer1M: number;
  outputPer1M: number;
  label: string;
}

/** Session health-score breakdown (owned by index.ts). */
export interface HealthBreakdown {
  score:   number;
  grade:   'A' | 'B' | 'C' | 'D' | 'F';
  threatHigh:   number;
  threatMedium: number;
  threatLow:    number;
  alertCount:   number;
}

export interface RouteContext {
  io: Server;
  /** Released app version from package.json (owned by index.ts). */
  appVersion?: string;
  /** Invalidate the in-memory suppressed-rule-keys cache (owned by index.ts). */
  invalidateSuppressedCache?: () => void;
  /** Invalidate the in-memory disabled-rule-labels cache (owned by index.ts). */
  invalidateDisabledRulesCache?: () => void;
  /** Record a config-mutating action in the operator audit log (owned by index.ts). */
  auditLog?: (req: Request, action: string, target: string, detail?: unknown) => void;
  /** Effective max-span capacity (owned by index.ts). */
  getMaxSpans?: () => number;
  /** Effective age-based retention window in days (owned by index.ts). */
  getRetentionDays?: () => number;
  /** Prune spans by age + count, returning what was removed (owned by index.ts). */
  pruneSpans?: () => { prunedByAge: number; prunedByCount: number };
  /** Build the current span graph for a Socket.io broadcast (owned by index.ts). */
  buildGraph?: (sessionFilter?: string) => unknown;
  /** Look up token pricing for a model name, or null if unknown (owned by index.ts). */
  lookupPricing?: (model: string) => ModelPricing | null;
  /** The full per-model pricing table (owned by index.ts). */
  MODEL_PRICING?: Record<string, ModelPricing>;
  /** Pure health formula over raw severity/alert counts (owned by index.ts). */
  healthFromCounts?: (h: number, m: number, l: number, alertCount: number) => HealthBreakdown;
  /** Compute a session's health score by traceId (owned by index.ts). */
  computeHealthScore?: (traceId: string) => HealthBreakdown;
  /** Snapshot of the current custom-rule list (owned by index.ts; read by detectSeverity). */
  getCustomRules?: () => CustomRule[];
  /** Append a custom rule and persist it (owned by index.ts). */
  addCustomRule?: (rule: CustomRule) => void;
  /** Remove a custom rule by id, returning true if one was removed (owned by index.ts). */
  removeCustomRule?: (id: string) => boolean;
  /** Snapshot of the user's protected-path list (owned by index.ts). */
  getProtectedPaths?: () => ProtectedPath[];
  /** Append a protected path, persist it, and re-mirror the hook artifact (owned by index.ts). */
  addProtectedPath?: (entry: ProtectedPath) => void;
  /** Remove a protected path by id, returning true if one was removed (owned by index.ts). */
  removeProtectedPath?: (id: string) => boolean;
  /** Current honeytoken list (owned by index.ts). */
  getHoneytokens?: () => string[];
  /** Persist honeytokens and rebuild scrubOptions (owned by index.ts). */
  saveHoneytokens?: (tokens: string[]) => void;
  /** Clear honeytokens from config and rebuild scrubOptions (owned by index.ts). */
  clearHoneytokens?: () => void;
  /** The shared severity detector (owned by index.ts; injected into the MCP/skill scanner). */
  detectSeverity?: DetectFn;
  /** Whether inline scrubbing is currently enabled (reads live scrubOptions; owned by index.ts). */
  getScrubEnabled?: () => boolean;
  /** Effective webhook URL (env override > DB config; owned by index.ts). */
  getWebhookUrl?: () => string;
  /** Effective minimum severity for webhook delivery (owned by index.ts). */
  getWebhookThreshold?: () => Severity;
  /** Mask a webhook URL down to its origin for safe UI display (owned by index.ts). */
  maskWebhookUrl?: (url: string) => string;
  /** Deliver an alert to the configured webhook, honouring threshold + SSRF guard (owned by index.ts). */
  fireWebhook?: (alert: {
    ruleLabel: string;
    severity: Severity;
    harness: string;
    spanName: string;
    matchedText: string;
    traceId: string;
  }) => Promise<void>;
  /** Scrub free-form enforcement-log text (home paths, secrets) using the live
   *  scrubOptions; honours CLAUDESEC_DISABLE_SCRUB, same as the span pipeline
   *  (owned by index.ts). */
  scrubEnforceText?: (s: string) => string;
  /** Append an enforcement-log event to the in-memory ring buffer (owned by index.ts). */
  appendEnforceLog?: (evt: EnforceLogEvent) => void;
  /** Read the most-recent N enforcement-log events, newest first (owned by index.ts). */
  readEnforceLog?: (limit: number) => EnforceLogEvent[];
  /** Total number of buffered enforcement-log events (owned by index.ts). */
  enforceLogCount?: () => number;
  /** Max enforcement-log ring-buffer capacity (owned by index.ts). */
  enforceLogMax?: number;
  /** Current effective enforcement mode (owned by index.ts). */
  getEnforceMode?: () => string;
  /** Current per-rule enforcement overrides (owned by index.ts). */
  getEnforceOverrides?: () => Record<string, 'alert' | 'block'>;
  /** Persist enforcement config + mirror it to the hook's config file (owned by index.ts). */
  writeEnforceConfigFile?: () => void;
  /** Path to the mirrored enforce-config.json the hook reads (owned by index.ts). */
  enforceConfigFile?: string;
}

/** Enforcement-log event (PreToolUse hook feed; owned by index.ts). */
export interface EnforceLogEvent {
  ts: number;
  mode: string;
  label: string;
  severity: string;
  command: string;
  wouldBlock: boolean;
}

/**
 * A user-added protected path: an always-on, per-user block-list entry that the
 * PreToolUse hook enforces regardless of monitor/enforce mode (owned by
 * index.ts; mirrored to protected-paths.json beside the installed hook).
 */
export interface ProtectedPath {
  id: string;
  /** Literal path string the hook substring-matches against (e.g. '~/.ssh/id_rsa'). */
  path: string;
  /** Human-friendly label shown in the block message + feed. */
  label: string;
  createdAt: string;
}

/** Custom (user-defined) severity rule (owned by index.ts; read by detectSeverity). */
export interface CustomRule {
  id: string;
  pattern: string;
  flags: string;
  severity: Severity;
  label: string;
  createdAt: string;
}
