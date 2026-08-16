/**
 * enforcementSnapshot.ts — single source of truth for the rules-enforcement.json
 * snapshot the PreToolUse hook (and the MCP-proxy sibling enforceEval.ts) read.
 *
 * The snapshot is a flat array of { source, flags, severity, label, action }:
 *   action = 'block'  for severity 'high' or 'critical'  (the two top tiers block)
 *   action = 'alert'  for everything else                (monitor / detect only)
 *
 * Built-in rules come from SEVERITY_RULES (server/detection.ts). User-added
 * custom rules follow the SAME convention — a high/critical custom rule blocks in
 * enforce mode, exactly like a built-in of that severity; lower severities stay
 * detect-only. Keeping one builder here guarantees the install-time generator
 * (scripts/build-enforcement-rules.ts) and the live server can never disagree on
 * the built-in portion of the snapshot.
 */

import { SEVERITY_RULES } from './detection.js';

export interface EnforcementRule {
  source: string;
  flags: string;
  severity: string;
  label: string;
  action: 'block' | 'alert';
}

/** A custom rule carries its pattern as a string (the server compiles/validates it). */
export interface CustomRuleInput {
  pattern: string;
  flags?: string;
  severity: string;
  label: string;
}

/** The hook blocks the two top tiers; everything else is alert-only. */
function actionForSeverity(severity: string): 'block' | 'alert' {
  return severity === 'high' || severity === 'critical' ? 'block' : 'alert';
}

/** Built-in detection rules → enforcement entries. */
export function builtinEnforcementRules(): EnforcementRule[] {
  return SEVERITY_RULES.map((r) => ({
    source: r.pattern.source,
    flags: r.pattern.flags,
    severity: r.severity,
    label: r.label,
    action: actionForSeverity(r.severity),
  }));
}

/** User-added custom rules → enforcement entries (same block convention). */
export function customEnforcementRules(custom: CustomRuleInput[]): EnforcementRule[] {
  return custom.map((r) => ({
    source: r.pattern,
    // Default to case-insensitive to match how the server compiles custom rules.
    flags: typeof r.flags === 'string' ? r.flags : 'i',
    severity: r.severity,
    label: r.label,
    action: actionForSeverity(r.severity),
  }));
}

/**
 * The full snapshot the hook reads: built-ins first, then custom rules. Passing
 * no custom rules yields exactly the built-in-only snapshot (the install-time
 * default), so the generator and the server share one code path.
 */
export function buildEnforcementSnapshot(custom: CustomRuleInput[] = []): EnforcementRule[] {
  return [...builtinEnforcementRules(), ...customEnforcementRules(custom)];
}
