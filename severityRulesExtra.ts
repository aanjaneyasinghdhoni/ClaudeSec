// severityRulesExtra.ts
//
// Gated bulk threat-rule expansion for ClaudeSec.
// Rules added here are ReDoS-safe (bounded quantifiers, no catastrophic-
// backtracking patterns) and deduped against the built-in SEVERITY_RULES set
// defined in server.ts.  At runtime, EXTRA_SEVERITY_RULES is spread into the
// tail of SEVERITY_RULES by server.ts so they participate in the same
// first-match-wins detection loop.
//
// Population is managed by scripts/ruleSelfTest.ts-gated generation tooling —
// do NOT import anything from server.ts (it is the app entrypoint, not a
// clean module).

export type ExtraSeverity = 'low' | 'medium' | 'high';

export interface ExtraRule {
  pattern: RegExp;
  severity: ExtraSeverity;
  label: string;
}

export const EXTRA_SEVERITY_RULES: ExtraRule[] = [
  // populated by scripts/ruleSelfTest.ts-gated generation (ReDoS-safe, deduped)
];
