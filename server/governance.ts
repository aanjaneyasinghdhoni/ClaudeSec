// server/governance.ts
//
// The AI Governance layer's data model: the policy set as data, plus the pure
// status logic that reads it. `docs/govern/policies.mdx` is the user-facing
// companion — it states what each policy claims and what it deliberately does
// not. No new detection and no new enforcement live here. Every fact
// a Policy reports already exists in `alerts`, `enforce_log`, `rule_overrides`,
// `suppressions` or the retention/scrub config — this module only groups them
// into statements a human can read.
//
// TWO NOUNS, NO THIRD. A Policy is one plain-English sentence backed by a fixed
// list of rule labels that already exist. There is no "Control" — the thing
// that implements a policy is already called a Rule. Framework identifiers
// (NIST subcategories, ISO Annex A controls) are metadata a Policy carries for
// the export to print, never something a user clicks.
//
// STATUS HAS THREE WORDS, NEVER A SCORE. Held / Violated / Not provable — see
// `PolicyStatus` below. "Not provable" is the load-bearing one: it is what
// keeps this page from being the kind of compliance dashboard that shows green
// because it simply was not looking.

import type { Severity } from '../src/shared/types.js';
import { SEVERITY_RULES } from './detection.js';

// ---------------------------------------------------------------------------
// The three-word status vocabulary
// ---------------------------------------------------------------------------

export type PolicyStatus = 'held' | 'violated' | 'not-provable';

/**
 * How a policy's backing rules can act on a match, reusing vocabulary the
 * product already teaches (Rules tab, Enforce tab) rather than inventing new
 * words:
 *   floor    — always-on catastrophic / protected-path / self-protection
 *              floor; blocks in BOTH monitor and enforce mode, once the
 *              opt-in PreToolUse hook is installed.
 *   enforce  — blocks only when the dashboard's mode is set to 'enforce'.
 *   detect   — never blocks; recorded as an alert only.
 *   config   — not a rule at all; a settings state (P11, P12).
 */
export type EnforcementClass = 'floor' | 'enforce' | 'detect' | 'config';

export interface Policy {
  /** Stable id, P1..P12 — referenced by the API, the UI and the export. */
  id: string;
  /** The one plain-English sentence this policy makes a claim about. */
  sentence: string;
  /**
   * The existing rule labels that back this policy. Representative, not
   * exhaustive — the live rule set holds hundreds of entries and a policy's
   * true backing set can be wider. Every label here MUST resolve against the live
   * rule set: `validatePolicyLabels()` is the gate, and `tests/
   * governancePolicyLabelsTest.ts` fails the build the moment one doesn't.
   * Empty for the two configuration policies (P11, P12).
   */
  ruleLabels: string[];
  /** The minimum severity this policy's backing carries. Null for config policies. */
  severityFloor: Severity | null;
  /** The DOMINANT enforcement class — what the coverage row's one word means. */
  enforcement: EnforcementClass;
  /** The nuanced split ("floor for X, enforce for the rest") — shown in the drawer/export. */
  enforcementNote: string;
  /** Where the evidence for this policy comes from, in prose. */
  evidenceDescription: string;
  /** Tags identifying which tables actually back the evidence count. */
  evidenceSources: EvidenceSourceTag[];
  /**
   * What this policy's status does NOT establish, even when it reads Held.
   * Every policy has at least one entry — a policy with nothing here means I
   * have not thought hard enough about it (GOVERNANCE.md §6, the drawer spec).
   */
  doesNotProve: string[];
  /** Framework identifiers this policy contributes to (metadata, never clickable — §1). */
  frameworks: { nist: string[]; iso: string[] };
  /** True for P11/P12: no rule backing, evaluated from config state, kept visibly separate. */
  configPolicy: boolean;
}

export type EvidenceSourceTag =
  | 'alerts' | 'enforce_log' | 'protected_paths' | 'operator_audit_log'
  | 'rule_overrides' | 'suppressions' | 'retention_config' | 'scrub_config'
  | 'chain_verify';

// ---------------------------------------------------------------------------
// Caveats that apply to every policy, not just the ones with something to add
// ---------------------------------------------------------------------------

/**
 * "Held" must never be read as "it did not happen." It means: nothing
 * ClaudeSec observed matched a rule ClaudeSec had enabled, in the window
 * ClaudeSec still holds. Four qualifiers, each independently falsifiable, and
 * each one is why a policy can read Held while the underlying activity still
 * occurred:
 *   1. observed   — an agent that never emitted to ClaudeSec is invisible.
 *   2. matched    — a rule that is disabled or suppressed cannot match.
 *   3. enabled    — the opt-in hook can be uninstalled without anything
 *                   recording that it happened (Phase 4(b) in the design closes this).
 *   4. the window — retention prunes older evidence; a violation before the
 *                   window opened leaves no trace inside it.
 * This is printed on every surface that shows a status word — the UI header,
 * the drawer, and page one of the evidence pack — not buried in a footnote.
 */
export const HELD_MEANS: string =
  'Nothing ClaudeSec observed matched a rule ClaudeSec had enabled, inside the window ClaudeSec still holds. ' +
  'It does not mean the activity did not happen — an unmonitored agent, a disabled or suppressed rule, an ' +
  'uninstalled hook, and a pruned retention window can each make a policy read Held on their own.';

export const NOT_A_SCORE: string =
  'There is no aggregate score and no percentage across these twelve policies, on purpose — an average would ' +
  'hide a catastrophic-floor gap behind a noisy low-severity rule. Read each row on its own.';

export const NOT_CERTIFICATION: string =
  'This is not "ISO 42001 compliant," "NIST AI RMF certified," or "audit-ready." It is one system reporting on ' +
  'itself, mapped against the frameworks it actually touches — see the coverage section of the evidence pack.';

// ---------------------------------------------------------------------------
// Framework identifiers actually claimed — coverage is stated in COMPLIANCE.md
// ---------------------------------------------------------------------------
//
// Only identifiers this layer meaningfully supports are ever assigned to a
// policy below; everything else is named explicitly as a gap so a reviewer
// finds the boundary stated by the tool, not discovered by them.

export const NIST_SUBCATEGORIES_TOTAL = 72;
export const ISO_ANNEX_A_CONTROLS_TOTAL = 38;
export const ISO_MANDATORY_CLAUSES_TOTAL = 7; // clauses 4–10
export const ISO_MANDATORY_CLAUSES_CLAIMED = 0; // no software feature satisfies clauses 4–10 — see §3.

/** Distinct NIST AI RMF subcategories this layer claims, across all twelve policies. */
export const NIST_SUBCATEGORIES_CLAIMED = [
  'MS-2.4', 'MS-3.1', 'MS-3.2', 'MS-4.1', 'MS-4.3', 'MG-2.3', 'MG-3.2', 'MG-3.4', 'MP-1.2', 'MP-1.5',
] as const;

/** Distinct ISO/IEC 42001 Annex A controls this layer claims, across all twelve policies. */
export const ISO_ANNEX_A_CONTROLS_CLAIMED = [
  'A.9.2', 'A.6.2.6', 'A.6.2.8', 'A.9.3', 'A.9.4', 'A.8.4', 'A.10.3',
] as const;

/** What GOVERN looks like from here: almost entirely untouched. Printed verbatim in the pack. */
export const NIST_GOVERN_GAP =
  'Nineteen of the twenty-one GOVERN subcategories are untouched (GV-2.x through GV-6.x — accountability, ' +
  'roles, cross-functional collaboration, escalation, risk tolerance, the regulatory register). GOVERN is ' +
  'people and paper; a runtime observer cannot write it.';

/** The biggest single gap in the whole design — printed on page one of the pack. */
export const BIGGEST_GAP =
  'ClaudeSec watches the shell an agent has on this machine. It has no visibility into the agent’s ' +
  'outputs — whether code is biased, wrong, unsafe, or harmful downstream; whether a human reviewed it; where ' +
  'the model came from. That is ISO 42001 clause 6.1.2 and Annex A.5.2–A.5.5, and NIST MP-3.x/MP-5.x/' +
  'MS-2.2/MS-2.3 — the entire "who is affected and how" axis. This layer covers roughly one axis of a ' +
  'two-axis standard.';

// ---------------------------------------------------------------------------
// The twelve policies
// ---------------------------------------------------------------------------

const RULE_BACKED_NIST_CORE = ['MS-2.4', 'MS-3.1', 'MS-3.2', 'MS-4.1', 'MS-4.3', 'MG-3.2', 'MP-1.2', 'MP-1.5'] as const;
const RULE_BACKED_NIST_WITH_MG23 = [...RULE_BACKED_NIST_CORE, 'MG-2.3'] as const;
const RULE_BACKED_ISO_CORE = ['A.9.2', 'A.6.2.6', 'A.6.2.8', 'A.9.3', 'A.9.4', 'A.8.4'] as const;
const CONFIG_NIST = ['MS-3.1', 'MS-4.1', 'MS-4.3', 'MG-3.2', 'MP-1.2', 'MP-1.5'] as const;
const CONFIG_ISO = ['A.9.2', 'A.6.2.8', 'A.9.3', 'A.9.4'] as const;

export const POLICIES: Policy[] = [
  {
    id: 'P1',
    sentence: 'Agents must not read credential stores.',
    ruleLabels: [
      'AWS credentials file read', 'AWS config file read', 'Kubeconfig access',
      'Netrc credentials file read', 'GCP credentials file read',
      'GCP application-default credentials read', 'GnuPG private keyring access',
      'Browser credential store access', 'Firefox credential store access',
      'npm auth token file read', 'PyPI credentials file read', 'Docker registry auth config read',
      'macOS keychain database read', 'SSH private key access', 'SSH private key file access',
      'Dotenv file read', 'SSH private key read via cat', 'macOS keychain full dump',
      'git credential store query', 'kubeconfig file direct read/copy',
      'GCP gcloud ADC/access-token file read',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'The default protected-paths set (~/.ssh, ~/.aws/credentials, ~/.config/gcloud, ' +
      '~/.kube/config, ~/.npmrc, .env-shaped files) denies read/write/edit/delete in either mode, once the ' +
      'opt-in hook is installed. That default set is user-removable, so status reads the live list, not the defaults.',
    evidenceDescription: 'Alerts for these labels (matchedText carries the secret’s shape, scrubbed, never ' +
      'the value); enforce_log rows with blocked=1; the live protected-paths list; ' +
      'protected-path.create/protected-path.delete entries in the operator audit log, proving nobody quietly removed a guard mid-period.',
    evidenceSources: ['alerts', 'enforce_log', 'protected_paths', 'operator_audit_log'],
    doesNotProve: [
      'The protected-paths floor only blocks once the opt-in PreToolUse hook is installed — detection (the ' +
      'alert) does not depend on the hook, but the block does.',
      'The default protected-paths set is user-removable; a status of Held on a machine with an emptied list ' +
      'is true but hollow.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P2',
    sentence: 'Credentials must never leave this machine.',
    ruleLabels: [
      'Environment credential sent in request body', 'AWS credentials file piped to network sink',
      'SSH private key / PEM piped to network sink', 'API key literal in curl POST to external host',
      '.env file rsync to remote host', 'credential file base64-piped to curl/wget',
      'private key PEM in curl POST body', 'Python reads credential file then POSTs to network',
      '.env file read piped to network sink', 'curl upload of SSH private key / PEM',
      'curl exfil of .env file', 'curl upload of ~/.ssh content',
    ],
    severityFloor: 'critical',
    enforcement: 'floor',
    enforcementNote: 'floor for the two high-precision read-and-send patterns; enforce (blocks only in enforce ' +
      'mode) for the rest of this critical tier.',
    evidenceDescription: 'Critical alerts; honeytoken firings, the cleanest possible exfiltration proof since a ' +
      'honeytoken has no legitimate reader; enforce_log blocks.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'Blocking is opt-in, fails open, and is bypassable with an env var — a seatbelt, not a cage.',
      'Egress that happens outside the agent’s own tool calls (a background process, a compromised MCP ' +
      'server acting independently) is not observed.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P3',
    sentence: 'No destructive commands against the system or its data.',
    ruleLabels: [
      'Recursive root deletion', 'Home directory deletion', 'rm with --no-preserve-root flag', 'Fork bomb',
      'mkfs format on block device', 'dd zero-wipe raw disk', 'Redirect output to raw block device',
      'Disk device wipe via dd', 'SQL DROP DATABASE statement', 'SQL DELETE with always-true WHERE (full wipe)',
      'Redis FLUSHALL via CLI', 'MongoDB dropDatabase() call', 'Cassandra DROP KEYSPACE',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'floor for the catastrophic subset (the same set tests/catastrophic-parity.test.ts pins); ' +
      'enforce for the database-destruction tail.',
    evidenceDescription: 'enforce_log rows carrying mode, label and the scrubbed command; alerts for the rest. ' +
      'This is the strongest evidence in the set — a block produces a row saying the action did NOT happen.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'Only the catastrophic subset is on the always-on floor; the database-destruction tail blocks only in enforce mode.',
      'A destructive command issued through a path this rule set does not pattern-match (a novel tool, a ' +
      'compiled binary) leaves no alert.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P4',
    sentence: 'Agents must not execute code fetched from the network.',
    ruleLabels: [
      'Remote code execution via curl', 'Remote code execution via wget', 'curl pipe to shell',
      'wget pipe to bash', 'Download-then-execute chain', 'Clone-and-execute',
      'PowerShell IEX wrapping download', 'mshta remote script execution', 'regsvr32 COM scriptlet from URL',
      'certutil urlcache download', 'base64 decode pipe to shell', 'python one-liner download and exec',
      'node -e requiring remote module URL',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'floor for curl|sh and its direct shell-pipe variants; enforce for the rest.',
    evidenceDescription: 'Alerts plus enforce_log blocks for these labels.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'A download-then-execute chain split across two separate, unlinked tool calls may not pattern-match as one event.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P5',
    sentence: 'Dependencies come only from trusted registries.',
    ruleLabels: [
      'Supply-chain: custom PyPI index', 'Supply-chain: npm registry override',
      'npm install from raw HTTP/S URL', 'npm install from git+http(s) URL',
      'scoped npm package from non-official registry (dependency confusion)',
      'package-lock resolved URL from non-official registry (lockfile tamper)',
      'yarn.lock entry with non-official registry URL', 'postinstall/preinstall script piping to shell',
      'gem install from raw URL', 'pip install from untrusted index URL',
      'pip install of version 0.0.x package (possible dependency confusion probe)',
    ],
    severityFloor: 'high',
    enforcement: 'enforce',
    enforcementNote: 'enforce only. None of this is on the always-on floor — a false block here breaks every ' +
      'developer’s day.',
    evidenceDescription: 'Alerts; the MCP/skill supply-chain scanner report for the agent’s own tool set.',
    evidenceSources: ['alerts'],
    doesNotProve: [
      'This proves an agent did not FETCH from an untrusted source. It proves nothing about the integrity of ' +
      'packages fetched from trusted ones — no SBOM, no signature verification, no provenance.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_CORE], iso: [...RULE_BACKED_ISO_CORE, 'A.10.3'] },
    configPolicy: false,
  },
  {
    id: 'P6',
    sentence: 'Agents must not establish persistence or escalate privilege.',
    ruleLabels: [
      'Crontab modification', 'cron spool append for persistence', 'macOS LaunchAgent manipulation',
      'LaunchAgent plist dropped (macOS persistence)', 'LaunchDaemon plist dropped (macOS persistence)',
      'SSH authorized_keys append (backdoor)', 'root SSH authorized_keys append',
      'sudoers NOPASSWD append via echo', 'sudoers file modification', '/etc/passwd append (backdoor user)',
      'LD_PRELOAD shared-library injection', 'kernel module loaded via insmod',
      '/etc/ld.so.preload backdoor append', 'systemd service enable+start (persistence)',
      '.bashrc backdoor append', '.zshrc backdoor append', 'setuid bit set on file',
      'Privilege escalation via group add', 'ptrace ATTACH (process injection)',
      'direct /proc/PID/mem access (process memory write)',
    ],
    severityFloor: 'high',
    enforcement: 'enforce',
    enforcementNote: 'enforce.',
    evidenceDescription: 'Alerts plus enforce_log blocks for these labels.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'Persistence mechanisms outside this list (a novel init system, a container escape) are not covered.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_CORE], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P7',
    sentence: 'Agents must not open outbound control channels.',
    ruleLabels: [
      'Bash TCP reverse shell', 'bash reverse shell via /dev/tcp', '/dev/udp reverse shell redirect',
      'netcat reverse shell with -e exec', 'socat exec reverse shell', 'python reverse shell one-liner',
      'PowerShell TCPClient reverse shell', 'Cobalt Strike beacon artifact', 'Sliver C2 framework',
      'Havoc C2 framework reference', 'C2 beacon URL in span', 'SSH reverse/dynamic port forward',
      'Metasploit multi/handler reverse shell',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'floor for nc -e and the /dev/tcp + shell forms; enforce for the rest.',
    evidenceDescription: 'Alerts plus enforce_log blocks for these labels.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'A C2 channel using a protocol or framework not in this list (a private beacon, a novel transport) is not caught.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P8',
    sentence: 'Internal networks and cloud metadata are out of bounds.',
    ruleLabels: [
      'Cloud IMDS IP (169.254.169.254) accessed', 'AWS IMDSv2 IPv6 endpoint accessed',
      'GCP metadata server accessed', 'Azure IMDS internal endpoint accessed',
      'IMDS IAM credential endpoint queried', 'RFC-1918 metadata SSRF probe',
      'RFC-1918 10.x metadata SSRF probe', 'nmap network/port scan', 'masscan high-speed port scan',
      'bash loop internal port sweep via /dev/tcp',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'floor for a WebFetch to a metadata / link-local address; enforce for loopback and ' +
      'private ranges (opt-out via CLAUDESEC_ALLOW_LOCAL_FETCH).',
    evidenceDescription: 'Alerts plus enforce_log blocks for these labels.',
    evidenceSources: ['alerts', 'enforce_log'],
    doesNotProve: [
      'A public hostname that resolves to an internal IP (DNS rebinding) is not caught by the synchronous hook.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_CORE], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P9',
    sentence: 'Untrusted content must not redirect the agent.',
    ruleLabels: [
      'Prompt injection: instruction override', 'Prompt injection: HTML comment directive',
      'Prompt injection: fake system prompt', 'system-prompt extraction request',
      'repeat-everything-above extraction', 'instruction smuggling via [system] tag',
      'instruction smuggling via <system> tag', 'base64-encoded instruction smuggling',
      'ROT13-encoded instruction smuggling', 'tool-result injection: ASSISTANT persona override',
      'exfiltration-via-injection: send conversation', 'Llama [INST] prompt injection',
      'DAN jailbreak attempt', 'bypass-safety-filters jailbreak',
    ],
    severityFloor: 'high',
    enforcement: 'detect',
    enforcementNote: 'detect only — never blocks.',
    evidenceDescription: 'Alerts, and the span each one attaches to, so what document carried the payload stays visible.',
    evidenceSources: ['alerts'],
    doesNotProve: [
      'This is the weakest policy in the set. Regex catches naive and copy-pasted injection. It does not catch ' +
      'a competent adversary, semantic paraphrase, or an injection carried in an image or a non-Latin script. ' +
      'This policy proves I am looking; it does not prove I am safe.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_CORE], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P10',
    sentence: 'Agents must not touch the security control plane.',
    ruleLabels: [
      'Shell history clear command', 'Delete bash history file', 'Overwrite system log file',
      'Null-out system log via cat redirect',
    ],
    severityFloor: 'high',
    enforcement: 'floor',
    enforcementNote: 'floor — blocks in either mode, always. Also covers the self-protection floor (any agent ' +
      'write to ~/.claudesec/hooks/ or the Claude Code settings that register the hook, at home or project ' +
      'scope) — a mechanism, not a regex rule label, so it is not counted in ruleLabels but is included in the evidence below.',
    evidenceDescription: 'enforce_log blocks; plus operator_audit_log entries for enforce.config, rule.disable, ' +
      'rule.disable.rejected, enforce.override.rejected, protected-path.delete, suppression.create, ' +
      'retention.set, webhook.set; plus the result of GET /api/audit/verify for every chain. This is the ' +
      'policy that guards the other eleven — if P10 is violated, the rest of the pack is worth less, and the ' +
      'pack says so explicitly rather than reporting P10 as one row of twelve.',
    evidenceSources: ['enforce_log', 'operator_audit_log', 'chain_verify'],
    doesNotProve: [
      'If P10 is violated, treat every other policy’s Held status with proportionally less confidence — ' +
      'the guard that would have proven the rest was itself bypassed.',
      'The self-protection floor is a file-write guard, not a rule label, so it does not appear in the alerts count above.',
    ],
    frameworks: { nist: [...RULE_BACKED_NIST_WITH_MG23], iso: [...RULE_BACKED_ISO_CORE] },
    configPolicy: false,
  },
  {
    id: 'P11',
    sentence: 'Recorded activity is kept for the stated window, and no longer.',
    ruleLabels: [],
    severityFloor: null,
    enforcement: 'config',
    enforcementNote: 'config — backed by getRetentionDays()/getMaxSpans() and the automatic prune, not a rule.',
    evidenceDescription: 'The configured window; the EFFECTIVE window (the timestamp of the oldest surviving ' +
      'span — this is the number that matters, not the configured one); retention.set audit entries; the audit ' +
      'chain’s re-anchor markers, which distinguish legitimate pruning from tampering.',
    evidenceSources: ['retention_config', 'operator_audit_log'],
    doesNotProve: [
      'A configured window is not a proven window. The count cap (CLAUDESEC_MAX_SPANS) can silently prune far ' +
      'sooner than the day-based window promises, and this policy exists specifically to catch that gap.',
    ],
    frameworks: { nist: [...CONFIG_NIST], iso: [...CONFIG_ISO] },
    configPolicy: true,
  },
  {
    id: 'P12',
    sentence: 'Recorded activity stays on this machine, with secrets redacted before storage.',
    ruleLabels: [],
    severityFloor: null,
    enforcement: 'config',
    enforcementNote: 'config — backed by server/scrub.ts (on by default), the bind address, the 0600 DB file ' +
      'mode, and the three optional egress sinks being unset.',
    evidenceDescription: 'Scrub state (CLAUDESEC_DISABLE_SCRUB unset); bind host; DB file mode; the list of ' +
      'configured sinks (OTEL_FORWARD_URL, CLAUDESEC_WEBHOOK_URL, CLAUDESEC_JUDGE_URL); webhook.set/webhook.delete audit entries.',
    evidenceSources: ['scrub_config', 'operator_audit_log'],
    doesNotProve: [
      'Scrubbing is best-effort pattern matching, not a guarantee — a secret shape it does not recognize passes through.',
      'The database is not encrypted at rest. Both caveats are already in COMPLIANCE.md §4 and repeat here on purpose.',
    ],
    frameworks: { nist: [...CONFIG_NIST], iso: [...CONFIG_ISO] },
    configPolicy: true,
  },
];

// ---------------------------------------------------------------------------
// Task 1's gate: every referenced rule label must resolve against the live set
// ---------------------------------------------------------------------------

/**
 * Cross-check every policy's `ruleLabels` against the live rule set
 * (SEVERITY_RULES = core + EXTRA). A policy that cites a label
 * no rule carries anymore is worse than no policy — it would silently zero
 * out that portion of the pack the moment a rule gets renamed. Called at
 * server start (fail loudly, not silently) and by
 * `tests/governancePolicyLabelsTest.ts` on every run.
 */
export function validatePolicyLabels(): { policyId: string; missing: string[] }[] {
  const live = new Set(SEVERITY_RULES.map(r => r.label));
  const problems: { policyId: string; missing: string[] }[] = [];
  for (const policy of POLICIES) {
    const missing = policy.ruleLabels.filter(label => !live.has(label));
    if (missing.length > 0) problems.push({ policyId: policy.id, missing });
  }
  return problems;
}

/** Look up a policy by id, or undefined if the id is unrecognised. */
export function getPolicy(id: string): Policy | undefined {
  return POLICIES.find(p => p.id === id);
}

// ---------------------------------------------------------------------------
// Status derivation — pure functions, no DB access, so they're unit-testable
// without a database. The route layer (server/routes/governance.ts) does the
// querying and hands the counts in.
// ---------------------------------------------------------------------------

export interface PolicyCounts {
  /** Alerts for this policy's rule labels in the window, excluding confirmed false positives. */
  alerts: number;
  /** enforce_log rows with blocked=1 for this policy's rule labels in the window. */
  blocked: number;
  /** Which of this policy's rule labels are currently disabled via rule_overrides. */
  disabledRuleLabels: string[];
  /** Which of this policy's rule labels currently sit under an active suppression. */
  suppressedRuleLabels: string[];
}

export interface CoverageInfo {
  hookInstalled: 'yes' | 'no' | 'unknown';
  /** Age in days of the oldest surviving span. Null when there is no data at all. */
  effectiveWindowDays: number | null;
  /** The period the caller asked for, in days. */
  requestedWindowDays: number;
}

export interface StatusResult {
  status: PolicyStatus;
  /** Why the status is Not provable. Empty for Held and Violated. */
  reasons: string[];
}

/** Status derivation for the ten rule-backed policies (P1–P10). */
export function derivePolicyStatus(policy: Policy, counts: PolicyCounts, coverage: CoverageInfo): StatusResult {
  if (policy.configPolicy) {
    throw new Error(`derivePolicyStatus is for rule-backed policies; ${policy.id} is a configuration policy — use deriveRetentionStatus/deriveLocalOnlyStatus`);
  }

  // A match is a match, and outranks a coverage caveat: a violation found
  // inside a partially-covered window is still a genuine violation, even if
  // the pack must separately disclose that the window wasn't fully covered.
  if (counts.alerts > 0 || counts.blocked > 0) {
    return { status: 'violated', reasons: [] };
  }

  const reasons: string[] = [];

  if (counts.disabledRuleLabels.length > 0) {
    reasons.push(`${counts.disabledRuleLabels.length} of ${policy.ruleLabels.length} backing rule(s) disabled: ${counts.disabledRuleLabels.join(', ')}`);
  }
  if (counts.suppressedRuleLabels.length > 0) {
    reasons.push(`${counts.suppressedRuleLabels.length} backing rule(s) currently suppressed: ${counts.suppressedRuleLabels.join(', ')}`);
  }

  // The blocking half of a floor/enforce policy needs the opt-in hook. If it
  // is not installed, "nothing matched" cannot distinguish "nothing happened"
  // from "nothing was watching the block path" — Held would overclaim.
  const hookMatters = policy.enforcement === 'floor' || policy.enforcement === 'enforce';
  if (hookMatters && coverage.hookInstalled !== 'yes') {
    reasons.push(
      coverage.hookInstalled === 'no'
        ? 'the PreToolUse hook is not installed, so the blocking half of this policy could not have run'
        : 'hook registration could not be determined from inside this environment',
    );
  }

  if (coverage.effectiveWindowDays == null) {
    reasons.push('no spans are retained at all — there is nothing to check this policy against');
  } else if (coverage.effectiveWindowDays < coverage.requestedWindowDays) {
    reasons.push(`retained data only covers ${coverage.effectiveWindowDays} of the requested ${coverage.requestedWindowDays} day(s)`);
  }

  if (policy.ruleLabels.length === 0) {
    reasons.push('this policy has no rule backing');
  }

  return reasons.length > 0 ? { status: 'not-provable', reasons } : { status: 'held', reasons: [] };
}

export interface RetentionCoverage {
  configuredDays: number;
  /** The real, measured age of the oldest surviving span. Null = no data yet. */
  effectiveDays: number | null;
}

/** Status derivation for P11 (retention). A silent shortfall is a violation, not a caveat — it is the exact failure this policy exists to catch. */
export function deriveRetentionStatus(coverage: RetentionCoverage): StatusResult {
  if (coverage.effectiveDays == null) {
    return { status: 'not-provable', reasons: ['no spans are retained yet, so the effective window cannot be measured'] };
  }
  // 5% slack absorbs rounding at the measurement boundary without hiding a real shortfall.
  if (coverage.effectiveDays < coverage.configuredDays * 0.95) {
    return {
      status: 'violated',
      reasons: [`configured to keep ${coverage.configuredDays} days; the count cap is actually holding only ${coverage.effectiveDays}`],
    };
  }
  return { status: 'held', reasons: [] };
}

export interface LocalOnlyCoverage {
  scrubEnabled: boolean;
  /** Any of OTEL_FORWARD_URL / CLAUDESEC_WEBHOOK_URL / CLAUDESEC_JUDGE_URL that are currently set. */
  configuredSinks: string[];
  /** The DB file's POSIX mode, or null if it could not be statted. */
  dbFileMode: number | null;
}

/** Status derivation for P12 (local-only + scrubbing). */
export function deriveLocalOnlyStatus(coverage: LocalOnlyCoverage): StatusResult {
  if (!coverage.scrubEnabled) {
    return { status: 'violated', reasons: ['secret scrubbing is disabled (CLAUDESEC_DISABLE_SCRUB=1)'] };
  }
  if (coverage.configuredSinks.length > 0) {
    return { status: 'violated', reasons: [`egress sink(s) configured: ${coverage.configuredSinks.join(', ')}`] };
  }
  const reasons: string[] = [];
  if (coverage.dbFileMode == null) {
    reasons.push('could not read the database file’s permission bits');
  } else if ((coverage.dbFileMode & 0o077) !== 0) {
    return {
      status: 'violated',
      reasons: [`database file permissions are ${(coverage.dbFileMode & 0o777).toString(8).padStart(3, '0')}, not the expected 600`],
    };
  }
  return reasons.length > 0 ? { status: 'not-provable', reasons } : { status: 'held', reasons: [] };
}
