/**
 * enforceStatus.ts — honest read-only status for the Enforce tab.
 *
 * The Enforce tab must not show a comforting green when nothing can actually be
 * blocked. Two truths are easy to get wrong and this module surfaces both:
 *
 *   1. EFFECTIVE MODE + its SOURCE. The configured toggle in the dashboard is not
 *      necessarily what the hook runs. The hook resolves mode with a fixed
 *      precedence (enforce-config.json `mode` → CLAUDESEC_MODE env → 'monitor'),
 *      so an operator who sets CLAUDESEC_MODE=enforce can still be running monitor
 *      because the config file wins. We mirror that precedence EXACTLY (see
 *      enforceEval.resolveMode) and report which layer won.
 *
 *   2. HOOK REGISTRATION. None of the above matters if no PreToolUse hook is
 *      registered in the user's Claude Code settings — then the dashboard can
 *      neither block nor observe tool calls via the hook. We look for a
 *      PreToolUse entry whose command runs claudesec-enforce.cjs across the three
 *      settings scopes Claude Code reads (user / project / project-local).
 *
 * Everything here is READ-ONLY and FAIL-SAFE: any read or parse error for a scope
 * counts as "not found for that scope" and never throws out of the caller. Inside
 * a container the host's settings aren't visible, so hook detection returns
 * 'unknown' rather than a misleading 'no'.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveConfigPath } from './enforceEval.js';

export type EnforceMode = 'monitor' | 'enforce';
export type ModeSource = 'config-file' | 'env' | 'default';
export type HookInstalled = 'yes' | 'no' | 'unknown';

/**
 * The substring that identifies our hook command in a settings entry.
 * Exported so the test suite can assert it matches the installer's copy —
 * a test-level parity check is the right tool here (keeping server/ free of
 * any runtime dependency on cli/, same pattern as the catastrophic-parity test).
 */
export const HOOK_FILENAME = 'claudesec-enforce.cjs';

export interface EffectiveModeResolution {
  /** The mode the hook will actually use. */
  effectiveMode: EnforceMode;
  /** Which precedence layer supplied it. */
  modeSource: ModeSource;
}

export interface HookStatus {
  installed: HookInstalled;
  /** Where a matching PreToolUse entry was found, e.g. ['user','project-local']. */
  scopes: string[];
}

/**
 * Resolve the effective enforcement mode the SAME way the hook does
 * (enforceEval.resolveMode) AND report which layer won. Kept structurally
 * parallel to resolveMode so the two cannot drift: config-file is accepted only
 * when it is exactly 'monitor'|'enforce'; otherwise env (same strict accept);
 * otherwise the 'monitor' default. A garbage value at any layer falls through —
 * it never resolves to 'enforce'.
 */
export function resolveEffectiveMode(): EffectiveModeResolution {
  try {
    const cfg = JSON.parse(fs.readFileSync(resolveConfigPath(), 'utf8'));
    if (cfg && (cfg.mode === 'enforce' || cfg.mode === 'monitor')) {
      return { effectiveMode: cfg.mode, modeSource: 'config-file' };
    }
  } catch {
    /* missing / unreadable / malformed → fall through to env */
  }
  const env = process.env.CLAUDESEC_MODE;
  if (env === 'enforce' || env === 'monitor') {
    return { effectiveMode: env, modeSource: 'env' };
  }
  return { effectiveMode: 'monitor', modeSource: 'default' };
}

/**
 * Running inside a container? Then host Claude Code settings aren't visible.
 *
 * Detection is Docker-only (presence of /.dockerenv) by design: it is the one
 * reliable, cross-platform signal available without root or extra tooling.
 * Non-Docker runtimes (Podman rootless, nspawn, etc.) will report false here,
 * which means they proceed to the normal file-based hook scan — if the host
 * settings aren't mounted, that scan returns 'no' rather than 'unknown'.
 * Erring toward 'no' is the safe direction: the Enforce tab will show the
 * "no hook registered" warning rather than silently suppressing it.
 */
function inContainer(): boolean {
  try {
    return fs.existsSync('/.dockerenv');
  } catch {
    return false;
  }
}

/** The user-settings path, honoring the same override the installer uses. */
function userSettingsPath(): string {
  return (
    process.env.CLAUDESEC_CLAUDE_SETTINGS ??
    path.join(os.homedir(), '.claude', 'settings.json')
  );
}

/**
 * Does this settings file carry a PreToolUse entry that runs our hook?
 * Fail-safe: a missing / unreadable / malformed file, or any unexpected shape,
 * counts as "not present" and never throws.
 */
function settingsHasOurHook(file: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return false; // absent / unreadable / not JSON → treat as not found
  }
  const pre = (parsed as { hooks?: { PreToolUse?: unknown } } | null)?.hooks?.PreToolUse;
  if (!Array.isArray(pre)) return false;
  for (const entry of pre) {
    const hooks = (entry as { hooks?: unknown })?.hooks;
    if (!Array.isArray(hooks)) continue;
    for (const h of hooks) {
      const cmd = (h as { command?: unknown })?.command;
      if (typeof cmd === 'string' && cmd.includes(HOOK_FILENAME)) return true;
    }
  }
  return false;
}

/**
 * Detect whether the PreToolUse enforcement hook is registered, and in which
 * scopes. Checks the three settings files Claude Code reads, in its own
 * precedence order:
 *   • user          → ~/.claude/settings.json (override: CLAUDESEC_CLAUDE_SETTINGS)
 *   • project        → ./.claude/settings.json (relative to cwd)
 *   • project-local  → ./.claude/settings.local.json
 *
 * Inside a container the host's settings can't be seen, so we return 'unknown'
 * rather than a misleading 'no' — host data simply isn't mounted there.
 */
export function detectHookStatus(cwd: string = process.cwd()): HookStatus {
  if (inContainer()) return { installed: 'unknown', scopes: [] };

  const candidates: { scope: string; file: string }[] = [
    { scope: 'user', file: userSettingsPath() },
    { scope: 'project', file: path.join(cwd, '.claude', 'settings.json') },
    { scope: 'project-local', file: path.join(cwd, '.claude', 'settings.local.json') },
  ];

  const scopes: string[] = [];
  for (const c of candidates) {
    if (settingsHasOurHook(c.file)) scopes.push(c.scope);
  }
  return { installed: scopes.length > 0 ? 'yes' : 'no', scopes };
}
