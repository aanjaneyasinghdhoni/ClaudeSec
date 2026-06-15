# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ClaudeSec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use one of these methods:

1. **GitHub Security Advisories** (preferred): Go to the [Security tab](https://github.com/aanjaneyasinghdhoni/ClaudeSec/security/advisories) and click "Report a vulnerability".
2. **Email**: Contact the maintainer directly via their GitHub profile.

I will acknowledge your report within **48 hours** and aim to share a status update within **7 days**. For critical issues I'll target a patch release within 14 days, though as a solo-maintained open-source project I cannot guarantee a contractual SLA. There is no bug-bounty program. I will credit reporters by name (or keep you anonymous on request) in the release notes.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes       |
| 1.x (< 1.3) | Security fixes only, on request |
| < 1.0   | No        |

---

## Security Posture Statement

As of **2026-06-15**, no CVEs have been reported against ClaudeSec itself. ClaudeSec is a
local-first, single-maintainer open-source project — it has not undergone a third-party
penetration test or formal security audit, and makes no claim of certification.

ClaudeSec is a tool for *observing and detecting* threats in AI coding-agent sessions. It is
not itself an isolated sandbox and carries the limitations any local server does:

- **Authentication** — loopback traffic is trusted by default. Binding a non-loopback interface
  requires a `CLAUDESEC_TOKEN` bearer token; without one the server refuses to start on a
  non-loopback host.
- **TLS** — the server speaks plain HTTP. For any non-loopback deployment, terminate TLS at a
  reverse proxy before ClaudeSec.
- **Data at rest** — `spans.db` is created with `0600` permissions (owner-only). It is
  unencrypted; protect it with filesystem-level controls appropriate to your threat model.
- **Secret scrubbing** — ClaudeSec redacts known credential shapes (AWS keys, Anthropic/OpenAI
  tokens, private-key PEM blocks, DB connection strings, JWTs, home paths) from every span
  before it is stored, broadcast, or exported. Scrubbing catches known *shapes*, not arbitrary
  free-form text.
- **Threat detection engine** — 639 regex rules, RE2-compiled (linear-time, ReDoS-safe on the
  server path). Pattern matching produces false positives. It is defence-in-depth, not a
  guarantee.
- **Audit logs** — the operator audit log and the enforcement block-feed are append-only and
  **hash-chained**, so a later edit, reordering, or deletion of an earlier row is detectable
  (`GET /api/audit/verify`), and a wholesale wipe is flagged by reset detection. Retention pruning
  **re-anchors** the surviving rows, so it is never mistaken for tampering. An optional local key
  (`~/.claudesec/hooks/audit-key`, under the self-protected hooks dir) signs the chain. This is
  tamper-*evident*, not tamper-*proof* — a same-user attacker who can read the key and recompute the
  whole chain can forge a consistent history, and tail-truncation of the newest rows is a residual
  gap the chain cannot detect on its own.

**Relevant upstream CVEs** — two vulnerabilities were disclosed in 2025–2026 against Anthropic's
Claude Code CLI itself (not ClaudeSec), and are relevant context for users of both tools:

- **CVE-2025-59536** (CVSS 8.7, critical) — RCE via malicious `.claude/settings.json` hooks
  that fired before the trust dialog appeared. Fixed in Claude Code v1.0.111. ClaudeSec's hook
  installer (`node cli/init.mjs install-hook`) adds hooks to the *user-global* settings file,
  not to project-level files, and does not execute third-party hooks.
- **CVE-2026-21852** (CVSS 5.3) — API-key exfiltration via `ANTHROPIC_BASE_URL` override in a
  repository's settings file, redirecting authenticated traffic before any trust prompt. Fixed
  in Claude Code v2.0.65. ClaudeSec's own SSRF guard blocks requests to private/loopback ranges
  on all optional outbound paths (`OTEL_FORWARD_URL`, `CLAUDESEC_WEBHOOK_URL`,
  `CLAUDESEC_JUDGE_URL`), and — when the enforcement hook is installed — blocks a Claude Code
  `WebFetch` to a cloud-metadata / link-local host in either mode (loopback/private ranges in
  `enforce`). The hook matches the literal host, so it does not resolve a public name that points
  at an internal IP (DNS rebinding); the server-side guard, which DNS-resolves every target, covers
  the paths it controls.

---

## Security Model

ClaudeSec is designed as a **local-first** tool. It runs on `localhost` and is intended for
individual developer workstations or internal team networks behind a VPN.

### What ClaudeSec does

- Ingests OTLP traces on `localhost` (default port 3000) and stores them in a local SQLite
  database (`spans.db`).
- Evaluates every span against 639 built-in regex rules to detect suspicious patterns.
- Broadcasts updates to connected browser clients via Socket.io.
- Optionally forwards traces to an upstream OTLP collector (`OTEL_FORWARD_URL`), with
  DNS-resolving SSRF protection that blocks private and loopback destinations.

### What ClaudeSec does NOT do

- **No sandboxing** — the PreToolUse enforcement hook raises the bar for an agent, but it is
  not an OS-level sandbox and fails open by design. A broken hook config never locks you out;
  a bypassed hook allows everything through.
- **No TLS** — terminate TLS at a reverse proxy for any non-loopback deployment.
- **No encryption at rest** — `spans.db` is owner-only (`0600`) but not encrypted.
- **No formal audit** — ClaudeSec has not undergone an independent security review. Use it
  accordingly.

### Known Limitations

- Regex pattern matching produces false positives and false negatives. The 639 built-in rules
  are a starting point, not an exhaustive threat library.
- The process scanner uses `ps aux` to detect running agents. It is informational only.
- Webhook delivery is best-effort. Do not rely on it for critical alerting without a
  dedicated incident-management system.
- Enforcement (the PreToolUse hook and MCP proxy) is opt-in, Claude-Code-specific (the hook),
  and fail-open. It can be bypassed with `CLAUDESEC_HOOKS_BYPASS=1`. The MCP proxy applies the
  *same* floors as the hook (a parity test pins their verdicts), including the SSRF-on-fetch floor
  for fetch-shaped MCP tools, so a non-Claude-Code agent routed through the proxy is also blocked
  from internal/metadata fetches.
- **Same-user (same-UID) ceiling.** ClaudeSec defends against a *misbehaving agent*, not a hostile
  process running as the operator's own account. Because the local API is loopback-trusted (no
  token on localhost), a same-host process could flip the enforcement mode or clear user-added
  protected paths — but the always-on floors (catastrophic, self-protection, live-secret,
  cloud-metadata SSRF, and the default protected paths) still hold regardless of mode. For that
  threat model, layer an OS sandbox or separate user account beneath ClaudeSec.

---

## Best Practices

- Run ClaudeSec on `localhost` only, or behind a VPN or firewall with mutual trust.
- Do not expose the dashboard or API to the public internet without adding authentication at
  the network layer (reverse proxy + auth middleware or mTLS).
- Set `CLAUDESEC_TOKEN` and bind a non-loopback host only when you need remote access, and only
  over an authenticated, TLS-terminated channel.
- Protect `spans.db` with filesystem permissions appropriate to your data-classification policy.
- Keep ClaudeSec updated — rule additions ship in patch releases.
- Review the [Enforcement](/security/enforcement) docs before enabling the PreToolUse hook in
  a shared or CI environment.

---

## Responsible Disclosure

I follow a coordinated disclosure process:

1. Reporter submits vulnerability details privately (GitHub Advisory or email).
2. I confirm receipt within 48 hours and triage the issue.
3. I develop and release a fix, keeping the reporter informed of progress.
4. After a patch is released, I publicly disclose the vulnerability with credit to the reporter
   (or anonymise on request).

Thank you for helping keep ClaudeSec and its users safe.
