# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ClaudeSec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use one of these methods:

1. **GitHub Security Advisories** (preferred): Go to the [Security tab](https://github.com/aanjaneyasinghdhoni/ClaudeSec/security/advisories) and click "Report a vulnerability".
2. **Email**: Contact the maintainer directly via their GitHub profile.

I will acknowledge your report within **48 hours** and aim to share a status update within **7 days**. For critical issues I target a patch release within **14 days**. That window is deliberately longer than it could be: this is a solo-maintained open-source project, and a date I can actually meet is worth more to you than a shorter one I miss. It is a target, not a contractual SLA. There is no bug-bounty program. I will credit reporters by name (or keep you anonymous on request) in the release notes.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| 1.3.x   | Security fixes only, on request |
| < 1.3   | No        |

---

## Security Posture Statement

As of **2026-08-16**, no CVEs have been reported against ClaudeSec itself. ClaudeSec is a
local-first, single-maintainer open-source project — it has not undergone a third-party
penetration test or formal security audit, and makes no claim of certification.

ClaudeSec is a tool for *observing and detecting* threats in AI coding-agent sessions. It is
not itself an isolated sandbox and carries the limitations any local server does:

- **Authentication** — **reads** over loopback are open and need no credential, so the dashboard
  works the moment it starts. **Mutations** over loopback (changing the enforcement mode, editing
  rules, saving settings) require a control token. A loopback TCP connection carries no user or
  process identity, so nothing in an HTTP request can tell the operator's browser apart from any
  other process on the machine. That is why the token is never handed out in response to a
  request of any shape. It is a 32-byte pairing key generated on first run and stored `0600` at
  `~/.claudesec/hooks/control-token`, inside the self-protected control-plane directory.
  `claudesec open` pairs a browser once by passing that key on the URL; the server exchanges it
  for an `HttpOnly`, `SameSite=Strict` cookie derived from the key by HMAC and redirects the key
  out of the address bar. Scripts may present the key itself as a bearer token, in `x-api-key`,
  or in the `x-claudesec-token` header. Three routes stay open to unauthenticated local
  mutation because their callers are machine clients with nowhere to keep a secret: OTLP ingest
  (`POST /v1/traces`), the MCP tool surface (`POST /mcp`), and the enforcement hook's own
  append-only feed (`POST /api/enforce-log`). Binding a non-loopback interface requires a
  `CLAUDESEC_TOKEN` bearer token on every request; without one the server refuses to start on a
  non-loopback host. `CLAUDESEC_TRUST_LOCAL=1` (the Docker default, safe only with a
  127.0.0.1-published port) disables the whole local check, including the control token.
- **TLS** — the server speaks plain HTTP. For any non-loopback deployment, terminate TLS at a
  reverse proxy before ClaudeSec.
- **Data at rest** — `spans.db` is created with `0600` permissions (owner-only). It is
  unencrypted; protect it with filesystem-level controls appropriate to your threat model.
- **Secret scrubbing** — ClaudeSec redacts known credential shapes (AWS keys, Anthropic/OpenAI
  tokens, private-key PEM blocks, DB connection strings, JWTs, home paths) from every span
  before it is stored, broadcast, or exported. Scrubbing catches known *shapes*, not arbitrary
  free-form text.
- **Threat detection engine** — 671 regex rules. Every one is held to a linear-time execution
  gate by the rule self-test, and custom rules you author are additionally compiled with RE2,
  which rejects backtracking constructs outright. Pattern matching produces false positives. It
  is defence-in-depth, not a guarantee.
- **Audit logs** — the operator audit log, the enforcement block-feed, and the spans ledger are
  append-only and **hash-chained**. Each row's hash is a plain keyless **SHA-256** over its
  canonical content plus the previous row's hash, so a later edit, reordering, or deletion of an
  earlier row breaks every hash after it, and anyone can recompute the chain without holding a
  secret. The boundaries a chain cannot see about itself (how many rows there should be, and
  which row is the last one) live in a small **Ed25519-signed tail anchor** file kept outside the
  database, so a truncated tail and an emptied table are now detected rather than reading as a
  valid short chain. `GET /api/audit/verify` reports `ok`, `row_mismatch`, `truncated`, `wiped`,
  `tail_mismatch`, `anchor_missing`, `anchor_unsigned` or `unanchored` instead of one pass/fail,
  and names the first bad row. The public key is served at `GET /api/audit/public-key`, so a
  third party can verify the record without being able to forge one; the previous HMAC scheme,
  where any verifier necessarily held the forging secret, is retired. Old HMAC rows still verify
  and are counted separately as `legacyHmacRows`, because those are exactly the rows an outside
  verifier cannot check. Retention pruning of the two capped logs **re-anchors** the survivors, so
  it is never mistaken for tampering, and a pruned span leaves a small tombstone carrying its
  chain link. On macOS the private key can optionally be moved into the Keychain
  (`claudesec audit-key to-keychain`); on any platform it can optionally be timestamped by an
  independent notary (see *Optional egress* below). This is tamper-*evident*, not tamper-*proof*,
  and it can never prove **completeness**, because an event that was never written leaves no
  cryptographic residue. A key held on this machine also does not bind this machine's owner: a
  same-user attacker who can read the private key can mint a history that verifies. What the
  signature buys is that a remote or different-UID party cannot.
- **Optional egress** — nothing leaves the machine by default. There are four outbound paths, each
  off unless you set its variable and each passed through the SSRF guard: `OTEL_FORWARD_URL`
  (forward OTLP traces upstream), `CLAUDESEC_WEBHOOK_URL` (alert delivery),
  `CLAUDESEC_JUDGE_URL` (the optional LLM-as-judge, which allows loopback so it can run
  on-device), and `CLAUDESEC_ANCHOR_METHOD=tsa|ots` (audit anchoring, via an RFC 3161 Time-Stamp
  Authority or an OpenTimestamps calendar). The anchoring path sends only a 32-byte SHA-256
  hash: never span content, commands, file paths, or repository names. Two caveats are worth
  knowing before you rely on it. The TSA certificate chain is not validated, and an
  OpenTimestamps `receipted` status means a calendar acknowledged the digest, not that Bitcoin
  confirmed it. The raw receipts are kept so `openssl ts -verify` and the official `ots` client
  can do the layers ClaudeSec does not.

**Relevant upstream CVEs** — two vulnerabilities were disclosed in 2025–2026 against Anthropic's
Claude Code CLI itself (not ClaudeSec), and are relevant context for users of both tools:

- **CVE-2025-59536** (CVSS 8.7, critical) — RCE via malicious `.claude/settings.json` hooks
  that fired before the trust dialog appeared. Fixed in Claude Code v1.0.111. ClaudeSec's hook
  installer (`node cli/init.mjs install-hook`) adds hooks to the *user-global* settings file,
  not to project-level files, and does not execute third-party hooks.
- **CVE-2026-21852** (CVSS 5.3) — API-key exfiltration via `ANTHROPIC_BASE_URL` override in a
  repository's settings file, redirecting authenticated traffic before any trust prompt. Fixed
  in Claude Code v2.0.65. ClaudeSec's own SSRF guard blocks requests to private/loopback ranges
  on all four optional outbound paths (`OTEL_FORWARD_URL`, `CLAUDESEC_WEBHOOK_URL`,
  `CLAUDESEC_JUDGE_URL`, and audit anchoring), and — when the enforcement hook is installed — blocks a Claude Code
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
- Evaluates every span against 671 built-in regex rules to detect suspicious patterns.
- Broadcasts updates to connected browser clients via Socket.io.
- Serves reads to any local caller, and gates every local **mutation** behind a control token
  paired out of band by `claudesec open`.
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

- Regex pattern matching produces false positives and false negatives. The 671 built-in rules
  are a starting point, not an exhaustive threat library.
- The process scanner uses `ps aux` to detect running agents. It is informational only.
- Webhook delivery is best-effort. Do not rely on it for critical alerting without a
  dedicated incident-management system.
- Enforcement (the PreToolUse hook and MCP proxy) is opt-in, Claude-Code-specific (the hook),
  and fail-open. It can be bypassed with `CLAUDESEC_HOOKS_BYPASS=1`; that bypass is now recorded
  (best-effort) in the tamper-evident enforcement feed, so accidental and operational bypasses are
  visible to an operator — though a same-UID attacker who can set the variable can also tamper
  further. The MCP proxy applies the
  *same* floors as the hook (a parity test pins their verdicts), including the SSRF-on-fetch floor
  for fetch-shaped MCP tools, so a non-Claude-Code agent routed through the proxy is also blocked
  from internal/metadata fetches.
- **Same-user (same-UID) ceiling.** ClaudeSec defends against a *misbehaving agent*, not a hostile
  process running as the operator's own account. Mutating the control plane over HTTP alone is
  closed: no request, with any headers, from any client, is answered with a usable token, so a
  prompt-injected agent that can only make HTTP calls is shut out. What is **not** closed is a
  process running as you reading the `0600` pairing key off disk. What changed is the cost and
  the visibility of that attack. It is now a filesystem read of a distinctive path inside the
  self-protected control-plane directory, recorded in the span and command-audit trail like any
  other file access, in a directory the enforcement floor refuses to let anyone **overwrite**.
  Before, it was one unremarkable HTTP request that looked exactly like the dashboard.
  A same-user process that does read the key can still flip the enforcement mode or clear
  user-added protected paths, and can read the audit signing key. The always-on floors
  (catastrophic, self-protection, live-secret, cloud-metadata SSRF, and the default protected
  paths) still hold regardless of mode. Making the key unreadable needs a second OS user; nothing
  at this layer substitutes for that. For that threat model, layer an OS sandbox or a separate
  user account beneath ClaudeSec.

---

## Best Practices

- Run ClaudeSec on `localhost` only, or behind a VPN or firewall with mutual trust.
- Do not expose the dashboard or API to the public internet without adding authentication at
  the network layer (reverse proxy + auth middleware or mTLS).
- Set `CLAUDESEC_TOKEN` and bind a non-loopback host only when you need remote access, and only
  over an authenticated, TLS-terminated channel.
- Protect `spans.db` with filesystem permissions appropriate to your data-classification policy.
- Back up `CLAUDESEC_HOME` (`~/.claudesec` by default) together with the database. It holds the
  audit signing key and the signed tail anchor, and the chain cannot be verified without them, so
  a database backup on its own is not a complete backup of the record.
- Open the dashboard with `claudesec open` rather than a bare bookmark, so the browser is paired
  and settings actually save. Treat a pairing link like a password: it belongs in a terminal or a
  browser, never in a log file, a shell history, or a screenshot.
- Record the audit key's fingerprint (`keyId`, reported by `GET /api/audit/verify`) somewhere off
  this machine. A chain can be re-founded under a fresh key and will then verify perfectly; a
  keyId that changed is the one signal that says so.
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
