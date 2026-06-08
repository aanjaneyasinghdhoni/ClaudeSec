# Changelog

All notable changes to ClaudeSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Isolated demo container — an on-demand container, pre-seeded with synthetic
  data on its own database volume, for showing ClaudeSec without exposing real
  telemetry. Start it with `./start.sh --demo` (or
  `docker compose --profile demo up`): prod stays on `:3000` with your real data,
  and the demo runs on `:3001` (override with `DEMO_PORT`) seeded with three
  synthetic sessions that fire real detection rules. The demo container is
  physically isolated from prod — its own `claudesec-demo-data` volume, no in-app
  toggle, no per-row tagging.
- `COMPLIANCE.md` — a compliance and controls mapping that relates ClaudeSec's
  detection, enforcement, and local-first hardening features to common security
  control frameworks, so teams can reason about where the tool fits in their
  existing posture.
- Project governance and release-process documentation (`.github/GOVERNANCE.md`
  and `.github/RELEASING.md`) describing roles, decision-making, and how versioned
  releases are cut.

### Changed

- Rewrote the Docker deployment section of the README to match
  `docker-compose.yml`: the host port is published on `127.0.0.1` only, and the
  bundled `CLAUDESEC_TRUST_LOCAL=1` lets the local browser dashboard reach the API
  without a token. Documented the compose lifecycle, the persistent
  `claudesec-data` volume, and how to harden the deployment (set a `CLAUDESEC_TOKEN`
  and move the port binding off loopback) before exposing it to a network.

## [1.0.0] - 2026-06-08

First production-ready public release. ClaudeSec is a zero-config, fully-local
security observatory for AI coding agents: it watches the sessions already running
on your machine, surfaces what those agents are actually doing, and scores every
tool call, command, and file access against a built-in threat-detection engine —
without anything leaving your computer.

### Added

- Real-time local observability for Claude Code, GitHub Copilot CLI, and Codex.
  A zero-config transcript watcher tails each agent's on-disk session transcripts
  live — no environment variables and no agent restart — so activity streams into
  the dashboard the moment any session does something, including sessions that were
  already running.
- Live timeline and orchestration views with nanosecond-precision durations,
  per-agent tool inventory, command-audit trail, sensitive-file-access panel, and a
  threat-activity heatmap.
- Approximately 630 built-in threat-detection rules across HIGH / MEDIUM / LOW
  severities, covering prompt injection, credential theft, reverse shells and C2,
  supply-chain attacks, data exfiltration, cloud-metadata SSRF, container escape,
  crypto-mining, privilege escalation, and reconnaissance. Rules are evaluated on
  every ingested span and patterns are compiled with RE2 for linear-time,
  ReDoS-safe matching.
- A rule self-test gate (`pnpm test`) that enforces ReDoS heuristics, a ReDoS
  execution gate, deduplication, and a false-positive check; the `prebuild` script
  runs it first, so a ReDoS-prone or duplicate rule fails the build.
- Custom rule CRUD via the dashboard and REST API, with rule suppressions, alert
  deduplication via fingerprinting, alert triage, and an immutable alert log.
- Enforcement that can stop a tool call before it runs: an opt-in Claude Code
  PreToolUse hook that blocks high-severity tool calls, and a cross-agent MCP
  enforcement proxy that gates `tools/call` for any MCP-speaking agent over stdio.
  Both default to `monitor` mode (log would-blocks, forward normally); `enforce`
  mode actively denies. The server is the source of truth for mode and per-rule
  overrides, toggled from the Enforce dashboard tab.
- MCP / skill static scanner (`GET /api/mcp-scan`) that read-only scans installed
  MCP server configs and skill files for tool-poisoning, prompt-injection in
  descriptions, hardcoded secrets, and suspicious launch commands. It never
  launches a server or writes a file.
- MCP server at `POST /mcp` exposing tools for AI-to-AI interaction (health,
  sessions, spans, alerts, search, tagging, bookmarking, processes, and incident
  summaries).
- Optional, off-by-default LLM-as-judge semantic detection. Set
  `CLAUDESEC_JUDGE_URL` to any OpenAI-compatible endpoint (for example a local
  Ollama or LM Studio instance) to score flagged spans on-demand; zero network
  calls are made unless explicitly configured.
- OTLP/HTTP-JSON ingestion at `POST /v1/traces` so agents running in containers,
  on other machines, or in CI can stream into the same detection-and-storage
  pipeline as the local watcher.
- Transparent OTLP forwarding to an upstream collector via `OTEL_FORWARD_URL`.
- Prometheus metrics at `GET /metrics` and a health endpoint at `GET /api/health`.
- Token cost view with API-equivalent pricing per session and model, with
  subscription-plan awareness.
- Webhook delivery of HIGH-severity alerts to Slack, Discord, or any JSON endpoint,
  with a configurable severity threshold.
- Honeytokens: planted canary strings that fire a HIGH-severity exfiltration alert
  on any matching span.
- Process scanner that detects running agent CLIs and can kill, pause, or resume
  them from the dashboard.
- Bookmarks, tags, annotations, session labels, and free-text notes for triage.
- Hourly auto-export of spans, alerts, and sessions to `exports/` (last 24 kept).
- Bundled CLI (`claudesec`) for installing a background service, tailing live
  spans, searching, ranking sessions, exporting, and generating session reports.
- Responsive dashboard (React 19 + Tailwind CSS 4) with a drawer sidebar, bottom
  tab bar, four built-in themes, and keyboard/ARIA accessibility.
- In-app MDX documentation site (Diátaxis structure) and a complete OpenAPI 3.0.3
  specification (`openapi.yaml`).

### Security

- Local-first by construction: the server binds `127.0.0.1` (loopback) by default
  and refuses to bind a non-loopback host without a `CLAUDESEC_TOKEN` bearer token.
- No egress by default. The only optional outbound paths — `OTEL_FORWARD_URL` and
  the opt-in `CLAUDESEC_JUDGE_URL` — are both off unless set, and both pass through
  an SSRF guard that blocks loopback, private, and cloud-metadata IP ranges,
  re-checked on every retry to defeat DNS rebinding.
- Secret scrubbing on by default: known secret shapes (keys, tokens, credentials,
  home paths, usernames, emails) are redacted before anything is stored, broadcast,
  or exported.
- The SQLite database (`spans.db`) is created with `0600` (owner-only) permissions.
- The data-wipe endpoint is disabled unless `CLAUDESEC_ALLOW_RESET=1` is explicitly
  set; `helmet` and `cors` middleware and configurable rate limiting protect the
  ingestion endpoint.

### Deployment

- pnpm-based zero-config dev and build path (Node.js >= 22.13.0, pnpm managed via
  corepack) bringing up the full live dashboard with no environment variables.
- Production-ready multi-stage Dockerfile and a `docker-compose.yml` suited to
  headless or server deployments, with the host port bound to loopback and a
  required bearer token for non-loopback access.

### License

- Released under the [AGPL-3.0-only](LICENSE) license. Commercial and
  dual-licensing options are documented in [`.github/LICENSING.md`](.github/LICENSING.md).

[Unreleased]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.0.0
