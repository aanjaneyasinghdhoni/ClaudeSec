# Changelog

All notable changes to ClaudeSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The container image failed to build from a version tag: the Docker build
  context excluded `cli/`, but the build's test gate checks
  `cli/hooks/claudesec-enforce.cjs` for catastrophic-rule parity and fails
  hard when it is missing. The build context now includes `cli/`. The
  runtime image is unchanged — the CLI still does not ship in the container.

### Security

- The Docker build context now excludes all hidden files and directories, so
  VCS, CI, editor, and local tool state can never reach an image layer.

## [1.2.0] - 2026-06-10

### Added

- A `critical` severity tier — a new highest level above `high`, reserved for
  active secret **exfiltration**: a credential, private key, or `.env` being
  transmitted off the machine (piped to `curl`/`wget`/`nc`, `scp`/`rsync`/`sftp`
  to a remote, posted via `requests`, or a key literal in a POST body). A secret
  merely *present* in a file stays `high`; transmission is what escalates to
  `critical`. Sixteen existing transmission rules were promoted and nine new
  exfiltration rules added (25 critical rules total). Critical alerts render with
  a distinct rose badge and are blocked alongside `high` in `enforce` mode.
- Database connection-string scrubbing — inline `user:password@` credentials in
  `mongodb://`, `postgres://`/`postgresql://`, `mysql://`, and `redis://` URLs are
  now redacted before persistence, so a dumped `.env` no longer stores live DB
  passwords. As with every alert, `critical` exfiltration alerts store only the
  scrubbed/redacted matched text — never the live secret.
- One-command enforcement hook install — `node cli/init.mjs install-hook` builds
  the rules snapshot locally from the repo's rule source (no network), copies the
  dependency-free PreToolUse hook to `~/.claudesec/hooks/`, and registers it in
  `~/.claude/settings.json`. Consent is mandatory: the installer prints the exact
  JSON it will write and asks before touching anything, backs up the previous
  settings file, and is idempotent on re-run. `uninstall-hook` removes only
  ClaudeSec's entries; `--purge` also deletes the installed files.
- An honest Enforce tab. It now reports three distinct facts — the configured
  mode, the effective mode the hook actually runs (with which precedence layer
  won: `enforce-config.json` → `CLAUDESEC_MODE` → default), and whether the hook
  is registered in any Claude Code settings scope. Green is reserved for the one
  case where blocking is real: enforce effective *and* a hook registered.
  A missing hook or an env var silently overridden by the config file shows a
  loud warning instead of a false green.
- Blocked tool calls now appear in the Enforce feed. Previously only
  monitor-mode "would block" events were reported; a real block wrote its denial
  to the terminal and exited without telling the server. Blocks are logged
  before the hook exits — a slow or failed report can never turn a block into an
  allow — and the feed distinguishes *blocked* from *would block*.
- URL routing for the whole dashboard — every view is a real URL
  (`#/<category>/<tab>` for tabs, `#/docs/<slug>` for docs), so a refresh
  restores the exact view, back/forward work, and any tab can be deep-linked.
  Existing docs links keep working.
- A local operator audit log that records every config-mutating action
  (scrubbed and size-capped, exposed through a read-only API), plus per-rule
  toggles to disable individual detection rules — except the catastrophic
  floor, which can never be turned off.
- Session navigation from the orchestration spawn tree — clicking a spawned
  agent jumps straight to its session timeline.
- File-access drill-down — rows group by folder and repository, tool and file
  rows open a span-detail drawer, and the 100-row display cap is gone.

### Fixed

- Costs no longer double-count. API usage is keyed on the message id and
  deduped at query time, so transcript lines that repeat the same API response
  are counted once; harness token totals share the same basis, and demo traces
  are excluded from aggregates.
- False-positive alerts are kept out of the default alert list and the nav
  badge, dismissing a grouped alert covers all of its duplicates, and dismissal
  has a short undo window.
- `./start.sh` builds and serves the production app instead of starting a dev
  server, so the dashboard you open is the real production bundle. The build
  runs on-device from in-repo source with no network fetch.
- Docs navigation: switching tabs while reading docs now actually leaves the
  docs view and clears the stale `#/docs/...` URL, docs gained a breadcrumb and
  back button, and the nav rail stays in sync when jumping to a session from
  the Processes or Bookmarks views.
- The installed hook path is quoted — a space in `$HOME` would otherwise split
  the command and, because the hook fails open, silently disable enforcement.
  NotebookEdit cell content is now inspected like every other editing tool.
- `/api/health`, `/api/export`, and the MCP server report the released version
  read from `package.json` instead of a hardcoded string.

### Performance

- Dashboard queries (costs, heatmap, orchestration, metrics) aggregate in SQL
  instead of loading every span into memory, backed by new composite indexes;
  MCP search routes through the full-text index; socket-triggered refetches are
  debounced and redundant graph layouts skipped, so event bursts no longer
  stampede the dashboard.

### Changed

- The README now leads with the one-command start and links to the in-app docs
  for everything else, instead of duplicating them.

## [1.1.0] - 2026-06-09

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
- Cost tracking for Claude Fable 5, priced at its published rates ($10 / 1M input,
  $50 / 1M output). Prompt-cache tokens are derived from the input rate, so cache
  reads and writes are costed automatically. Spans from Fable 5 sessions now show
  real costs instead of `$0`.

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

[Unreleased]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.2.0
[1.1.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.1.0
[1.0.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.0.0
