# Changelog

All notable changes to ClaudeSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-07

First production-ready release. Complete local AI agent observatory with multi-harness
OTLP ingestion, real-time threat detection, and interactive visualization.

### Added

#### Core Infrastructure
- Express + Socket.io backend (`server.ts`) with OTLP/HTTP JSON ingestion at `POST /v1/traces`
- SQLite persistence via `better-sqlite3` (spans, sessions, alerts, config tables)
- Vite 6 + React 19 + Tailwind CSS 4 frontend
- Auto-layout via Dagre for the interactive ReactFlow span graph
- Two-process dev mode: Vite HMR proxied through the Express server

#### Multi-Harness Support
- Harness detection registry (`src/harnesses.ts`) covering 10 agent frameworks:
  Claude Code, GitHub Copilot, OpenHands, Cursor, Aider, Cline, Goose, Continue.dev, Windsurf, and Unknown
- Automatic harness identification from `service.name` / `telemetry.sdk.name` resource attributes
- Per-harness colored root nodes in the graph
- Interactive CLI setup wizard (`npx claudesec init` / `npm run init`)

#### Observatory Features
- Live span graph with ReactFlow — nodes color-coded by threat severity
- Gantt-style timeline view with BigInt nanosecond precision
- Session isolation: each traceId becomes a named session with inline rename
- Span search with `key=value` attribute filter syntax
- Severity filter chips (All / Normal / Malicious)
- Per-harness filter chips when multiple agents are active
- Live metrics: input tokens, output tokens, tool calls, avg latency

#### Agent Orchestration
- Orchestration tab with SVG agent DAG showing inter-agent edges
- Sub-agent spawn tree: detects cross-trace parent-child span relationships
- Tool inventory with table and heatmap grid views (tool × harness matrix)
- Suspicious tool flagging (bash, eval, exec, curl, etc.)

#### Security Engine
- 31 built-in threat detection rules across HIGH / MEDIUM / LOW severities:
  - HIGH: `rm -rf /`, passwd read, curl|sh, wget|sh, SQL DROP/TRUNCATE, eval/exec injection,
    prompt injection (3 patterns), AWS/GitHub/OpenAI secret patterns,
    supply-chain (custom PyPI/npm registry, clone-and-execute), TCP reverse shell
  - MEDIUM: process.env, .env files, SSH key manipulation, /etc/shadow|hosts|sudoers,
    base64 decode, SSH dir access, macOS keychain, Python one-liner
  - LOW: SELECT *, world-executable chmod, sudo, global npm install, pip install
- Custom rule CRUD via dashboard UI and REST API (saved to `rules.json`)
- Immutable alert log (SQLite `alerts` table) with timestamp, matched text, and span context
- Web Notifications API integration for desktop HIGH severity alerts
- Alerts tab with severity filtering, JSON export, and clear

#### Token Cost Estimator
- `GET /api/costs` endpoint aggregating tokens and estimated USD cost per session × model
- Pricing table for 20+ models: Claude (Opus/Sonnet/Haiku), GPT-4o/4/3.5, Gemini
- Cost tab in dashboard with model summary and per-session breakdown
- Color-coded cost bars with proportional intensity

#### Webhook Alerts
- Configurable webhook delivery on threat detection
- Slack, Discord, and generic JSON payload formats — auto-detected from URL
- Threshold configuration (`CLAUDESEC_WEBHOOK_THRESHOLD`: low/medium/high, default: high)
- In-dashboard webhook management UI with test delivery button
- `CLAUDESEC_WEBHOOK_URL` env var override for CI/CD environments

#### Observability
- `GET /api/health` — server status, uptime, span/session/alert counts, DB size
- `GET /metrics` — Prometheus text format with spans_total, threats_total,
  tokens_in_total, tokens_out_total (by harness), sessions_total, alerts_total, uptime_seconds

#### Documentation
- Mintlify documentation site in `docs/` — run with `npx mintlify dev`
  - Getting Started: overview, quickstart
  - Harness guides: one page per supported agent with copy-paste setup commands
  - Security: threat rules reference, alert system guide
  - API Reference: 9 pages covering all endpoints
- Complete OpenAPI 3.0.3 spec (`openapi.yaml`) with all schemas and examples
- `CLAUDE.md` for AI-assisted development context

#### Open Source
- MIT License
- `CONTRIBUTING.md` with dev setup, contribution workflow, threat rule guide
- `CODE_OF_CONDUCT.md`
- GitHub Actions CI: Node 18.x + 20.x matrix, lint + build on push/PR
- Issue templates: bug report, feature request
- Pull request template
- `npm run init` / `npx claudesec init` CLI wizard

### API

| Method | Path | Description |
|--------|------|-------------|
| POST   | `/v1/traces` | Ingest OTLP JSON traces |
| GET    | `/api/graph` | ReactFlow graph data |
| GET    | `/api/sessions` | List sessions with stats |
| PATCH  | `/api/sessions/:id` | Rename session |
| GET    | `/api/spans` | Search spans (`?q=`, `?session=`) |
| GET/POST/DELETE | `/api/rules` | Manage custom threat rules |
| GET/DELETE | `/api/alerts` | Threat alert log |
| GET    | `/api/alerts/export` | Export alerts JSON |
| GET    | `/api/export` | Export all spans JSON |
| GET    | `/api/export/csv` | Export spans CSV |
| GET    | `/api/harnesses` | Active harness list |
| GET    | `/api/orchestration` | Agent DAG, tools, spawn tree |
| GET    | `/api/costs` | Token usage and cost estimates |
| GET    | `/api/health` | Server health status |
| GET    | `/metrics` | Prometheus metrics |
| GET/POST/DELETE | `/api/webhook` | Webhook alert config |
| POST   | `/api/webhook/test` | Test webhook delivery |
| POST   | `/api/reset` | Clear all data |

---

## [0.3.0] — 2026-03-15

### Added
- Session isolation with traceId grouping
- Timeline (Gantt) view with BigInt nanosecond precision
- Span search with attribute `key=value` filter syntax
- Custom rules UI and `rules.json` persistence

## [0.2.0] — 2026-03-08

### Added
- Multi-harness detection registry (`src/harnesses.ts`)
- Per-harness colored graph root nodes
- Threat detection engine with 20+ built-in rules
- Alert log (SQLite `alerts` table)
- Desktop notifications via Web Notifications API

## [0.1.0] — 2026-03-01

### Added
- Initial MVP: Express OTLP ingestion, SQLite persistence, ReactFlow graph
- Socket.io real-time push from server to dashboard
- Dagre auto-layout for span graph

[1.0.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.0.0
[0.3.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v0.3.0
[0.2.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v0.2.0
[0.1.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v0.1.0
