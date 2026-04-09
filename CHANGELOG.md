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
- Harness detection registry (`src/harnesses.ts`) covering 14 agent frameworks:
  Claude Code, GitHub Copilot CLI, OpenHands, Cursor, Aider, Cline, Goose, Continue.dev, Windsurf, Codex CLI, Amazon Q Developer, Gemini CLI, Roo-Code, and Bolt.new
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
- 183 built-in threat detection rules across HIGH / MEDIUM / LOW severities covering:
  system compromise, prompt injection, credential theft, data exfiltration, supply-chain attacks,
  reverse shells, container escape, reconnaissance, and more
- Custom rule CRUD via dashboard UI and REST API (saved to `rules.json`)
- Rule suppressions — temporarily or permanently suppress noisy rules
- Immutable alert log (SQLite `alerts` table) with timestamp, matched text, and span context
- Alert deduplication via fingerprinting — prevents duplicate alerts for the same pattern
- Alert triage — mark alerts as dismissed or false-positive
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

#### MCP Server
- Model Context Protocol server at `POST /mcp` with 11 tools for AI-to-AI interaction:
  get_health, get_sessions, get_spans, get_alerts, search_spans, tag_span, suppress_rule,
  bookmark_span, get_processes, get_incident_summary, list_bookmarks

#### Process Scanner
- Detects running AI agent CLIs on the local machine (14 harness patterns)
- Kill, pause, and resume individual agents or all agents from the dashboard
- Endpoints: `GET /api/processes`, `DELETE /api/processes/:pid`, `POST /api/processes/kill-all`, pause-all, resume-all

#### OTLP Forwarding
- Transparent proxy to upstream OpenTelemetry collectors via `OTEL_FORWARD_URL` environment variable
- Traces are analyzed locally and forwarded simultaneously

#### Auto-Export
- Hourly JSON snapshots of spans, alerts, and sessions to `exports/` directory
- Rolling retention: last 24 exports kept automatically

#### Span Bookmarks, Tags & Annotations
- Bookmark interesting spans for later review (`GET/POST/DELETE /api/bookmarks`)
- Add custom tags to any span (`GET/POST/DELETE /api/spans/:spanId/tags`)
- Add text annotations to spans (`GET/POST/DELETE /api/spans/:spanId/annotations`)

#### Session Labels & Notes
- Assign labels to sessions: normal, incident, investigation, automated, other
- Add free-text notes to any session
- Filter sessions by label

#### Graph Export
- Export span graph as Mermaid format (`GET /api/graph/mermaid`)
- Export span graph as Graphviz DOT format (`GET /api/graph/dot`)

#### Command Audit & File Access Tracking
- Track commands executed by agents (`GET /api/command-audit`)
- Track file access patterns (`GET /api/file-access`)

#### Activity & Heatmap
- Activity timeline (`GET /api/activity`)
- Live activity stream (`GET /api/live-activity`)
- Threat activity heatmap (`GET /api/heatmap`)
- Server-sent events tail (`GET /api/tail`)

#### Welcome Screen & Demo Simulator
- First-run welcome screen with onboarding flow
- Demo trace simulator injects 3 realistic sessions (`POST /api/simulate`)
- Auto-detects running agents on the machine

#### Docker Support
- Production-ready Dockerfile with multi-stage build
- docker-compose.yml with volumes, health checks, and environment variables

#### Observability
- `GET /api/health` — server status, uptime, span/session/alert counts, DB size
- `GET /metrics` — Prometheus text format with spans_total, threats_total,
  tokens_in_total, tokens_out_total (by harness), sessions_total, alerts_total, uptime_seconds

#### Documentation
- Mintlify documentation site in `docs/` — run with `npx mintlify dev`
  - Getting Started: overview, quickstart, architecture
  - Harness guides: one page per supported agent (14 harnesses) with copy-paste setup commands
  - Security: threat rules reference, alert system guide, rule suppressions
  - Observatory: welcome screen, process scanner, session labels
  - Integrations: MCP server, OTLP collector
  - API Reference: comprehensive endpoint documentation
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

### API (73 endpoints)

Key endpoint groups — see `openapi.yaml` for the full specification:

| Group | Key Paths | Description |
|-------|-----------|-------------|
| OTLP | `POST /v1/traces` | Ingest OTLP JSON traces |
| MCP | `POST /mcp` | Model Context Protocol server (11 tools) |
| Graph | `/api/graph`, `/api/graph/mermaid`, `/api/graph/dot` | Graph state + export |
| Sessions | `/api/sessions`, `PATCH`, compare, report, health | Session management |
| Spans | `/api/spans`, search, tags, annotations, bookmarks | Span queries + metadata |
| Alerts | `/api/alerts`, export, `PATCH` triage | Threat alert log |
| Rules | `/api/rules`, threshold rules, suppressions | Rule management |
| Webhooks | `/api/webhook`, test, deliveries | Webhook config + history |
| Costs | `/api/costs`, `/api/cost-trend` | Token usage + cost |
| Processes | `/api/processes`, kill-all, pause, resume | Agent management |
| Export | `/api/export`, csv, `POST /api/import` | Data import/export |
| Monitoring | `/api/health`, `/metrics` | Health + Prometheus |
| Activity | `/api/activity`, live-activity, heatmap, tail | Activity streams |
| Audit | `/api/command-audit`, `/api/file-access` | Audit logs |
| Config | `/api/config`, collector-config, db-stats | Server config |
| Simulate | `POST /api/simulate` | Demo trace injection |
| Reset | `POST /api/reset` | Clear all data |

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
