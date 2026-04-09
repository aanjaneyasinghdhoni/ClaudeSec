# ClaudeSec

[![CI](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml/badge.svg)](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/claudesec.svg)](https://www.npmjs.com/package/claudesec)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)

**Real-time local observatory and security visualizer for AI agent telemetry.**

ClaudeSec ingests OpenTelemetry traces from any AI agent harness — Claude Code, Copilot, Cursor, Aider, and more — and surfaces suspicious activity as an interactive graph. Built for developers running local AI agents who need visibility into what those agents are actually doing.

---

## Features

- **Live graph** — ReactFlow node graph, color-coded by threat severity, Dagre auto-layout. Watch spans appear in real time as your agent works.
- **Timeline** — Gantt-style span timeline with BigInt nanosecond precision. Zoom into exactly when each tool call happened.
- **Orchestration** — Agent DAG showing inter-agent edges, sub-agent spawn trees across traces, and a tool inventory heatmap (tool x harness matrix).
- **Alerts** — Immutable threat alert log with severity filtering, deduplication, triage (dismiss/false-positive), and JSON export.
- **Rules engine** — 183 built-in regex rules (HIGH / MEDIUM / LOW) plus a custom rule CRUD UI with a live tester. Rules persist to `rules.json`.
- **Rule suppressions** — Temporarily or permanently suppress noisy rules without deleting them.
- **Cost estimator** — Token cost breakdown for 20+ models (Claude, GPT, Gemini) with per-session and per-model views, including cost trend over time.
- **Webhooks** — Push HIGH-severity alerts to Slack, Discord, or any generic JSON endpoint. Delivery history with retry support.
- **Desktop notifications** — Native OS alerts for HIGH severity detections, no browser tab required.
- **Prometheus metrics** — `GET /metrics` endpoint ready to scrape with Grafana.
- **Health endpoint** — `GET /api/health` for uptime monitoring.
- **MCP server** — 11 Model Context Protocol tools at `POST /mcp` for AI-to-AI interaction (get sessions, search spans, tag spans, manage bookmarks, etc.).
- **Process scanner** — Detects running AI agent CLIs on your machine. Kill, pause, or resume agents from the dashboard.
- **OTLP forwarding** — Transparent proxy to upstream OpenTelemetry collectors. Set `OTEL_FORWARD_URL` to forward traces while still analyzing them locally.
- **Auto-export** — Hourly JSON snapshots to `exports/` directory (last 24 retained automatically).
- **Span bookmarks** — Save interesting spans for later review.
- **Span tags & annotations** — Add custom metadata to any span.
- **Session labels & notes** — Organize sessions with labels (normal, incident, investigation, automated) and free-text notes.
- **Graph export** — Export the span graph as Mermaid or Graphviz DOT format.
- **Command audit log** — Track which commands agents have executed.
- **Welcome screen** — First-run onboarding with a demo simulator that injects 3 realistic sessions (`POST /api/simulate`).
- **Setup wizard** — `npx claudesec init` interactive CLI prints copy-paste env var commands for your harness.

---

## Quick Start

```bash
git clone https://github.com/aanjaneyasinghdhoni/ClaudeSec.git
cd ClaudeSec
npm install
npm run dev
```

Then open your browser at:

```
http://localhost:3000
```

---

## Connecting an Agent

### Claude Code (primary example)

Set these environment variables before starting a Claude Code session:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
```

Then start Claude Code as normal. Spans will appear in the dashboard live.

### Other harnesses — interactive setup

```bash
npm run init
```

The setup wizard prompts you to choose your harness and prints the exact env var commands to copy-paste.

---

## Docker

```bash
docker compose up
```

The Docker image runs both the Express backend and serves the production-built frontend. Data persists via a mounted volume for `spans.db`.

---

## Supported Harnesses

| Harness | OTLP env var |
|---|---|
| Claude Code | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| GitHub Copilot CLI | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| OpenHands | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Cursor | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Aider | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Cline | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Goose | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Continue.dev | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Windsurf | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Codex CLI | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Amazon Q Developer | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Gemini CLI | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Roo-Code | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Bolt.new | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Any OTLP-compatible tool | `OTEL_EXPORTER_OTLP_ENDPOINT` |

All harnesses use the same OTLP HTTP/JSON wire format. Set the endpoint to `http://localhost:3000/v1/traces` and set `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`.

---

## Architecture

```
AI Agent
   |
   | POST /v1/traces  (OTLP JSON)
   v
server.ts (Express + Socket.io)
   |
   +-- Threat detection (183 built-in regex rules)
   |
   +-- SQLite  (spans.db, persists across restarts)
   |
   +-- Socket.io broadcast  (live push to browser)
   |
   +-- OTLP forwarding  (optional, to upstream collectors)
   |
   +-- MCP server  (POST /mcp, 11 tools for AI-to-AI)
   |
   +-- Process scanner  (detect running agent CLIs)
   |
   +-- Auto-export  (hourly JSON snapshots)
   |
   v
App.tsx (React 19 + ReactFlow)
   |
   +-- Graph tab        (live node graph)
   +-- Timeline tab     (Gantt, nanosecond precision)
   +-- Orchestration    (agent DAG + tool heatmap)
   +-- Alerts tab       (immutable detection log with triage)
   +-- Rules tab        (183 built-in + custom rules + suppressions)
   +-- Costs tab        (token cost estimator + trend)
   +-- Processes tab    (running agent detection + kill switch)
   +-- Bookmarks tab    (saved spans)
```

**Tech stack:** Express + Socket.io + better-sqlite3 · React 19 + @xyflow/react + Tailwind CSS 4 · Vite 6 · TypeScript

---

## Threat Detection

The security engine evaluates every incoming span against 183 built-in rules. Custom rules can be added via the Rules tab UI or directly in `rules.json`.

| Severity | Example patterns |
|---|---|
| **HIGH** | Destructive commands, passwd reads, piped remote code, SQL destruction, credential exfiltration, prompt injection, reverse shells, supply-chain attacks, container escape |
| **MEDIUM** | Environment variable access, dotenv files, SSH key manipulation, sensitive system files, base64 decoding, network reconnaissance, Python one-liners |
| **LOW** | Full table scans, world-executable permissions, sudo usage, global package installs, broad file globs |

HIGH severity detections trigger desktop notifications and fire configured webhooks immediately.

---

## API Reference

ClaudeSec exposes 73 REST endpoints. Key groups:

| Group | Endpoints | Description |
|---|---|---|
| **OTLP** | `POST /v1/traces` | Ingest OTLP JSON trace payloads |
| **MCP** | `POST /mcp` | Model Context Protocol server (11 tools) |
| **Graph** | `GET /api/graph`, `/api/graph/mermaid`, `/api/graph/dot` | Graph state + export formats |
| **Sessions** | `GET /api/sessions`, `PATCH`, compare, report, health | Session management and analysis |
| **Spans** | `GET /api/spans`, search, tags, annotations, bookmarks | Span queries and metadata |
| **Alerts** | `GET /api/alerts`, export, triage (`PATCH`) | Threat alert log |
| **Rules** | `GET/POST/DELETE /api/rules`, threshold rules, suppressions | Rule management |
| **Webhooks** | `GET/POST/DELETE /api/webhook`, test, deliveries | Webhook configuration and history |
| **Costs** | `GET /api/costs`, `/api/cost-trend` | Token usage and cost estimates |
| **Processes** | `GET/DELETE /api/processes`, kill-all, pause, resume | Running agent management |
| **Export** | `GET /api/export`, `/api/export/csv`, `POST /api/import` | Data import/export |
| **Monitoring** | `GET /api/health`, `GET /metrics` | Health check and Prometheus metrics |
| **Activity** | `GET /api/activity`, `/api/live-activity`, `/api/heatmap`, `/api/tail` | Activity monitoring and streaming |
| **Audit** | `GET /api/command-audit`, `/api/file-access` | Agent action audit logs |
| **Config** | `GET /api/config`, `/api/collector-config`, `/api/db-stats` | Server configuration and DB stats |
| **Simulate** | `POST /api/simulate` | Demo trace injection |

Full OpenAPI 3.0.3 spec: [`openapi.yaml`](openapi.yaml)

---

## Prometheus / Grafana

ClaudeSec exposes a Prometheus-compatible metrics endpoint. Add this scrape config to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: claudesec
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: /metrics
```

Then point a Grafana data source at your Prometheus instance to build dashboards over ClaudeSec data.

---

## Webhooks

Send HIGH-severity alerts to Slack, Discord, or any HTTP endpoint. Configure webhook URLs in the dashboard UI, or set them directly via the API:

```bash
curl -X POST http://localhost:3000/api/webhook \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}'
```

---

## Documentation

Full docs are in the [`docs/`](docs/) folder, powered by Mintlify.

```bash
npx mintlify dev
```

Then open `http://localhost:3333`.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on opening issues, submitting pull requests, and the local development workflow.

---

## License

[MIT](LICENSE)
