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
- **Alerts** — Immutable threat alert log with severity filtering and JSON export. Never lose a detection.
- **Rules engine** — 31+ built-in regex rules (HIGH / MEDIUM / LOW) plus a custom rule CRUD UI with a live tester. Rules persist to `rules.json`.
- **Cost estimator** — Token cost breakdown for 20+ models (Claude, GPT, Gemini) with per-session and per-model views.
- **Webhooks** — Push HIGH-severity alerts to Slack, Discord, or any generic JSON endpoint.
- **Desktop notifications** — Native OS alerts for HIGH severity detections, no browser tab required.
- **Prometheus metrics** — `GET /metrics` endpoint ready to scrape with Grafana.
- **Health endpoint** — `GET /api/health` for uptime monitoring.
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

> Docker support is coming in a future release.

```bash
docker compose up
```

---

## Supported Harnesses

| Harness | OTLP env var |
|---|---|
| Claude Code | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| GitHub Copilot | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| OpenHands | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Cursor | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Aider | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Cline | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Goose | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Continue.dev | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Windsurf | `OTEL_EXPORTER_OTLP_ENDPOINT` |
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
   +-- Threat detection (31+ regex rules)
   |
   +-- SQLite  (spans.db, persists across restarts)
   |
   +-- Socket.io broadcast  (live push to browser)
   |
   v
App.tsx (React 19 + ReactFlow)
   |
   +-- Graph tab      (live node graph)
   +-- Timeline tab   (Gantt, nanosecond precision)
   +-- Orchestration  (agent DAG + tool heatmap)
   +-- Alerts tab     (immutable detection log)
   +-- Rules tab      (31+ built-in + custom rules)
   +-- Costs tab      (token cost estimator)
```

**Tech stack:** Express + Socket.io + better-sqlite3 · React 19 + @xyflow/react + Tailwind CSS 4 · Vite 6 · TypeScript

---

## Threat Detection

The security engine evaluates every incoming span against 31+ built-in rules. Custom rules can be added via the Rules tab UI or directly in `rules.json`.

| Severity | Example patterns |
|---|---|
| **HIGH** | `rm -rf /`, `cat /etc/passwd`, `curl \| bash`, `wget \| bash`, `DROP TABLE`, `eval(`, `exec(`, credential exfiltration |
| **MEDIUM** | `process.env`, `.env` file access, `ssh-add`, `/etc/shadow`, `atob(`, `base64 -d`, network recon |
| **LOW** | `SELECT * FROM`, `chmod 777`, `sudo`, broad file glob patterns |

HIGH severity detections trigger desktop notifications and fire configured webhooks immediately.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/traces` | Ingest an OTLP JSON trace payload |
| `GET` | `/api/graph` | Current graph state as JSON |
| `GET` | `/api/export` | Download full session as JSON |
| `POST` | `/api/reset` | Clear graph and database |
| `GET` | `/api/health` | Health check (uptime monitoring) |
| `GET` | `/metrics` | Prometheus text format metrics |

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

Send HIGH-severity alerts to Slack, Discord, or any HTTP endpoint. Configure webhook URLs in the **Costs** tab UI, or set them directly via the API:

```bash
curl -X POST http://localhost:3000/api/webhooks \
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
