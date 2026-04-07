# AI Agent Observability Visualizer

[![CI](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml/badge.svg)](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A real-time dashboard that turns OpenTelemetry traces from AI agents into a live communication graph with built-in security threat detection.

---

## What It Does

Every time an AI agent (like Claude Code) performs an action — reads a file, runs a command, calls an API — it emits an OpenTelemetry span. This tool catches those spans and:

- Draws a **live node graph** showing what the agent communicated with and in what order
- **Colour-codes every workflow** by threat severity (green → yellow → orange → red)
- **Flags malicious patterns** like `rm -rf`, `eval()`, `process.env` access, SQL injection, and more
- **Persists all traces** to a local SQLite database so nothing is lost on restart
- Lets you **search, filter, and export** your session data

---

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- npm (comes with Node.js)

---

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Start the server

```bash
npm run dev
```

The app runs at **http://localhost:3000**

### 3. Open the dashboard

Navigate to `http://localhost:3000` in your browser. You should see the dark canvas with an **AI Agent** root node.

---

## Connecting Claude Code (Live Telemetry)

To stream real Claude Code traces into the visualizer, set these environment variables before starting a Claude Code session:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
```

Or add them permanently to `~/.claude/settings.json`:

```json
{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA": "1",
    "OTEL_TRACES_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:3000/v1/traces",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"
  }
}
```

> **Note:** Telemetry env vars are picked up at Claude Code session start. Restart your session after adding them.

---

## Using the Dashboard

### Left Pane — Workflows

Every incoming span appears here as a coloured row:

| Colour | Meaning |
|--------|---------|
| Green  | Clean — no threats detected |
| Yellow | Low severity (e.g. `sudo`, wildcard `chmod`) |
| Orange | Medium severity (e.g. `process.env`, `.env` file access) |
| Red    | High severity (e.g. `rm -rf`, `eval()`, `DROP TABLE`) |

**Click any row** to open the full span details panel on the right.

**Search** by span name, reason, or protocol using the search box.

**Filter** between All / Normal / Malicious using the filter buttons.

### Centre — Graph Canvas

Each span is a node connected to its parent by a directed edge. Edges are coloured to match the severity of the target node.

- **Scroll** to zoom in/out
- **Drag** to pan
- **Click a node** to open its detail panel

### Right Panel — Span Details

Shows the full metadata for a selected span:

- Span name and severity badge
- Protocol used (HTTPS, FS, SQL, bash, etc.)
- Reason provided by the agent
- All raw attributes from the OTel span

### Header Controls

| Button | Action |
|--------|--------|
| Export | Downloads the full session as `session-<timestamp>.json` |
| Trash  | Resets the graph and clears the database |

---

## Testing Without a Live Agent

Use the **Simulate** buttons in the left pane:

- **Normal Trace** — injects a clean `Fetch Data` span
- **Malicious Trace** — injects a `cat /etc/passwd` span (triggers HIGH alert)

---

## Sending Custom Traces

The OTLP ingestion endpoint accepts standard OpenTelemetry JSON. Send a `POST` to `http://localhost:3000/v1/traces`:

```bash
curl -X POST http://localhost:3000/v1/traces \
  -H "Content-Type: application/json" \
  -d '{
    "resourceSpans": [{
      "resource": {},
      "scopeSpans": [{
        "scope": {},
        "spans": [{
          "traceId": "abc123",
          "spanId": "span001",
          "name": "My Custom Step",
          "kind": 1,
          "startTimeUnixNano": "1700000000000000000",
          "endTimeUnixNano":   "1700000001000000000",
          "attributes": [
            { "key": "protocol", "value": { "stringValue": "HTTPS" } },
            { "key": "reason",   "value": { "stringValue": "Why this step happened" } },
            { "key": "payload",  "value": { "stringValue": "GET /api/data" } }
          ],
          "status": { "code": 0 }
        }]
      }]
    }]
  }'
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/traces` | Ingest an OTLP trace payload |
| `GET`  | `/api/graph`  | Return current graph state as JSON |
| `GET`  | `/api/export` | Download full session as JSON file |
| `POST` | `/api/reset`  | Clear graph and database |

---

## Threat Detection Rules

Spans are scanned against these patterns on ingestion:

| Severity | Patterns |
|----------|---------|
| **High** | `rm -rf /`, `cat /etc/passwd`, `curl \| bash`, `wget \| bash`, `DROP TABLE`, `TRUNCATE TABLE`, `eval(`, `exec(` |
| **Medium** | `process.env`, `.env` files, `ssh-add`, `/etc/shadow`, `atob(`, `base64 -d` |
| **Low** | `SELECT * FROM`, `chmod 777`, `sudo` |

---

## Data Persistence

All spans are stored in `spans.db` (SQLite) in the project root. The database is loaded on server startup, so your trace history survives restarts.

To permanently clear all data:

```bash
# Via the UI: click the trash icon in the header
# Via API:
curl -X POST http://localhost:3000/api/reset
```

---

## Project Structure

```
├── server.ts          # Express + Socket.io backend, OTLP ingestion, SQLite, security detection
├── src/
│   ├── App.tsx        # React frontend — graph canvas, workflow list, search/filter
│   ├── main.tsx       # React entry point
│   └── index.css      # Global styles (Tailwind + React Flow)
├── index.html         # HTML shell
├── vite.config.ts     # Vite + Tailwind config
├── package.json       # Dependencies
└── spans.db           # SQLite database (created on first run)
```

---

## Compatible Agents

Any agent that supports OpenTelemetry OTLP export will work. Tested with:

- **Claude Code** (via `OTEL_EXPORTER_OTLP_ENDPOINT`)
- Any custom agent using the [OpenTelemetry JS SDK](https://opentelemetry.io/docs/languages/js/)
- Any tool that can `POST` JSON to `/v1/traces`
