# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev       # Start dev server (backend + frontend HMR) on http://localhost:3000
npm run build     # Production build (vite build → dist/)
npm run preview   # Serve production build locally
npm run lint      # TypeScript type-check (tsc --noEmit, no test framework configured)
npm run clean     # Remove dist/
```

No test framework is configured — `npm run lint` is the closest to CI validation.

## Architecture

**ClaudeSec** is a real-time AI agent observability dashboard. It ingests OpenTelemetry (OTLP) traces from AI agents (e.g., Claude Code), detects security threats, and visualizes agent activity as a live interactive graph.

### Data flow

```
AI agent → POST /v1/traces (OTLP JSON) → server.ts
  → threat detection (regex rules)
  → SQLite (spans.db)
  → Socket.io broadcast
  → App.tsx (dashboard views: timeline, alerts, orchestration, etc.)
```

### Two-process model in one repo

- **`server.ts`** — Express backend. Handles OTLP ingestion, SQLite reads/writes, security rule evaluation, REST endpoints (`/api/graph`, `/api/export`, `/api/reset`), and Socket.io events. Also serves the Vite-built `dist/` in production.
- **`src/App.tsx`** — Main React frontend component. Uses Socket.io client for live updates and holds all UI state (filters, active tab, session selection). Shows a `WelcomeScreen` on first run (zero sessions). Default tab is Timeline.

### Key architectural decisions

- **SQLite via `better-sqlite3`** persists spans across server restarts (`spans.db` is gitignored but created automatically).
- **Dagre** computes graph layout on the server side (via `/api/graph`) for the headless graph API. There is no graph UI tab in the dashboard.
- **Threat detection** lives in `server.ts` as `SEVERITY_RULES` (183 built-in regex rules: prompt injection, credential theft, reverse shells, supply-chain, exfiltration, recon) evaluated against every incoming span.
- **Path alias** `@/*` resolves to the repo root (not `src/`). Configured in both `vite.config.ts` and `tsconfig.json`.

### Connecting Claude Code to the dashboard

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
export OTEL_LOG_TOOL_DETAILS=1
```

The `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA` flag enables `claude_code.llm_request` spans with model name and token counts. Without it, only opaque `tool_call/unknown` spans are emitted. `OTEL_LOG_TOOL_DETAILS` adds tool names and input arguments.

### Key features

- **Welcome screen** with auto-setup (`npx claudesec init`) — first-run UX
- **189 built-in security rules** — prompt injection, secrets, shells, supply-chain, exfiltration
- **Claude Code focused** — purpose-built for Claude Code telemetry and security monitoring
- **Process scanner** — detects running Claude Code processes via `ps aux`, kill switch via `DELETE /api/processes/:pid`
- **OTLP forwarding** — transparent proxy to upstream collectors (set `OTEL_FORWARD_URL`)
- **Auto-export** — hourly JSON snapshots to `exports/` (last 24 kept)
- **MCP server** — 11 tools for AI-to-AI interaction (`POST /mcp`)
- **Docker** — `docker compose up` for one-command deployment
