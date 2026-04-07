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
  → App.tsx (React Flow graph)
```

### Two-process model in one repo

- **`server.ts`** — Express backend. Handles OTLP ingestion, SQLite reads/writes, security rule evaluation, REST endpoints (`/api/graph`, `/api/export`, `/api/reset`), and Socket.io events. Also serves the Vite-built `dist/` in production.
- **`src/App.tsx`** — Entire React frontend in a single large component (~650 lines). No routing. Uses React Flow for the graph canvas, Socket.io client for live updates, and holds all UI state (selected span, filters, layout).

### Key architectural decisions

- **SQLite via `better-sqlite3`** persists spans across server restarts (`spans.db` is gitignored but created automatically).
- **Dagre** computes graph layout on the server side (via `/api/graph`) and on the client whenever new spans arrive.
- **Threat detection** lives entirely in `server.ts` as an array of `{ pattern: RegExp, level, reason }` objects evaluated against every incoming span's attributes.
- **Path alias** `@/*` resolves to the repo root (not `src/`). Configured in both `vite.config.ts` and `tsconfig.json`.

### Connecting Claude Code to the dashboard

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
```

The `.env.example` contains a legacy `GEMINI_API_KEY` entry that is no longer used.
