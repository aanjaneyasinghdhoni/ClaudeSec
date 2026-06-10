#!/usr/bin/env bash
#
# ClaudeSec — one command to run it.
#
# Two audiences, both zero-config (no .env file required):
#
#   ./start.sh            Local (humans): clone -> running dashboard in one
#                         command. Tails your on-disk agent transcripts live
#                         and tells you which agents it can see.
#
#   ./start.sh --docker   Docker (servers): runs `docker compose up` (headless).
#                         Docker ingests via OTLP only — it cannot read your
#                         machine's transcripts, so there is no local watching.
#
#   ./start.sh --demo     Docker + demo: runs `docker compose --profile demo up`,
#                         bringing up BOTH the prod container (:3000) and a
#                         separate demo container (:3001) pre-seeded with
#                         synthetic data on its own isolated volume — handy for
#                         showing the tool without exposing real telemetry.
#
# Why a shell script (not the existing `claudesec` CLI): the CLI installs a
# background OS service; this script is the friendlier "clone and go" path that
# runs the dashboard in the foreground and explains what it can see. It stays
# shell-only so a brand-new user needs nothing but bash to get started.

set -euo pipefail

# --- Always operate from the repo root -------------------------------------
# Every later step (node_modules check, pnpm install, pnpm dev, docker compose)
# assumes the current directory is the repo root. Resolve the script's own
# directory and cd into it so `./start.sh` works no matter where it's invoked.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# The dashboard listens on this port (server reads $PORT, defaulting to 3000).
URL="http://localhost:${PORT:-3000}"

# --- Helpers ---------------------------------------------------------------

# Open a URL in the default browser if an opener exists. Best-effort: this must
# never fail the script, so every path is guarded and returns success.
open_browser() {
  url="$1"
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true        # macOS
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true     # Linux
  fi
  return 0
}

usage() {
  cat <<'EOF'
ClaudeSec — start the local security observatory for your AI coding agents.

USAGE:
  ./start.sh            Run the full local dashboard (zero-config).
                        Installs deps if needed, shows which agents are
                        detected, opens http://localhost:3000, and tails your
                        Claude Code / Codex / Copilot CLI transcripts live.

  ./start.sh --docker   Run via Docker (`docker compose up`, headless).
                        Docker ingests via OTLP only — no local-transcript
                        watching (the container can't see your machine's files).

  ./start.sh --demo     Run via Docker with the demo container too
                        (`docker compose --profile demo up`). Brings up BOTH the
                        prod container on :3000 and a separate demo container on
                        :3001. The demo container is pre-seeded with synthetic
                        data on its OWN volume — physically isolated from your
                        real data — so you can show the tool to others safely.

  ./start.sh --help     Show this help.

Requires Node.js >= 22.13 and pnpm (enabled automatically via corepack) for the
local path, or Docker for the --docker path. No environment variables needed.
EOF
}

# --- Argument parsing ------------------------------------------------------
# Only --help, --docker and --demo are recognized; anything else is an error so
# typos don't silently fall through to the local path.
MODE="local"
case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  --docker)
    MODE="docker"
    ;;
  --demo)
    MODE="demo"
    ;;
  "")
    MODE="local"
    ;;
  *)
    echo "Unknown option: $1" >&2
    echo "Run './start.sh --help' for usage." >&2
    exit 1
    ;;
esac

# --- Docker path -----------------------------------------------------------
# A thin convenience wrapper over the existing docker-compose.yml. We print the
# OTLP-only caveat BEFORE launching, because `docker compose up` runs in the
# foreground and the note would otherwise scroll past in the build/run logs.
if [ "$MODE" = "docker" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: 'docker' was not found on your PATH." >&2
    echo "Install Docker (https://docs.docker.com/get-docker/) and retry." >&2
    exit 1
  fi
  echo "Starting ClaudeSec via Docker — dashboard at $URL"
  echo "Note: Docker ingests via OTLP only. The container cannot read your"
  echo "      machine's transcripts, so local Claude Code / Codex / Copilot CLI"
  echo "      sessions are NOT auto-watched. Point agents at $URL/v1/traces."
  echo
  # Run in the foreground so the build and run logs stay visible.
  exec docker compose up
fi

# --- Demo path -------------------------------------------------------------
# Brings up BOTH the prod container (:3000) and the demo container (:3001) via
# the `demo` Compose profile. The demo container has its own database volume
# pre-seeded with synthetic data, physically isolated from your real data.
if [ "$MODE" = "demo" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: 'docker' was not found on your PATH." >&2
    echo "Install Docker (https://docs.docker.com/get-docker/) and retry." >&2
    exit 1
  fi
  DEMO_URL="http://localhost:${DEMO_PORT:-3001}"
  echo "Starting ClaudeSec via Docker with the demo container:"
  echo "  Prod (your real data):     $URL"
  echo "  Demo (synthetic data):     $DEMO_URL"
  echo
  echo "Note: the demo container holds ONLY synthetic data on its own volume,"
  echo "      physically isolated from your real data — safe to show to others."
  echo
  # Run in the foreground so the build and run logs stay visible.
  exec docker compose --profile demo up
fi

# --- Local path ------------------------------------------------------------

# 1) Node.js >= 22.13 -------------------------------------------------------
# `better-sqlite3` and the server require a modern Node. Compare major/minor
# NUMERICALLY — a string compare would wrongly rank "22.9" above "22.13".
if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js was not found on your PATH." >&2
  echo "Install Node.js >= 22.13 from https://nodejs.org and retry." >&2
  exit 1
fi

NODE_RAW="$(node -v)"                 # e.g. "v24.14.0"
NODE_VER="${NODE_RAW#v}"              # strip leading "v" -> "24.14.0"
NODE_MAJOR="${NODE_VER%%.*}"         # "24"
NODE_REST="${NODE_VER#*.}"           # "14.0"
NODE_MINOR="${NODE_REST%%.*}"        # "14"

# Guard against non-numeric values (e.g. nightly builds) by defaulting to 0.
case "$NODE_MAJOR" in ''|*[!0-9]*) NODE_MAJOR=0 ;; esac
case "$NODE_MINOR" in ''|*[!0-9]*) NODE_MINOR=0 ;; esac

if [ "$NODE_MAJOR" -lt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 13 ]; }; then
  echo "Error: Node.js >= 22.13 is required (found $NODE_RAW)." >&2
  echo "Upgrade Node.js from https://nodejs.org and retry." >&2
  exit 1
fi

# 2) pnpm via corepack ------------------------------------------------------
# corepack ships with Node and activates the exact pnpm pinned in
# package.json's "packageManager" field. It's best-effort: if corepack is
# missing or fails, fall back to whatever pnpm is already on PATH.
if command -v corepack >/dev/null 2>&1; then
  corepack enable >/dev/null 2>&1 || true
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "Error: pnpm was not found and corepack could not provide it." >&2
  echo "Enable it with 'corepack enable', or install pnpm from" >&2
  echo "https://pnpm.io/installation, then retry. (ClaudeSec uses pnpm, not npm.)" >&2
  exit 1
fi

# 3) Install dependencies only if they're missing ---------------------------
# Skip a redundant install on every launch; pnpm install is idempotent but slow.
if [ ! -d node_modules ]; then
  echo "Installing dependencies with pnpm (first run)…"
  pnpm install
fi

# 4) Agent detection --------------------------------------------------------
# ClaudeSec watches each agent's on-disk transcript DIRECTORY (it never reads
# the file contents here — we only check that the directory exists). These three
# roots are the source of truth from defaultRoots() in
# server/transcriptWatcher.ts; keep them in sync if that changes.
CLAUDE_DIR="$HOME/.claude/projects"
CODEX_DIR="$HOME/.codex/sessions"
COPILOT_DIR="$HOME/.copilot/session-state"

detected=""
missing=""

# $1 = directory, $2 = friendly agent name
check_agent() {
  if [ -d "$1" ]; then
    detected="${detected}  - ${2} (captured live)\n"
  else
    missing="${missing}  - ${2}\n"
  fi
}

check_agent "$CLAUDE_DIR"  "Claude Code"
check_agent "$CODEX_DIR"   "Codex"
check_agent "$COPILOT_DIR" "GitHub Copilot CLI"

echo
echo "Agent transcript detection:"
if [ -n "$detected" ]; then
  echo "Detected — these will be captured live the moment they do something:"
  printf "%b" "$detected"
else
  echo "No agent transcript directories found yet."
fi
if [ -n "$missing" ]; then
  echo "Not detected yet (no transcripts on disk — start the agent and it'll appear):"
  printf "%b" "$missing"
fi
echo

# 5) Start the dashboard ----------------------------------------------------
# `pnpm dev` runs the server in the FOREGROUND and blocks, so we print the URL
# and (best-effort) open the browser first. The browser open is backgrounded
# with a short delay so the port is listening by the time it fires; it's fully
# guarded so a missing opener never aborts the run.
echo "Starting ClaudeSec — dashboard at $URL"
echo "(Press Ctrl-C to stop.)"
echo
# Optional next step: the dashboard only watches by default. To let ClaudeSec
# BLOCK dangerous tool calls before they run, register the PreToolUse hook with
# Claude Code. It asks before touching your settings and is fail-open by design.
# We only print the hint — we never install it for you.
echo "Tip: to block dangerous tool calls (not just watch), register the hook:"
echo "       node cli/init.mjs install-hook"
echo
( sleep 2; open_browser "$URL" ) >/dev/null 2>&1 &

exec pnpm dev
