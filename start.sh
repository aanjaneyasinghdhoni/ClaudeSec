#!/usr/bin/env bash
#
# ClaudeSec — one command to run it.
#
# Two audiences, both zero-config (no .env file required):
#
#   ./start.sh            Local (humans): clone -> running dashboard in one
#                         command. Builds the production app on first run (and
#                         whenever sources change), then serves it. Tails your
#                         on-disk agent transcripts live and tells you which
#                         agents it can see. Before starting, it OFFERS (y/N) to
#                         install the opt-in Claude Code enforcement hook so
#                         ClaudeSec can also block — not just watch. Without it,
#                         ClaudeSec only OBSERVES. Use --with-hook/--yes to
#                         install without asking, or --no-hook to skip silently.
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
#   ./start.sh --demo-local
#                         Demo without Docker: runs the LOCAL server against a
#                         DEDICATED demo database (~/.claudesec/demo.db) on its
#                         own port (3001 by default), seeds it with the same
#                         synthetic dataset, and opens the dashboard. Your real
#                         database and the regular port are never touched — the
#                         demo DB is a separate file and the script refuses to
#                         run if it would ever resolve to your live spans.db.
#
# Why a shell script (not the existing `claudesec` CLI): the CLI installs a
# background OS service; this script is the friendlier "clone and go" path that
# runs the dashboard in the foreground and explains what it can see. It stays
# shell-only so a brand-new user needs nothing but bash to get started.

set -euo pipefail

# --- Always operate from the repo root -------------------------------------
# Every later step (node_modules check, pnpm install, vite build, pnpm start,
# docker compose) assumes the current directory is the repo root. Resolve the
# script's own directory and cd into it so `./start.sh` works no matter where
# it's invoked.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# The dashboard listens on this port (server reads $CLAUDESEC_PORT, then $PORT,
# defaulting to 3000).
URL="http://localhost:${CLAUDESEC_PORT:-${PORT:-3000}}"

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
                        Installs deps if needed, builds the production app on
                        first run (and whenever sources change), then serves it,
                        shows which agents are detected, opens
                        http://localhost:3000 (default; set CLAUDESEC_PORT to
                        change), and tails your Claude Code / Codex / Copilot
                        CLI transcripts live.

  ./start.sh --docker   Run via Docker (`docker compose up`, headless).
                        Docker ingests via OTLP only — no local-transcript
                        watching (the container can't see your machine's files).

  ./start.sh --demo     Run via Docker with the demo container too
                        (`docker compose --profile demo up`). Brings up BOTH the
                        prod container on :3000 (default) and a separate demo
                        container on :3001. The demo container is pre-seeded with synthetic
                        data on its OWN volume — physically isolated from your
                        real data — so you can show the tool to others safely.

  ./start.sh --demo-local
                        Show the dashboard with synthetic data WITHOUT Docker.
                        Runs the local server against a dedicated demo database
                        (~/.claudesec/demo.db) on its own port (3001 by default;
                        set DEMO_PORT to change), seeds it with the synthetic
                        dataset, and opens the browser. Your real database and
                        your normal port are never touched: the demo DB is a
                        separate file, and the script aborts if that path would
                        ever resolve to your live spans.db. Good for evaluating
                        ClaudeSec when you have no telemetry of your own.

  ./start.sh --help     Show this help.

ENFORCEMENT HOOK (local path only):
  Out of the box ClaudeSec only OBSERVES — it never blocks a tool call. To also
  block dangerous calls before they run, register the Claude Code PreToolUse
  hook. It's opt-in, consent-gated, fail-open, and Claude-Code-only. By default
  the local path OFFERS to install it (y/N) on an interactive terminal.

  --with-hook, --yes    Install the enforcement hook without asking.
  --no-hook             Don't install it and don't ask (also the default when
                        stdin isn't a terminal, e.g. piped into bash).

Requires Node.js >= 22.13 and pnpm (enabled automatically via corepack) for the
local path, or Docker for the --docker path. No environment variables needed.
EOF
}

# --- Argument parsing ------------------------------------------------------
# Recognized: --help, --docker, --demo, --demo-local, and the hook opt-in/opt-out
# flags (--with-hook / --yes / --no-hook). Order doesn't matter and any flag may
# be combined with the local path; anything else is an error so typos don't
# silently fall through. The hook flags only affect the local path — Docker
# can't install a host hook (it has no access to your Claude Code settings).
#
# HOOK_CHOICE controls the consent prompt offered before the local server
# starts (see "Offer the enforcement hook" below):
#   ""    → ask interactively (y/N); skip the question if stdin isn't a TTY.
#   "yes" → install without asking (--with-hook / --yes).
#   "no"  → don't install and don't ask (--no-hook).
MODE="local"
HOOK_CHOICE=""
for arg in "$@"; do
  case "$arg" in
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
    --demo-local)
      MODE="demo-local"
      ;;
    --with-hook|--yes|-y)
      HOOK_CHOICE="yes"
      ;;
    --no-hook)
      HOOK_CHOICE="no"
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Run './start.sh --help' for usage." >&2
      exit 1
      ;;
  esac
done

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

# --- Demo-local setup (no Docker) ------------------------------------------
# `--demo-local` reuses the whole local path below (Node/pnpm/deps/build), but
# points the server at a DEDICATED demo database on a SEPARATE port and asks it
# to seed synthetic data. The real database and the normal port are never
# touched. We set this up here, before the shared steps, and the final start
# step (further down) branches on $MODE to launch with the demo environment.
#
# DATA SAFETY — this is the single most important guard in the script. A past
# reset wiped real telemetry, so the demo path must be physically incapable of
# writing to the live database:
#   • The demo DB is a separate file (~/.claudesec/demo.db), NEVER spans.db.
#   • We compute it ourselves and IGNORE any ambient CLAUDESEC_DB so an exported
#     "live DB" value can't leak in — `--demo-local` always overrides it.
#   • We then refuse to start if the resolved demo path ends in "spans.db" (the
#     live filename) — a belt-and-suspenders check in case anyone repoints it.
#   • Seeding itself only ever runs against this CLAUDESEC_DB, is opt-in
#     (CLAUDESEC_SEED_DEMO=1), and the server no-ops if the table isn't empty.
if [ "$MODE" = "demo-local" ]; then
  # The demo database lives next to your other ClaudeSec state, but as its own
  # file. $HOME is always set in a login shell; fall back defensively.
  DEMO_HOME="${HOME:-$SCRIPT_DIR}/.claudesec"
  DEMO_DB="$DEMO_HOME/demo.db"

  # Refuse outright if the demo DB would carry the live database's filename.
  # The live DB is named "spans_internal.db" (and historically "spans.db"); the
  # demo DB must not collide with either, old or new.
  case "$(basename "$DEMO_DB")" in
    spans.db|spans_internal.db)
      echo "Error: refusing to seed — the demo DB path resolves to the live" >&2
      echo "       database filename (spans.db / spans_internal.db). Aborting to protect real data." >&2
      exit 1
      ;;
  esac

  # Demo port: DEMO_PORT, else 3001 — deliberately NOT the normal dashboard port
  # ($CLAUDESEC_PORT/$PORT), so a running local service is never disturbed.
  DEMO_PORT_RESOLVED="${DEMO_PORT:-3001}"
  DEMO_URL="http://localhost:$DEMO_PORT_RESOLVED"

  mkdir -p "$DEMO_HOME"

  echo
  echo "Demo (local, no Docker) — synthetic data only:"
  echo "  Demo dashboard:  $DEMO_URL"
  echo "  Demo database:   $DEMO_DB  (separate file — your real data is untouched)"
  echo
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

# 5) Build the production app if needed -------------------------------------
# End users get the PRODUCTION build, never a dev server (Vite HMR with no
# prebuilt dist), so editing source without rebuilding can't silently serve
# stale assets. We build on-device from in-repo source only — no network fetch.
#
# Rebuild only when necessary so repeat launches stay fast: when there's no
# prior build (dist/index.html missing), or when any tracked source is newer
# than that build. `find ... -newer` prints a path for each stale file, so a
# non-empty result means "something changed since the last build".
#
# Note: we call `pnpm exec vite build` (NOT `pnpm build`) on purpose — `pnpm
# build` fires the `prebuild` hook, which runs the full test gate. That gate is
# for CI, not for an end user launching the app, so we bypass it here.
needs_build=""
if [ ! -f dist/index.html ]; then
  needs_build="1"
elif [ -n "$(find src server docs index.html vite.config.* package.json -type f -newer dist/index.html 2>/dev/null)" ]; then
  needs_build="1"
fi

if [ -n "$needs_build" ]; then
  echo "Building the app (first run / sources changed)…"
  if ! pnpm exec vite build; then
    echo "Error: the production build failed — not starting the server." >&2
    echo "Fix the build error above and retry ./start.sh." >&2
    exit 1
  fi
  echo
fi

# 6) Start the dashboard ----------------------------------------------------
# `pnpm start` runs the server in PRODUCTION mode (NODE_ENV=production), serving
# the freshly-built dist/. It runs in the FOREGROUND and blocks, so we print the
# URL and (best-effort) open the browser first. The browser open is backgrounded
# with a short delay so the port is listening by the time it fires; it's fully
# guarded so a missing opener never aborts the run.
# --- Offer the enforcement hook (consent-based, honest) --------------------
# By default ClaudeSec only OBSERVES — it never blocks a tool call. The opt-in
# Claude Code PreToolUse hook adds best-effort, before-it-runs blocking. We OFFER
# to install it here, but we are deliberately honest about what it is and isn't:
#   • It's monitor-by-default (an always-on "catastrophic floor" — e.g. rm -rf /,
#     fork bombs, curl|sh — plus any file paths you mark protected, block even in
#     monitor; everything else only blocks once you switch to enforce mode).
#   • It's Claude-Code-only (other agents are observe-only via this hook).
#   • It's fail-open: if the hook errors or is missing, the call is ALLOWED. It
#     raises the bar for an agent; it is not an OS sandbox or a hard guarantee.
# The underlying installer is itself consent-gated and idempotent, so re-running
# is safe. We never claim "you are now protected".
offer_hook() {
  # --no-hook, or non-interactive (piped) with no explicit --with-hook: don't
  # ask. Just print the honest one-liner so the option is discoverable.
  if [ "$HOOK_CHOICE" = "no" ] || { [ "$HOOK_CHOICE" != "yes" ] && [ ! -t 0 ]; }; then
    echo "Heads up: ClaudeSec is OBSERVING only — it won't block anything yet."
    echo "To add opt-in, before-it-runs blocking for Claude Code (monitor-by-"
    echo "default, fail-open, best-effort), register the hook:"
    echo "       node cli/init.mjs install-hook"
    echo
    return 0
  fi

  # Decide whether to install: pre-approved via --with-hook/--yes, else ask.
  if [ "$HOOK_CHOICE" != "yes" ]; then
    echo "ClaudeSec is OBSERVING only right now — it won't block anything."
    echo "Optionally install the Claude Code enforcement hook to also BLOCK"
    echo "dangerous tool calls before they run. It's monitor-by-default (only the"
    echo "always-on catastrophic floor + your protected paths block until you"
    echo "switch to enforce), Claude-Code-only, and fail-open (best-effort, not a"
    echo "sandbox). The installer asks again before it touches your settings."
    printf "Install the enforcement hook now? [y/N] "
    read -r reply || reply=""
    case "$reply" in
      y|Y|yes|YES) ;;
      *)
        echo "Skipped. You can install it anytime with: node cli/init.mjs install-hook"
        echo
        return 0
        ;;
    esac
  fi

  # Run the existing installer. It is consent-gated and idempotent; if it fails
  # we must NOT abort the launch (the dashboard still observes), so swallow the
  # error and fall back to the manual hint.
  echo "Installing the enforcement hook…"
  if node cli/init.mjs install-hook; then
    echo "Hook installed. Restart Claude Code so it loads the hook."
    echo "It's monitor-by-default and fail-open — flip to enforce from the"
    echo "Enforce tab when the would-block feed looks right."
  else
    echo "Hook install did not complete — ClaudeSec will still OBSERVE." >&2
    echo "You can retry anytime with: node cli/init.mjs install-hook" >&2
  fi
  echo
}

# --- Demo-local start ------------------------------------------------------
# In demo mode we DON'T offer the enforcement hook (it edits your real Claude
# Code settings, which has nothing to do with a throwaway demo) and we launch
# the server with the demo environment instead of the normal one:
#   • CLAUDESEC_DB        → the dedicated demo file (overrides any ambient value)
#   • CLAUDESEC_PORT      → the demo port (overrides the ambient one, so we never
#                           collide with a running local service on its port)
#   • CLAUDESEC_SEED_DEMO → "1", the server's opt-in synthetic-seed switch
#                           (it only seeds when the demo DB's table is empty)
# `env -u PORT` drops any inherited PORT so CLAUDESEC_PORT is the sole source of
# truth for the bind port. We set these inline (not `export`) so they scope to
# this one process and never leak into your shell.
if [ "$MODE" = "demo-local" ]; then
  echo "Starting ClaudeSec (demo) — dashboard at $DEMO_URL"
  echo "(Press Ctrl-C to stop. Synthetic data only — your real data is untouched.)"
  echo
  ( sleep 2; open_browser "$DEMO_URL" ) >/dev/null 2>&1 &

  exec env -u PORT \
    CLAUDESEC_DB="$DEMO_DB" \
    CLAUDESEC_PORT="$DEMO_PORT_RESOLVED" \
    CLAUDESEC_SEED_DEMO=1 \
    pnpm start
fi

offer_hook

echo "Starting ClaudeSec — dashboard at $URL"
echo "(Press Ctrl-C to stop.)"
echo
( sleep 2; open_browser "$URL" ) >/dev/null 2>&1 &

exec pnpm start
