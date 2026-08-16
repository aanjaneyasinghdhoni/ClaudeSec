# ClaudeSec

[![CI](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml/badge.svg)](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/ci.yml)
[![CodeQL](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/codeql.yml/badge.svg)](https://github.com/aanjaneyasinghdhoni/ClaudeSec/actions/workflows/codeql.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.13-green.svg)](https://nodejs.org)

**A zero-config, fully-local security observatory for AI coding agents — observe by default, enforce when you opt in.**

Claude Code, GitHub Copilot CLI, and Codex all write full session transcripts to disk as they
work. ClaudeSec tails those transcripts in real time — across every repo on your machine — and
surfaces what your agents are actually doing: every tool call, every command, every file touched,
scored live against ~673 built-in threat-detection rules plus a stateful sequence engine that
correlates multi-step attack chains. Nothing leaves your machine by default — the only outbound
paths are four optional sinks you have to turn on yourself.

---

## Run it

From a fresh clone, one command does everything — checks Node, enables pnpm, installs deps on
first run, builds and serves the production app (zero-config), prints which agents it can see,
and opens the dashboard:

```bash
git clone https://github.com/aanjaneyasinghdhoni/ClaudeSec.git
cd ClaudeSec
./start.sh
```

Then open **http://localhost:3000**. No environment variables, no shell edits, no agent restart —
the watcher picks up sessions that were already running. The dashboard starts **empty** — it only
shows your own agent activity as it happens.

Two alternatives, same script:

- `./start.sh --docker` — run headless via `docker compose up`. Docker ingests via **OTLP only**;
  it cannot read your machine's transcripts, so point agents at it over
  [OTLP](docs/how-to/remote-agents.mdx).
- `./start.sh --demo` — bring up the dashboard **plus** a separate demo container on `:3001`,
  pre-seeded with synthetic data on its own isolated volume — safe to show to others. The default
  `./start.sh` and `--docker` paths never seed this synthetic data; only `--demo` does, on its own
  container. Any synthetic rows can be removed anytime from **Settings → Data → Clear demo data**.

> `better-sqlite3` builds a native module on install. On macOS, run `xcode-select --install` if the
> build fails; on Linux, install `build-essential`.

### Windows

The one-command `./start.sh` is a Bash script and the local path compiles native modules, so the
recommended way to run ClaudeSec on Windows is **Docker Desktop**:

```powershell
git clone https://github.com/aanjaneyasinghdhoni/ClaudeSec.git
cd ClaudeSec
docker compose up
```

Then open **http://localhost:3000**. Docker ingests via **OTLP only**, so point your agents at it
over [OTLP](docs/how-to/remote-agents.mdx) — the on-disk transcript watcher and the Processes tab
are not available on the Windows native path. To run natively instead (PowerShell, no Docker) you
need Git Bash or WSL to invoke `start.sh`, plus the
[Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) "Desktop
development with C++" workload and Python so `better-sqlite3` and `re2` can compile.

---

## What you get

- **Live timeline & orchestration** — tool calls streaming in with nanosecond durations, per-agent
  tool inventory, a command-audit trail, and a sensitive-file-access panel.
- **673 built-in threat rules** (194 core + 479 extra) — CRITICAL / HIGH / MEDIUM / LOW regex
  rules for prompt injection, credential theft, reverse shells, supply-chain attacks, exfiltration,
  SSRF, container escape, and more. The CRITICAL tier is reserved for active secret *exfiltration*
  — a credential or `.env` being transmitted off the machine. Every rule is held to a linear-time
  execution gate by the ReDoS self-test, and custom rules you add are compiled with RE2. A **stateful sequence engine** on top of the single-span rules watches for
  multi-step chains across a session — recon then exfiltration, a credential read followed by a
  network send — and renders the matched steps as a chain on the alert, not just the final span.
- **Enforcement (opt-in, Claude Code only)** — out of the box ClaudeSec only *observes*: there is
  **zero pre-execution blocking** until you register the Claude Code PreToolUse hook with one command
  (`node cli/init.mjs install-hook`; `./start.sh` also offers to do it for you). Once installed it's
  `monitor` by default — the always-on **catastrophic floor** (root-preserving `rm -rf /`, system-dir
  wipes with developer carve-outs, fork bombs, `curl … | sh`, reverse shells, raw-disk overwrites,
  common Windows destructive commands, and reading a secret and piping/uploading it off-machine in
  one command) and any **protected paths** — a small, user-removable default set (`~/.ssh`,
  `~/.aws/credentials`, `~/.config/gcloud`, `~/.kube/config`, `~/.npmrc`, `.env`-style secrets) plus
  anything you mark in the dashboard — denied on read, write, edit, and delete — block even in
  monitor; every other rule blocks only in `enforce` mode. It **blocks
  actions, not edits**: `Bash` is matched in full against the rules, but an `Edit`/`Write` is gated
  on the **file path + action** plus a tiny live-secret check on the content — never the whole file
  body against the rule set — so editing security code or fixtures is never blocked. A `WebFetch` to
  a cloud-metadata / internal host is blocked before the request leaves the machine (DNS rebinding is
  a known gap of the synchronous hook). Custom regex rules added in the UI **detect by default**; in
  `enforce` mode a **high- or critical-severity** custom rule also blocks (low/medium stay
  detect-only). Pre-execution blocking
  reaches **Claude Code only** today — it's the one agent with a pre-exec hook; the others (Codex,
  Copilot) are **observe-only** unless routed through the optional cross-agent MCP proxy
  (`claudesec mcp-proxy`), which applies the **same** floors as the hook — catastrophic, protected
  paths, self-protection, and the fetch-SSRF guard — with a parity test pinning its verdicts to the
  hook's; any other MCP-speaking agent can be gated the same way. It's a
  **tripwire, not a sandbox** — a best-effort, fail-open defense-in-depth layer. It can catch and
  block known-bad tool calls before they run, but an agent (or a prompt-injected command) that sets
  `CLAUDESEC_HOOKS_BYPASS=1`, restructures a command, or spawns a subprocess can evade it. Use it
  as one layer, not as containment.
- **MCP / skill scanner** — statically scans installed MCP server configs and Claude skills for
  tool-poisoning, prompt injection, hardcoded secrets, and suspicious launch commands.
- **Honeytokens** — plant canary strings; any span containing one fires a HIGH exfiltration alert.
- **Optional LLM-as-judge** — off by default, on-demand, local-first semantic classification.
- **Three agent harnesses** — Claude Code, GitHub Copilot CLI, and Codex, auto-detected from
  on-disk transcripts. Remote and CI agents stream in over OTLP into the same pipeline.
- **Cost view** — token usage and API-equivalent cost per session and model (Claude Code; Copilot CLI
  and Codex sessions may show no spend), with subscription-plan awareness (API / Pro / Max 5× / Max 20×).
- **Integrations** — a Prometheus-format `/metrics` endpoint (counters), webhooks (Slack / Discord / JSON), graph
  export, and an 11-tool MCP server at `POST /mcp`.
- **Triage tooling** — bookmarks, tags, annotations, session labels, custom rules with a live tester,
  and a process scanner that can kill / pause / resume agent CLIs.
- **Govern** — 12 plain-language policies ("agents must not read credential stores," "no destructive
  commands," …) evaluated against your own alert and enforcement history, each reporting **Held**,
  **Violated**, or **Not provable** — the third status exists on purpose, for when nothing was
  watching rather than nothing happened. A downloadable evidence pack backs every status with the
  underlying rows. It's software reporting on itself, not a certification: current framework
  coverage is roughly 10 of 72 NIST AI RMF subcategories and 7 of 38 ISO/IEC 42001 Annex A
  controls, and **zero** of the mandatory ISO clauses (4–10) — those are organizational, not
  something a runtime observer can satisfy. See [Governance](docs/govern/policies.mdx).

---

## Privacy & security

ClaudeSec reads sensitive material — your agents' commands, prompts, and file contents — so it is
local-first by construction. The server binds **`127.0.0.1` only** by default. **Secret scrubbing**
redacts known secret shapes, home paths, usernames, and emails before anything is stored, broadcast,
or exported. The SQLite database is created `0600`.

**Reads are open on loopback; changes need a paired browser.** A local TCP connection carries no
identity, so nothing in an HTTP request can tell your dashboard apart from anything else running as
you. Changing the enforcement mode, editing rules, or saving settings therefore needs a control
token that the server will never hand out in response to a request. Run `claudesec open` once: it
launches the dashboard with a one-time pairing key and the server swaps it for an `HttpOnly`
cookie. See [Privacy & security](docs/security/privacy.mdx).

**No egress**: there are four optional outbound paths, all off unless you set them and all
SSRF-guarded. They are `OTEL_FORWARD_URL` (forward OTLP traces), `CLAUDESEC_WEBHOOK_URL` (alert
delivery), `CLAUDESEC_JUDGE_URL` (the optional LLM judge, which may be a local model), and
`CLAUDESEC_ANCHOR_METHOD` (timestamp the audit anchor with an RFC 3161 authority or
OpenTimestamps). Anchoring sends only a 32-byte hash, never span content, commands, file paths,
or repository names.

For how these controls map to SOC 2, ISO 27001, GDPR, NIST AI RMF, and others, see
[`COMPLIANCE.md`](COMPLIANCE.md).

---

## Documentation

Full docs build into the dashboard's **Docs** tab (including the changelog). The MDX source lives
under [`docs/`](docs/):

- [Quickstart](docs/quickstart.mdx) — install and see live activity in under a minute.
- [Launch the full platform](docs/how-to/launch.mdx) — run from a clone or via Docker, across
  macOS / Linux / Windows, and connect your first agent.
- [Tour of the dashboard](docs/explanation/dashboard-tour.mdx) — what each screen is for.
- [Configuration reference](docs/reference/config.mdx) — every environment variable and its default.
- [Capture remote & CI agents (OTLP)](docs/how-to/remote-agents.mdx) — stream telemetry from
  machines ClaudeSec can't read from disk.
- [Use a local LLM as judge](docs/how-to/local-llm.mdx) — run an on-device model with Ollama or
  LM Studio.
- [Architecture](docs/architecture.mdx) — ingestion, storage, detection, and the two-process model.
- [Security rules](docs/security/rules.mdx) · [Enforcement](docs/security/enforcement.mdx) ·
  [Privacy & security](docs/security/privacy.mdx) · [MCP scanner](docs/security/mcp-scan.mdx).
- [Governance](docs/govern/policies.mdx) — the 12 policies, their statuses, and the evidence pack.
- [Data retention & capacity](docs/explanation/retention.mdx) — what's kept and how pruning works.
- [CLI reference](docs/reference/cli.mdx) — every `claudesec` command and flag.
- [API reference](docs/api-reference/introduction.mdx) and [`openapi.yaml`](openapi.yaml).
- Releasing this project: [`.github/RELEASING.md`](.github/RELEASING.md).

---

## Contributing

Contributions are welcome — see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md). Run `pnpm lint`
(TypeScript type-check) and `pnpm test` (rule self-test gate) before opening a PR.

To report a vulnerability, see [`.github/SECURITY.md`](.github/SECURITY.md).

---

## License

[AGPL-3.0-only](LICENSE) — copyright 2026 The ClaudeSec Authors. Commercial and dual-licensing
options are documented in [`.github/LICENSING.md`](.github/LICENSING.md).

Authored by [withkarann](https://github.com/withkarann) and
[aanjaneyasinghdhoni](https://github.com/aanjaneyasinghdhoni).
