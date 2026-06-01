# Contributing to ClaudeSec

Thank you for your interest in contributing! This guide covers everything you need to get started.

---

## Prerequisites

- **Node.js** >= 18
- **npm** >= 9 (comes with Node 18+)
- A terminal and a code editor

---

## Dev Setup

```bash
# 1. Fork and clone the repo
git clone https://github.com/<your-username>/ClaudeSec.git
cd ClaudeSec

# 2. Install dependencies
npm install

# 3. Start the dev server (Vite + Express in parallel)
npm run dev
```

The app is available at **http://localhost:3000**.

`npm run dev` runs the Express backend with Vite HMR in the foreground (no background service). To exercise the one-command install path during development, run `npx claudesec` from the repo.

---

## Generating test activity (live capture)

The transcript watcher captures your local agents automatically — just run Claude Code, GitHub Copilot CLI, or Codex in another terminal and activity will stream into the dashboard with no setup. See [How the watcher works](docs/explanation/watcher.mdx).

For agents on other machines or in CI, point them at the OTLP endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
```

You can also POST a synthetic OTLP payload directly to `http://localhost:3000/v1/traces` (see the curl example in the Quickstart docs) to test ingestion without a real agent.

---

## Submitting Changes

1. **Fork** the repository on GitHub.
2. **Create a branch** from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes, commit using the style below, then push.
4. Open a **Pull Request** against `master`. Fill in the PR template and link any related issues.

Keep PRs focused — one logical change per PR makes review much faster.

---

## Commit Style

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | When to use |
|--------|-------------|
| `feat:` | New feature or behaviour |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `chore:` | Build, tooling, deps — no production code change |
| `refactor:` | Code change that neither fixes a bug nor adds a feature |
| `test:` | Adding or updating tests |

Example: `feat: add prompt-injection detection rule`

---

## Code Style

- **TypeScript strict mode** is enabled — do not disable it.
- **No `any` casts** in new code. Use proper types or `unknown` with a type guard.
- Run `npm run lint` before pushing; the CI will fail otherwise.
- Formatting is handled by the existing ESLint + TypeScript config — keep it consistent.

---

## Adding a New Threat Rule

Threat-detection rules live in `server.ts` in the `SEVERITY_RULES` array. Each rule is an object with three fields:

```ts
{ pattern: /your-regex/i, severity: 'HIGH' | 'MEDIUM' | 'LOW', label: 'Short description of what this rule detects' }
```

Steps:
1. Open `server.ts` and locate `SEVERITY_RULES`.
2. Add your entry in the appropriate severity group (HIGH first, then MEDIUM, then LOW).
3. Include a comment explaining what the rule targets.
4. Add a matching entry to the threat-detection table in `README.md`.
5. Test it with a `curl` POST to `/v1/traces`, or by running a real agent whose action matches the pattern.

---

## Adding agent capture

ClaudeSec captures three agents automatically by tailing their on-disk session transcripts in `transcriptWatcher.ts`:

- **Claude Code** — `~/.claude/projects/**/*.jsonl`
- **GitHub Copilot CLI** — `~/.copilot/session-state/**/*.jsonl`
- **Codex** — `~/.codex/sessions/**/*.jsonl`

To support a new local agent, add a `HarnessKind`, a default root in `defaultRoots()`, and a record-mapper (modeled on `mapClaudeRecord` / `mapCodexRecord` / `mapCopilotRecord`) in `transcriptWatcher.ts`. Agents that export OpenTelemetry can stream in over the OTLP endpoint with no code changes (see [docs/how-to/remote-agents.mdx](docs/how-to/remote-agents.mdx)).

---

## Questions?

Open a [GitHub Discussion](https://github.com/aanjaneyasinghdhoni/ClaudeSec/discussions) — questions, ideas, and design proposals are all welcome there.
