# Contributing to ClaudeSec

Thank you for your interest in contributing! This guide covers everything you need to get started.

---

## Prerequisites

- **Node.js** >= 22.13.0
- **pnpm** >= 11 — managed automatically via [corepack](https://nodejs.org/api/corepack.html) (ships with Node 22+)
- A terminal and a code editor

---

## Dev Setup

```bash
# 1. Fork and clone the repo
git clone https://github.com/<your-username>/ClaudeSec.git
cd ClaudeSec

# 2. Enable corepack so Node activates the pinned pnpm version automatically
corepack enable

# 3. Install dependencies
pnpm install

# 4. Start the dev server (Vite + Express in parallel)
pnpm dev
```

The app is available at **http://localhost:3000**.

`pnpm dev` runs the Express backend with Vite HMR in the foreground (no background service). To exercise the one-command install path during development, run `node cli/init.mjs` from the repo — ClaudeSec is not published to npm, so there is no `npx` equivalent.

---

## Generating test activity (live capture)

The transcript watcher captures your local agents automatically — just run Claude Code, GitHub Copilot CLI, or Codex in another terminal and activity will stream into the dashboard with no setup. See [How the watcher works](../docs/explanation/watcher.mdx).

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
- Run `pnpm lint` before pushing; the CI will fail otherwise.
- Formatting is handled by the existing ESLint + TypeScript config — keep it consistent.

---

## Adding a New Threat Rule

The core threat-detection rules live in `server/detection.ts` in the `CORE_SEVERITY_RULES` array; the extended rule set lives in `server/severityRulesExtra.ts`. Each rule is an object with three fields:

```ts
{ pattern: /your-regex/i, severity: 'high' | 'medium' | 'low', label: 'Short description of what this rule detects' }
```

Steps:
1. Open `server/detection.ts` and locate `CORE_SEVERITY_RULES` (or add to `server/severityRulesExtra.ts` for the extended set).
2. Add your entry in the appropriate severity group (high first, then medium, then low).
3. Include a comment explaining what the rule targets.
4. Add a matching entry to the threat-detection table in `README.md`.
5. Test it with a `curl` POST to `/v1/traces`, or by running a real agent whose action matches the pattern.

---

## Adding agent capture

ClaudeSec captures three agents automatically by tailing their on-disk session transcripts in `transcriptWatcher.ts`:

- **Claude Code** — `~/.claude/projects/**/*.jsonl`
- **GitHub Copilot CLI** — `~/.copilot/session-state/**/*.jsonl`
- **Codex** — `~/.codex/sessions/**/*.jsonl`

To support a new local agent, add a `HarnessKind`, a default root in `defaultRoots()`, and a record-mapper (modeled on `mapClaudeRecord` / `mapCodexRecord` / `mapCopilotRecord`) in `transcriptWatcher.ts`. Agents that export OpenTelemetry can stream in over the OTLP endpoint with no code changes (see [docs/how-to/remote-agents.mdx](../docs/how-to/remote-agents.mdx)).

---

## Licensing of Contributions

By submitting a pull request or patch you agree that your contribution is made under the
same **AGPL-3.0-only** license that governs the project (see [`LICENSE`](../LICENSE)).

Because ClaudeSec is offered under a dual-licensing model (open-source AGPL + a separate
commercial license), note the distinction between two mechanisms:

- A **Developer Certificate of Origin (DCO)** sign-off (`Signed-off-by:` in the commit
  message) certifies that you have the right to contribute the code under the existing
  project license. It does **not** grant the maintainers the additional rights needed to
  offer your contribution under a separate commercial license.
- A **Contributor License Agreement (CLA)** explicitly grants the maintainers those
  additional rights, which is what makes dual-licensing legally sound.

No CLA process is currently required. If one is introduced, full details and a simple
sign-off mechanism will be provided before it takes effect. Your rights under the AGPL
are never affected by the dual-licensing arrangement.

---

## Questions?

Open a [GitHub Discussion](https://github.com/aanjaneyasinghdhoni/ClaudeSec/discussions) — questions, ideas, and design proposals are all welcome there.
