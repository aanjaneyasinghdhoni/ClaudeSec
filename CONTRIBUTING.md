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

---

## Connecting Your Agent (Live Telemetry)

Before testing with a live AI agent, export these three environment variables:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3000/v1/traces
```

Restart your agent session after setting them. Spans will begin appearing in the dashboard immediately.

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
5. Test it via the **Simulate** button or a `curl` POST to `/v1/traces`.

---

## Adding Harness Support

Harness integrations live in `src/harnesses.ts`. The registry currently supports 14 agent frameworks. Each harness entry declares:

- `id` — unique slug used as graph node ID prefix
- `name` — display name shown in the UI
- `color` — Tailwind-compatible hex color for the agent node
- `description` — short description shown in the setup wizard
- `envVars` — environment variables the user must set (use `{{ENDPOINT}}` as placeholder)
- `serviceNamePattern` — regex to identify spans from this harness
- `spanAttributes` — known span attribute keys this harness emits
- `docsUrl` — link to the harness documentation

To add a new harness, add an entry to the `HARNESSES` array in `src/harnesses.ts` and create a corresponding docs page at `docs/harnesses/<id>.mdx`.

---

## Questions?

Open a [GitHub Discussion](https://github.com/aanjaneyasinghdhoni/ClaudeSec/discussions) — questions, ideas, and design proposals are all welcome there.
