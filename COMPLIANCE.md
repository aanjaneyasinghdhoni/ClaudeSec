# ClaudeSec Compliance & Controls Mapping

> **Status of this document.** ClaudeSec is open-source software, not a certified or
> audited product. Nothing here claims that ClaudeSec is "compliant with" or "certified
> against" any framework. ClaudeSec is **self-hosted software that a deployer runs inside
> their own environment**. This document explains which technical controls ClaudeSec
> *provides* and *supports*, and — just as importantly — which controls remain the
> **deployer's responsibility**. Certification is achieved by an organization's overall
> control environment, of which a tool is only one part.

---

## 1. Overview

ClaudeSec is a self-hosted, local-first security-observability tool for AI coding agents
(Claude Code, GitHub Copilot CLI, Codex, and any OpenTelemetry/OTLP-emitting agent). It
ingests agent activity, evaluates each span against ~673 deterministic threat-detection
rules, persists spans to a local SQLite database, streams them to a local dashboard, and
can optionally **enforce** (block) tool calls before they run.

Because ClaudeSec observes sensitive material — your agents' commands, prompts, and file
contents — it is designed to be **local-first by construction**: it binds to loopback by
default, performs no outbound calls unless explicitly configured, scrubs secrets before
storage, and ships no telemetry to its authors.

This document is intended for security and compliance reviewers evaluating ClaudeSec for
use in a regulated environment. It maps ClaudeSec's features to widely used control
frameworks and is explicit about the boundary between what the tool does and what the
deploying organization must still implement.

**Scope of evidence.** Every control claim below references a feature that exists in the
public repository. Primary references:
[`README.md`](README.md),
[`.github/SECURITY.md`](.github/SECURITY.md),
[`.env.example`](.env.example),
[`docker-compose.yml`](docker-compose.yml),
[`openapi.yaml`](openapi.yaml),
the CI workflows under [`.github/workflows/`](.github/workflows),
and the server modules under [`server/`](server) (notably `scrub.ts`, `ssrf.ts`,
`detection.ts`, `db.ts`).

---

## 2. Shared-Responsibility Model

ClaudeSec is unmanaged software. There is no ClaudeSec-operated service, no cloud
backend, and no data egress to its authors. As a result, the operational and governance
controls in any framework belong to the **deployer**. The split is summarized below.

| Area | ClaudeSec provides | Deployer must implement |
|---|---|---|
| **Hosting & data residency** | Runs entirely on hardware the deployer controls; SQLite stays on local disk | Choose and secure the host; meet residency/sovereignty requirements |
| **Network exposure** | Binds `127.0.0.1` by default; refuses to bind a non-loopback host without a token or explicit `CLAUDESEC_TRUST_LOCAL=1` | TLS termination, reverse proxy, VPN/firewall, network segmentation for any non-local exposure |
| **Authentication** | Optional bearer token (`CLAUDESEC_TOKEN`) gating non-loopback API/MCP/OTLP access | SSO/MFA, identity lifecycle, and access reviews at the network/identity layer |
| **Data at rest** | DB file created `0600` (owner-only); secret scrubbing before persistence | Disk/volume encryption (full-disk, LUKS, or equivalent); filesystem ACLs; backup protection |
| **Data minimization & retention** | Secret/PII scrubbing on by default; count- and age-based pruning (`CLAUDESEC_MAX_SPANS`, `CLAUDESEC_RETENTION_DAYS`) | Set retention to match policy; document lawful basis; honor data-subject requests |
| **Detection content** | ~673 built-in rules + custom-rule CRUD; honeytokens; optional MCP/skill scanner | Tune rules to environment; triage alerts; integrate with SIEM/incident process |
| **Enforcement** | **Opt-in and Claude-Code-only**: nothing blocks until the deployer installs the PreToolUse hook (one-command installer) — until then ClaudeSec only observes. Once installed it is `monitor` by default (only the always-on catastrophic floor — destructive commands plus two high-precision secret-exfiltration patterns — and user-defined protected paths block); `enforce` adds blocking of the broader high/critical (active exfiltration) tool calls. Custom regex rules detect by default; in `enforce` mode a high/critical custom rule also blocks (low/medium stay detect-only). Other agents are gated only via the cross-agent MCP proxy. **Fail-open** by design. Dashboard surfaces hook-registration status (no false green) | Install and verify the hook; decide policy; understand the fail-open, Claude-only, best-effort scope; layer an OS sandbox for hard isolation |
| **Governance** | Audit-quality event logs and reporting to feed a program | Policies, risk register, roles/accountability, training, vendor management, audits |

> **Read this first:** [`.github/SECURITY.md`](.github/SECURITY.md) states plainly that
> ClaudeSec ships **no authentication, no TLS, and no encryption at rest by default**. Those
> are deliberate consequences of the local-first design and are the deployer's
> responsibility to add for any non-local or regulated deployment. This document does not
> contradict that — it explains how the tool's controls *support* the deployer in closing
> those gaps.

---

## 3. Framework Mapping

Mappings use the verbs **"maps to," "supports," and "helps satisfy."** They never assert
"compliant" or "satisfies in full." Each row separates the tool-provided control from the
deployer obligation. Control identifiers are taken from the published frameworks.

### 3.1 SOC 2 (AICPA Trust Services Criteria)

| TSC | Criterion | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **CC6.1** | Logical access security measures | Loopback-only default bind; **bind-refusal guard** that exits rather than expose a non-loopback host without a token; a **control token** on every local mutation, paired out of band and never issued in response to an HTTP request; optional `CLAUDESEC_TOKEN` for remote access; `0600` DB file | MFA/SSO, identity store, password policy, privileged-access management |
| **CC6.6** | Access restricted from external threats | No egress by default; the four outbound paths (`OTEL_FORWARD_URL`, `CLAUDESEC_WEBHOOK_URL`, `CLAUDESEC_JUDGE_URL`, and audit anchoring via `CLAUDESEC_ANCHOR_METHOD`) are off unless set and pass an SSRF guard | Network segmentation, IDS/IPS, perimeter controls |
| **CC6.7** | Transmission of data protected | Optional bearer-token auth on remote API/OTLP; SSRF guard blocks egress to private/loopback/metadata ranges | **TLS in transit** (terminate at a reverse proxy) — not provided by the tool |
| **CC7.1** | Vulnerability & malware detection | ~673 threat rules covering credential theft, reverse shells, supply-chain attacks, exfiltration (a dedicated `critical` tier for active off-machine secret transmission), cloud-metadata SSRF, container escape; MCP/skill static scanner | Endpoint EDR, host vulnerability scanning, patch cadence |
| **CC7.2** | Monitoring for security events | Real-time span ingestion + live alerting; Prometheus `/metrics`; webhook delivery of HIGH alerts; honeytokens | Central SIEM, alert triage SLAs, on-call rotation |
| **CC7.3 / CC7.4** | Incident evaluation, containment & response | Per-session security reports (`cli/init.mjs report`); the opt-in, Claude-Code-only enforcement hook/proxy can block a tool call before it runs (`enforce` mode, or the always-on floors in any mode) once the deployer installs it — best-effort and fail-open, and the dashboard verifies the hook is registered before claiming blocking is active | Documented IR plan, runbooks, post-incident reviews; install/verify the hook; do not treat fail-open blocking as containment |
| **CC8.1** | Authorized, tested changes | The project's own SDLC: SHA-pinned GitHub Actions, `pnpm install --frozen-lockfile`, type-check + build gates, ReDoS rule self-test gate as a `prebuild` step | The deployer's own change-management process |

### 3.2 ISO/IEC 27001:2022 (Annex A)

| Annex A | Control | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **A.8.11** | Data masking | **Secret scrubbing** (`server/scrub.ts`): keys, tokens, JWTs, cloud credentials, database connection-string credentials, home paths, usernames, and emails are redacted before anything is stored, broadcast, or exported (on by default). Alert `matchedText` is stored **already scrubbed** — even a `critical` exfiltration alert records the secret *type / redacted shape*, never the live value | Classification scheme; verifying masking meets policy (scrubbing is best-effort regex) |
| **A.8.12** | Data leakage prevention | A dedicated `critical` severity tier flags active secret **exfiltration** — a credential / `.env` being transmitted off the machine (the broad critical tier blocks in `enforce` mode, while two high-precision read-secret-and-send-it patterns sit on the always-on floor and block in either mode once the opt-in hook is installed); honeytokens fire an exfiltration alert on any match; broader exfiltration rules in the detection set | Enterprise DLP, egress monitoring |
| **A.8.15** | Logging | Every span persisted with nanosecond timing; structured, queryable audit trail of tool calls, commands, and file access; the spans ledger, the operator audit log, and the enforcement block-feed are hash-chained (tamper-*evident*) under an Ed25519-signed tail anchor. The chain **re-anchors** on retention pruning (so pruning is not mistaken for tampering) and flags a wholesale wipe; `GET /api/audit/verify` reports both. **Two span fields are deliberately outside the hash**: `endNano` (written by an `UPDATE` when a tool call finishes, after the span was already inserted and chained at start) and `repo` (often inserted as `unknown` and corrected in place once the working directory resolves) — both are mutated by this same server after the row is first hashed, so a hash that covered them would break on the server's own ordinary writes. Excluding them is honest about the consequence: **duration and repository attribution are not tamper-evident**; everything else about a span — its identity, its content, its place in the sequence — is | Log retention policy, time-source governance; tamper-evidence is detective, not preventive — it does not stop a same-UID attacker who recomputes the chain or truncates the tail. Protect the key/DB |
| **A.8.16** | Monitoring activities | Continuous evaluation of every span against the rule set; live anomaly surfacing and alerting | SOC processes, correlation across other sources |
| **A.8.23** | Web filtering / egress control | SSRF guard (`server/ssrf.ts`) DNS-resolves targets at call time and allows only globally-routable unicast addresses — blocking loopback, private, link-local, and `169.254.169.254` metadata; re-resolves on every request to defeat DNS rebinding | Proxy/filtering at the network layer |
| **A.8.25 / A.8.28** | Secure development lifecycle / secure coding | CodeQL static analysis (weekly + on PR), `pnpm audit --prod`, RE2/linear-time regex compilation for ReDoS safety, ReDoS self-test gate | Applies to the *project*; deployer runs own SDLC for its systems |
| **A.5.23** | Information security for cloud services | Local-first by construction; no third-party cloud dependency unless the deployer adds one | Cloud-provider due diligence if hosted in cloud |
| **A.8.10** | Information deletion | Age- and count-based pruning (`CLAUDESEC_RETENTION_DAYS`, `CLAUDESEC_MAX_SPANS`); `POST /api/reset` is disabled unless `CLAUDESEC_ALLOW_RESET=1` | Deletion policy, certificate-of-destruction processes |

### 3.3 AI Governance — NIST AI RMF 1.0, ISO/IEC 42001:2023, EU AI Act

> **Positioning, stated plainly.** ClaudeSec is **not itself a high-risk AI system** and is
> **not a GPAI model**. Its detection engine is **deterministic regular-expression matching**.
> The only generative component — the optional LLM-as-judge — is **off by default**, runs
> locally, and makes zero network calls unless explicitly configured. ClaudeSec is an
> **instrument that helps a deploying organization govern the AI agents *it* operates**. The
> AI Management System (AIMS), policies, risk tolerance, and accountability structures are
> the **deployer's** responsibility; ClaudeSec provides the operational monitoring,
> record-keeping, and oversight tooling that those programs require.

**The Govern tab and its coverage, stated in numbers.** The dashboard's **Govern** category
evaluates 12 plain-language policies (`server/governance.ts`) against your own alert and
enforcement history and reports each as **Held**, **Violated**, or **Not provable** — never a
score or a percentage, and "Held" never means "this did not happen," only that nothing matched
within the window ClaudeSec still holds (see the in-app "what Held means" note, printed on every
surface that shows the word). A downloadable evidence pack bundles the underlying alert,
enforcement, and audit-log rows behind each status. Measured against the frameworks in this
document, current coverage is:

| Framework | Coverage claimed |
|---|---|
| NIST AI RMF 1.0 subcategories | ~10 of 72 |
| ISO/IEC 42001:2023 Annex A controls | 7 of 38 |
| ISO/IEC 42001:2023 mandatory clauses (4–10) | **0 of 7** — these are organizational (policy documents, management review, accountability); no runtime observer can satisfy them |

The GOVERN function of NIST AI RMF is almost entirely untouched by this layer (19 of its 21
subcategories require people and paper, not a process watching a shell). This is one system
reporting on itself — no independent party, no external time anchor — and it is explicitly not
"ISO 42001 compliant" or "NIST AI RMF certified." See the pack's own coverage section for the
full, current list of claimed identifiers.

**NIST AI RMF 1.0**

| Subcategory | Function | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **MEASURE — MS-3.1 / MS-3.2** | AI risk tracked over time | Continuous post-deployment monitoring of agent behavior; per-session health scoring surfaces degradation and anomalous activity | Defining metrics/thresholds; periodic review cadence |
| **MEASURE — MS-2.4** | Security & privacy assessed | Detection of credential theft, exfiltration, prompt-injection patterns in agent activity; MCP/skill scanner | Formal pre-deployment evaluation of the deployer's AI systems |
| **MANAGE — MG-2.3** | Emergency interventions | Once the opt-in, Claude-Code-only hook is installed, `enforce` mode + the always-on catastrophic floor and protected paths (e.g. `rm -rf /`, fork bombs, piped RCE) act as a best-effort, fail-open tool-call-level intervention, with the dashboard verifying the hook is registered before claiming blocking is active; process scanner can pause/kill agents | A real "kill switch" / org-level shutdown authority — fail-open blocking is not one |
| **MANAGE — MG-3.2** | AI incidents documented & investigated | Persistent span store + per-session security reports + webhook alerting provide an incident evidence trail; the spans ledger, the operator audit log and the enforcement block-feed are **hash-chained** under an Ed25519-signed tail anchor (tampering is *detectable*, not prevented, and completeness is never claimed; verifiable via `GET /api/audit/verify`) | Incident log, severity classification, post-incident review |
| **GOVERN — GV-1.x / GV-4.x** | Policies, cross-functional escalation | (Tool provides evidence inputs only) | **Deployer obligation** — policies, accountability, escalation paths are organizational, not tool features |

**ISO/IEC 42001:2023 (Annex A)**

| Control | Name | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **A.6.2.6** | AI system operation and monitoring | Real-time, continuous monitoring of AI agent operations with alerting on anomalies | Defining alert thresholds and remediation processes |
| **A.6.2.8** | AI system recording of event logs | Durable, queryable event logs of every agent tool call (the spans/alerts tables) sufficient for incident investigation and audit; the enforcement would-block/block feed is persisted to SQLite and **hash-chained** (survives restart); deleted spans leave a tombstone carrying their chain link, so retention destroys the data without destroying the evidence that it existed | Log retention periods and access controls per policy |
| **A.8.4** | Communication of incidents | Webhook delivery of HIGH-severity alerts to Slack/Discord/JSON endpoints; per-session reports | Notification thresholds, regulatory/affected-party reporting |
| **A.9.2** | Processes for responsible use of AI systems | Once installed, the opt-in, Claude-Code-only enforcement layer can gate agent tool calls against an acceptable-use rule set (`monitor`/`enforce`) on a best-effort, fail-open basis, with the dashboard verifying the hook is registered before claiming blocking is active | The acceptable-use policy itself and human-oversight procedures; not relying on fail-open gating |
| **A.2.2 / A.3.2 / A.5.2** | AI policy, roles, impact assessment | (Deployer obligation) | **Deployer owns** the AIMS, policy, RACI, and AI impact assessments |

**EU AI Act**

| Reference | Topic | How ClaudeSec relates | Notes |
|---|---|---|---|
| **Art. 6 / Annex III** | High-risk classification | ClaudeSec is **not** an Annex III high-risk use case and is **not** a safety component under Annex I | It is a developer security tool, not a system making decisions about people |
| **Art. 26** | Deployer obligations (human oversight, monitoring, log-keeping) | ClaudeSec **supports a deployer** in meeting monitoring and automatically-generated-log retention duties for high-risk AI systems they operate. Art. 26(6) expects logs kept **at least six months**: the default **Minimum** profile is 183 days paired with a 1,000,000-span ceiling, sized so a realistic workload (~3,500 spans/day) reaches the full six months instead of having ingestion pause at 90% of a too-small ceiling. **Audit year** (400 days / 5,000,000) covers a longer sampling period. If you set the two values by hand, check the effective window reported by `/api/db-stats` — a ceiling below the window's own volume stops recording early | The legal obligation remains the deployer's — including choosing a profile that matches the period you must retain, and sizing disk for it |
| **Art. 50** | Transparency for AI interaction / generated content | Relevant only if the optional local LLM-judge is enabled; its output is internal classification, not user-facing generated content | Off by default; deployer assesses applicability if enabled |
| **Art. 3 (GPAI)** | GPAI model obligations | **Not applicable** — ClaudeSec trains and ships no model | — |

### 3.4 Privacy — GDPR

> **Role determination.** The ClaudeSec project operates no service and receives no data
> (no telemetry-home, no egress by default). Therefore the **ClaudeSec project is neither a
> controller nor a processor**; the **deploying organization is the sole data controller**
> for any personal data its agents' activity contains. There is no processor relationship,
> so **no Data Processing Agreement applies** between the deployer and the ClaudeSec authors.

| Article | Requirement | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **Art. 25** | Data protection by design & by default | Loopback-default bind, no egress by default, and **secret/PII scrubbing on by default** are privacy-protective defaults | Configuring the deployment to its risk profile |
| **Art. 32** | Security of processing | `0600` DB permissions; SSRF egress guard; pseudonymization of identifiers via scrubbing | **Encryption at rest and in transit** (not provided), access control, breach detection |
| **Art. 5(1)(c)** | Data minimization | Scrubbing removes secrets, home paths, usernames, and email local-parts before storage | Deciding which spans/attributes are necessary |
| **Art. 5(1)(e)** | Storage limitation | Configurable age- and count-based retention; automatic pruning | Setting retention to match policy; documenting it |
| **Art. 17** | Right to erasure | `POST /api/reset` (gated by `CLAUDESEC_ALLOW_RESET`) and pruning provide deletion mechanisms | Operationalizing data-subject request handling |
| **Art. 30 / 35** | RoPA, DPIA | (Deployer obligation) | **Deployer owns** records of processing and any DPIA |

> **Honest limitation.** Secret/PII scrubbing is **best-effort pattern matching**. It
> redacts known secret shapes and identifiers but cannot guarantee removal of every
> sensitive value an agent may emit. At-rest data is **not encrypted** by the tool. Treat
> the database as sensitive and apply disk encryption and filesystem controls accordingly.

### 3.5 CIS Controls v8

| Control | Safeguard(s) | How ClaudeSec supports it | Deployer still owns |
|---|---|---|---|
| **Control 8 — Audit Log Management** | 8.2 Collect audit logs; 8.5 Detailed logs; 8.11 Review logs | Collects detailed, structured logs of every agent tool call; dashboard + CLI support review | 8.3 Log storage sizing; 8.10 retention duration |
| **Control 16 — Application Software Security** | 16.1 Secure SDLC; 16.2/16.4 vuln intake; 16.5 trusted components; 16.12 code-level checks | The project's own posture: CodeQL, `pnpm audit --prod`, SHA-pinned actions, Dependabot (npm + actions, weekly), `frozen-lockfile`, ReDoS self-test, RE2 linear-time regex | The deployer's own application security program |
| **Control 13 — Network Monitoring & Defense** | 13.1 Centralize alerting; 13.2 host-based detection | Centralized, real-time alerting on agent activity; behavioral detection across sessions | Network-layer IDS/IPS, flow logs |
| **Control 3 — Data Protection** | 3.1 management process; 3.4 retention; 3.5 disposal | Scrubbing, configurable retention, gated reset/disposal | 3.6/3.11 encryption at rest; 3.13 DLP |
| **Control 17 — Incident Response** | 17.2 contact info; 17.4 IR process | Evidence trail + per-session reports + alert routing feed an IR process; [`SECURITY.md`](.github/SECURITY.md) defines a vulnerability-reporting path | The IR plan, roles, and exercises |
| **Control 6 — Access Control** | 6.1/6.2 grant/revoke; 6.3 MFA for exposed apps | Token gate for non-loopback access; bind-refusal guard | MFA, RBAC, and access reviews at identity layer |

---

## 4. Data Handling & Privacy

- **What data is processed.** OpenTelemetry spans describing AI-agent activity: tool
  names, command lines, file paths, and (when enhanced telemetry is enabled) prompts and
  arguments. This material **may contain secrets or personal data** by nature.
- **Where it lives.** A single local SQLite database at `~/.claudesec/spans.db`, created with
  `0600` (owner-only) permissions, plus hourly JSON snapshots in `exports/` (also `0600`; the
  most recent 24 are kept) and periodic online binary backups in `~/.claudesec/backups/` (`0600`;
  the most recent 7 are kept). Nothing is stored off the host. The **evidence material that
  proves the record** is separate: the Ed25519 audit signing key and the signed tail anchor live
  under `CLAUDESEC_HOME` (`~/.claudesec` by default), not beside the database. **A backup of the
  database alone is therefore not a complete backup of the audit record** — the chain cannot be
  verified without the signing key, and the chain's boundaries cannot be checked without the
  anchor. Retain the two together for whatever period your log-retention policy sets, and record
  the key's fingerprint (`keyId`) off-box so a re-founded identity is detectable.
- **Secret & PII scrubbing.** On by default. Before any span is persisted, broadcast, or
  exported, `server/scrub.ts` redacts known secret formats (API keys, tokens, JWTs, cloud
  credentials, private keys, database connection-string credentials), home directory paths,
  OS usernames, and the local-part of email addresses. The same scrubbing runs on alert
  `matchedText`, so a `critical` exfiltration alert stores the secret *type / redacted shape*
  only — never the live credential. Disable only with `CLAUDESEC_DISABLE_SCRUB=1`. Scrubbing
  is best-effort.
- **Retention.** Two settings act together and are configured together as a **profile**:
  `CLAUDESEC_RETENTION_DAYS` (the age window) and `CLAUDESEC_MAX_SPANS` (the span
  ceiling). The shipped profiles are:

  | Profile | Days | Span ceiling | What it is for |
  |---|---|---|---|
  | **Minimum** (default) | 183 | 1,000,000 | A six-month window that a normal workload can actually reach |
  | **Audit year** | 400 | 5,000,000 | A year plus a ~35-day tail, so day one of the period is still present at audit time |
  | **Forensic** | unbounded | unbounded | Keep everything; growth is bounded only by disk |
  | **Custom** | any | any | Both values explicit; the effective window is reported back |

  **How the two interact — the part that is easy to get wrong.** The age window is a
  hard floor: count-based pruning may only reclaim spans that are *already* past the
  age cutoff, so the span ceiling can never shorten the window by deleting data. What
  it *can* do is stop new data arriving — OTLP ingestion pauses at **90% of the
  ceiling**, and if the ceiling is smaller than the window's own volume, nothing is
  ever prunable to relieve it and recording stops for good. A ceiling of 50,000 spans
  against a 183-day window ends ingestion in roughly **twelve days** on a workload of
  ~3,500 spans/day. Profiles size the two together so this cannot happen by default.
  A custom pair is allowed, and `/api/db-stats` reports the **effective window** —
  which limit governs, and the real number of days at the install's own measured
  ingest rate — so the discrepancy is visible rather than silent. Note that an
  environment variable **overrides** a value saved from the dashboard; that override
  is reported too.
- **Deletion.** Pruning is automatic; full wipe via `POST /api/reset` is **disabled by
  default** and requires `CLAUDESEC_ALLOW_RESET=1` to prevent accidental data loss.
- **No telemetry-home.** ClaudeSec sends nothing to its authors. There are exactly four
  operator-configured outbound paths: `OTEL_FORWARD_URL`, `CLAUDESEC_WEBHOOK_URL`,
  `CLAUDESEC_JUDGE_URL`, and audit anchoring (`CLAUDESEC_ANCHOR_METHOD=tsa|ots`). Each is off
  unless set and each is SSRF-guarded. The first three can carry span-derived content, scrubbed.
  The anchoring path is different in kind: it transmits **only a 32-byte SHA-256 digest** of the
  audit anchor, never span content, commands, file paths, or repository names, so a Time-Stamp
  Authority or OpenTimestamps calendar learns that this install seals a record and nothing about
  what the record contains.

---

## 5. Security Controls

- **Network & authentication.** Binds `127.0.0.1` by default. A **bind-refusal guard**
  refuses to start on a non-loopback host unless `CLAUDESEC_TOKEN` is set or
  `CLAUDESEC_TRUST_LOCAL=1` is explicitly chosen. When set, the token gates all
  non-loopback API, MCP, and OTLP access (bearer header, `x-api-key`, or query token).
- **SSRF guard.** All operator-configured outbound fetches pass through `server/ssrf.ts`,
  which requires http/https, **DNS-resolves the target at call time**, and allows only
  globally-routable unicast addresses — transparently blocking loopback, private,
  link-local, CGNAT, and `169.254.169.254` cloud-metadata ranges, and defeating DNS
  rebinding by re-resolving on every request.
- **Data at rest.** DB file is `0600`. The tool does **not** encrypt at rest; pair with
  disk/volume encryption.
- **Container hardening.** The Docker image runs as the non-root `node` user (via
  `su-exec`) and publishes the host port on `127.0.0.1` only.
- **Supply chain & CI.** GitHub Actions are **pinned by commit SHA**; `pnpm install
  --frozen-lockfile` enforces the lockfile; `pnpm audit --prod --audit-level high` gates
  the build; CodeQL runs on every PR and weekly; Dependabot tracks the project's Node/pnpm
  dependencies and GitHub Actions weekly (via the `npm` ecosystem provider, which reads pnpm
  lockfiles); CI fails if any database file is accidentally tracked.
- **Detection-engine safety.** Custom rules compile with RE2 (linear-time, ReDoS-safe); a
  rule self-test gate (`tests/ruleSelfTest.ts`) enforces ReDoS heuristics, a deduplication
  check, and a false-positive gate, and runs as a `prebuild` step so a bad rule fails the
  build.
- **Enforcement, honestly scoped.** Enforcement is **opt-in**: ClaudeSec **blocks nothing
  until the deployer installs the hook** — until then it only observes. The PreToolUse hook
  is **Claude-Code-only** (other agents are gated only when routed through the MCP proxy),
  and both the hook and proxy are an **agent-specific** layer, **not an OS sandbox**. Both
  **fail open**: any error, missing config, or unparseable input results in *allow*. The
  hook is bypassable (`CLAUDESEC_HOOKS_BYPASS=1`). A one-command, consent-gated installer
  (`claudesec install-hook` / `uninstall-hook`) registers and removes the hook; its rules
  snapshot is built from in-repo rule source at install time (no network). Two floors block
  in **either mode** once installed: the always-on catastrophic floor (destructive
  commands plus two high-precision secret-exfiltration patterns) and any
  **user-defined protected paths** (file/directory targets marked in the dashboard, denied on
  read, write, edit, and delete); everything else blocks only in `enforce` — including
  **high/critical custom regex rules** (low/medium custom rules stay detect-only). Mode precedence
  is deterministic and documented (`enforce-config.json` → `CLAUDESEC_MODE` → `monitor`
  default) and surfaced on the dashboard, which also **verifies the hook is registered** and
  will not show a "blocking active" state unless enforce is effective *and* a hook is
  present (no false green). The hook's always-on catastrophic floor is parity-tested in the
  test gate (`tests/catastrophic-parity.test.ts` covers `cli/hooks/claudesec-enforce.cjs`), and a
  behavioral parity test (`tests/enforceParityTest.ts`) pins the **MCP proxy's verdicts to the
  hook's** so the cross-agent layer enforces the *same* floors and rules — including the catastrophic
  floor against the **raw command** a command-shaped `tools/call` carries (not the serialized JSON
  blob), and the **SSRF-on-fetch floor** for a fetch-shaped MCP tool, so a non-Claude-Code agent
  routed through the proxy cannot reach an internal/metadata host either. The floor patterns are
  proven linear-time. The **protected-paths floor ships a small, conservative default set** that is
  protected out of the box and **user-removable** — `~/.ssh`, `~/.aws/credentials`, `~/.config/gcloud`,
  `~/.kube/config`, `~/.npmrc`, and `.env`-style secret files (matched by shape, with
  `.env.example`/`.sample`/`.template` carve-outs). A **self-protection floor** always blocks (either
  mode) any agent write to the enforcement control plane — `~/.claudesec/hooks/` plus the Claude Code
  settings that register the hook, at **both** the home-dir and **project-level** (`./.claude/`) scopes.
  For `Edit`/`Write` the hook **blocks on the file path + action** (against protected paths) plus a
  minimal high-confidence live-secret floor on the content — it does **not** scan the file body against
  the rule set, so legitimate edits to security code or test fixtures are not blocked (full-content
  threat *detection* still runs server-side). With the hook installed, a `WebFetch` to a
  cloud-metadata / link-local address is blocked in either mode, and loopback/private ranges in
  `enforce` (opt-out via `CLAUDESEC_ALLOW_LOCAL_FETCH`); a public name that resolves to an internal
  IP (DNS rebinding) is a known gap the synchronous hook does not catch. Protected-path checks resolve
  symlinks (realpath) before matching; a time-of-check/time-of-use race remains an inherent residual
  limitation.
- **Threat-model boundary — same-user (same-UID) ceiling.** ClaudeSec defends against a
  *misbehaving agent*, not a hostile process running as the operator's own account. Enforcement is
  best-effort and **fail-open**, covering the Claude Code PreToolUse hook and the MCP proxy — not
  arbitrary egress. Mutating routes need a **control token** even on loopback, and reads still need
  nothing. That token is never issued in response to an HTTP request — loopback TCP carries no user
  or process identity, so no request header can distinguish the operator's browser from another
  local process. It is a pairing key stored `0600` under the self-protected hooks directory and
  presented once by `claudesec open`. This closes the HTTP-only path to mutation entirely; it does
  **not** remove the same-UID ceiling, because a process running as the operator can read that file
  and then change the enforcement **mode** or clear **user-added** protected paths. Only a separate
  OS user closes that, and ClaudeSec does not claim to. The **always-on floors** (catastrophic, self-protection, live-secret,
  cloud-metadata SSRF, and the **default** protected paths) remain in force regardless of mode. The audit log is
  tamper-**evident** (it detects in-place edits, reordering, and deletion via the chain, and a
  wholesale wipe via reset detection) but **not** tamper-**proof**: a same-UID attacker who can
  recompute the whole chain and read the local Ed25519 signing key — stored under the self-protected
  hooks directory, or optionally moved into the macOS Keychain (`claudesec audit-key to-keychain`),
  both of which raise the bar without eliminating it — can forge a consistent history;
  **tail-truncation** of the newest rows is the residual gap. For a threat model that includes a
  hostile same-user process, layer an OS sandbox, separate account, or container boundary beneath
  ClaudeSec.

---

## 6. Industry-Specific Frameworks

These regimes regulate the **deploying organization**, not ClaudeSec. ClaudeSec provides
controls that *support* a deployer's program; it does not by itself confer compliance.

- **HIPAA (US healthcare).** ClaudeSec supports the Security Rule's audit-controls
  (§164.312(b)) and information-system-activity-review (§164.308(a)(1)(ii)(D)) expectations
  by logging and monitoring agent activity. **Deployer must** execute Business Associate
  Agreements with any third parties, encrypt ePHI at rest and in transit (not provided by
  the tool), and govern access. Do not feed unscrubbed ePHI into spans.
- **PCI DSS (payment cards).** Supports Requirement 10 (logging and monitoring of access)
  and Requirement 6 secure-development expectations via the project's SDLC. **Deployer
  must** handle network segmentation (Req. 1), encryption (Req. 3/4), and access control
  (Req. 7/8). ClaudeSec must not store cardholder data; scrubbing reduces but does not
  guarantee removal.
- **FedRAMP / NIST SP 800-53 (US government).** Maps conceptually to the AU (Audit &
  Accountability) and SI (System & Information Integrity) families through logging,
  monitoring, and detection. **Deployer must** operate the full authorization boundary,
  control inheritance, and continuous-monitoring program; the tool is one inheritable
  control source, not an ATO.

---

## 7. Reporting a Vulnerability

Please report security issues responsibly via the process in
[`.github/SECURITY.md`](.github/SECURITY.md) — GitHub Security Advisories (preferred) or
direct maintainer contact. **Do not open a public issue for a vulnerability.** Reports are
acknowledged within 48 hours, with a status update targeted within 7 days and a patch release
targeted within **14 days** for critical issues, under a coordinated-disclosure process. These
are targets a solo maintainer can meet, not a contractual SLA.

---

*This document describes software controls and deployer responsibilities. It is not legal
advice and does not assert certification against any standard. For regulated deployments,
validate the control environment with a qualified auditor or your compliance function.*
