# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ClaudeSec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use one of these methods:

1. **GitHub Security Advisories** (preferred): Go to the [Security tab](https://github.com/aanjaneyasinghdhoni/ClaudeSec/security/advisories) and click "Report a vulnerability".
2. **Email**: Contact the maintainers directly via their GitHub profiles.

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

---

## Security Model

ClaudeSec is designed as a **local-first** tool. It runs on `localhost` and is intended for individual developer workstations.

### What ClaudeSec does

- Ingests OTLP traces on `localhost:3000` and stores them in a local SQLite database (`spans.db`).
- Evaluates every span against 183 built-in regex rules to detect suspicious patterns.
- Broadcasts updates to connected browser clients via Socket.io.
- Optionally forwards traces to an upstream OTLP collector (`OTEL_FORWARD_URL`).

### What ClaudeSec does NOT do

- **No authentication** — There is no built-in auth on API endpoints. If you expose ClaudeSec beyond localhost, you must add authentication at the network layer (reverse proxy, VPN, etc.).
- **No TLS** — The dev server runs plain HTTP. For non-local deployments, terminate TLS at a reverse proxy.
- **No data encryption at rest** — SQLite stores data unencrypted on disk. Protect the `spans.db` file with appropriate filesystem permissions.

### Known Limitations

- The threat detection engine uses pattern matching (regex). It can produce false positives and is not a substitute for comprehensive security monitoring.
- The process scanner uses `ps aux` to detect running agents. This is informational and should not be relied upon as a security control.
- Webhook delivery retries are best-effort. Critical alerting should use a dedicated incident management system.

---

## Best Practices

- Run ClaudeSec on `localhost` only, or behind a VPN/firewall.
- Do not expose the dashboard or API to the public internet without adding authentication.
- Regularly review and clear exported data in the `exports/` directory.
- Keep ClaudeSec updated to receive the latest security rule additions.

---

## Responsible Disclosure

We follow a coordinated disclosure process:

1. Reporter submits vulnerability details privately.
2. We confirm the issue and begin work on a fix.
3. We release a patched version.
4. We publicly disclose the vulnerability with credit to the reporter (unless anonymity is requested).

Thank you for helping keep ClaudeSec and its users safe.
