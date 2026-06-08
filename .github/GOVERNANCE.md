# Governance

This document describes how ClaudeSec is governed: who makes decisions, how those
decisions are made and recorded, and how someone can take on more responsibility
over time. It is written to be honest and right-sized for what ClaudeSec actually
is — a maintainer-led open-source project, not a foundation. We have kept it
deliberately lightweight, and we would rather under-promise process than describe
a bureaucracy we do not run.

## Overview

ClaudeSec is a zero-config, fully-local security observatory for AI coding agents.
It is maintained by a small group of maintainers who are responsible for the
direction, quality, and long-term health of the project. Day-to-day work happens
in the open on GitHub through issues and pull requests, and anyone is welcome to
take part.

## Roles

### Maintainers

Maintainers are responsible for the project as a whole. In practice that means
reviewing and merging pull requests, triaging issues, setting direction and
scope, cutting releases, handling security reports, and making the final call when
a decision needs one. Maintainers are expected to act in the project's long-term
interest and to keep ClaudeSec aligned with its local-first, privacy-preserving
design.

The current maintainers are:

- [withkarann](https://github.com/withkarann)
- [aanjaneyasinghdhoni](https://github.com/aanjaneyasinghdhoni)

### Contributors

A contributor is anyone who submits a pull request, files or triages an issue,
improves documentation, reports a bug, or otherwise helps move the project
forward. You do not need to be invited and you do not need any special status to
contribute — opening a pull request is enough. Contribution guidelines live in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Decision-Making

We work by **lazy consensus**. Most changes do not need an explicit vote: if a
proposal or pull request is open and no maintainer objects within a reasonable
review window, it is considered accepted. Silence is taken as assent. This keeps
small, uncontroversial changes moving without ceremony.

When a decision is genuinely contested — a breaking change, a shift in scope or
direction, a security trade-off, or anything that would weaken the local-first
guarantees — maintainers discuss it openly and try to reach agreement. If
agreement cannot be reached, the maintainers have the final say. We aim to make
those calls transparently and to explain the reasoning, especially when we decide
against a contributor's proposal.

## How Decisions Are Recorded

Decisions are recorded where the work happens, in public, so the history is
self-documenting:

- **Issues** capture proposals, bug reports, and design discussion.
- **Pull requests** capture the change itself, the review conversation, and the
  approval that merged it.
- **Commit history and the [CHANGELOG](../CHANGELOG.md)** record what actually
  shipped and when.

We do not keep a separate decision log. The issue and pull-request trail is the
record of intent; the commit history and changelog are the record of outcome.

## Becoming a Maintainer

Maintainership is earned through sustained, high-quality contribution and good
judgment, not granted on request. There is no fixed checklist, but the things we
look for are consistent: a track record of merged pull requests, thoughtful and
constructive review of others' work, reliability in following through, and a
demonstrated understanding of the project's goals — especially its commitment to
keeping everything local and private by default.

When a contributor has built that track record, an existing maintainer may propose
adding them. The decision is made by the current maintainers using the same
consensus process described above.

## Releases

ClaudeSec follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and
notable changes are recorded in the [CHANGELOG](../CHANGELOG.md). The mechanics of
cutting a release — versioning, tagging, and the steps involved — are documented
in [`RELEASING.md`](RELEASING.md).

## Security

Security is handled separately from ordinary issues, and security vulnerabilities
should never be reported in public. The reporting process, supported versions, and
the project's security model are documented in [`SECURITY.md`](SECURITY.md).

## Code of Conduct

Everyone participating in the project is expected to follow our
[Code of Conduct](CODE_OF_CONDUCT.md). Maintainers are responsible for enforcing
it fairly and consistently.

## Licensing

ClaudeSec is licensed under **AGPL-3.0-only**. Contributions are accepted under
that same license; see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the details on how
contribution licensing works. Commercial and dual-licensing options for
organizations that cannot comply with the AGPL are documented in
[`LICENSING.md`](LICENSING.md).

## Amending This Document

This document can change as the project does. Amendments are proposed through a
pull request and adopted using the same decision-making process described above:
lazy consensus among maintainers, with maintainers having the final say. When the
way we work changes in practice, we will update this document so it keeps
describing reality rather than aspiration.
