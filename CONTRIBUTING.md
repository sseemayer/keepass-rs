# Contributing to keepass-rs

Thanks for your interest in contributing to keepass-rs! This document outlines our guidelines for contributing code, reporting issues, and other ways to get involved.


## Commit messages (Conventional Commits)

We follow the Conventional Commits specification. This keeps the history structured and makes changelogs easier to generate. A commit message should look like:

  feat(engine): add support for new KDF option

Please see https://www.conventionalcommits.org/ for the full specification and examples.

## Security issues

If you discover a security vulnerability, please do not create a public issue. Report it privately so the maintainers can triage and coordinate a fix:

- Preferred: use the repository's GitHub Security Advisories (via the Security tab) to report the issue privately.
- If that is not available, contact the maintainers privately (use the repository's security contact or the project website contact information).

When reporting, include a clear description, reproduction steps, affected versions, and any suggested mitigations. Avoid posting exploit details in public until a fix is available.

## KeePass test fixtures

When adding KeePass databases as test fixtures, follow these rules to keep tests fast and inspectable:

- Password: set the database password to the literal string `demopass`.
- KDF settings: use KDF parameters that complete quickly in CI and on developer machines. For example, use AES-KDF with 100 iterations (or equivalent low-cost settings for other KDFs).
- No secrets: do not include real or sensitive data in fixtures.
- Size: keep fixtures small (minimal groups/entries required for the test).

This repository deliberately uses inexpensive KDF settings for fixtures so tests run quickly and reliably in CI. If you need to validate behaviour with expensive KDFs locally, please create those databases outside of the repository and do not add them as fixtures.

## Further questions

If anything in this document is unclear, open an issue or ask a maintainer for clarification.

