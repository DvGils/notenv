# Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/DvGils/notenv/security/advisories/new), not a
public issue. Reports are acknowledged within **5 business days**, investigated, and a fix and
coordinated disclosure follow. We aim to assess every report and report back on next steps within
**14 days** of acknowledgement.

## Supported versions

Only the latest release receives security fixes. Upgrading is always safe: every 1.x release
interoperates with every other and never migrates your storage, so running the latest patch is the
fix path. When a new major version ships, the previous major receives critical security fixes on a
best-effort basis for six months, then reaches end-of-life. See the
[security policies](policies.md) for the full statement.

## Scope

The [threat model](threat-model.md) describes what notenv defends and, explicitly, what it does not. A
report that a documented **non-goal** is undefended is not a vulnerability; a report that a **stated
guarantee** does not hold is, and is welcome.
