# Security policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/DvGils/notenv/security/advisories/new), not a
public issue. Reports are acknowledged within **5 business days**, investigated, and a fix and
coordinated disclosure follow. We aim to assess every report and report back on next steps within
**14 days** of acknowledgement.

## Supported versions

Only the latest release receives security fixes. Within a major version this costs nothing to
follow: every 1.x release interoperates with every other and an upgrade never migrates your storage
(see [Compatibility](https://dvgils.github.io/notenv/project/compatibility/)), so upgrading to the
latest patch is always safe and is the fix path for any reported vulnerability. When a new major
version ships, the previous major line receives critical security fixes on a best-effort basis for
6 months to give you time to migrate, then reaches end-of-life.

## Scope

The [threat model](https://dvgils.github.io/notenv/security/threat-model/) describes what notenv
defends and, explicitly, what it does not. A report that a documented **non-goal** is undefended is
not a vulnerability; a report that a **stated guarantee** does not hold is, and is welcome.

## Policies

The project's standing security policies (secrets management, access to sensitive resources,
supported versions, and the thresholds for remediating dependency and code-scanning findings) are
documented at [Security policies](https://dvgils.github.io/notenv/security/policies/).
