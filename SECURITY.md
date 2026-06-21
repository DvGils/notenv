# Security policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/DvGils/notenv/security/advisories/new), not a
public issue. Reports are acknowledged within **5 business days**, investigated, and a fix and
coordinated disclosure follow. We aim to assess every report and report back on next steps within
**14 days** of acknowledgement.

## Supported versions

notenv is pre-1.0 and developed on a rolling basis. Security fixes land on the latest release, and
only the latest release is supported: a version stops receiving security updates as soon as a newer
release ships. A formal supported-versions and end-of-life policy will be defined at 1.0. Run a
recent version.

## Scope

The [threat model](https://dvgils.github.io/notenv/security/threat-model/) describes what notenv
defends and, explicitly, what it does not. A report that a documented **non-goal** is undefended is
not a vulnerability; a report that a **stated guarantee** does not hold is, and is welcome.

## Policies

The project's standing security policies (secrets management, access to sensitive resources,
supported versions, and the thresholds for remediating dependency and code-scanning findings) are
documented at [Security policies](https://dvgils.github.io/notenv/security/policies/).
