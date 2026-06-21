# Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/DvGils/notenv/security/advisories/new), not a
public issue. Reports are acknowledged within **5 business days**, investigated, and a fix and
coordinated disclosure follow. We aim to assess every report and report back on next steps within
**14 days** of acknowledgement.

## Supported versions

notenv is pre-1.0 and developed on a rolling basis. Security fixes land on the latest release, and
only the latest release is supported: a version stops receiving security updates as soon as a newer
release ships. A formal supported-versions and end-of-life policy will be defined at 1.0. Run a
recent version. See the [security policies](policies.md) for the full statement.

## Scope

The [threat model](threat-model.md) describes what notenv defends and, explicitly, what it does not. A
report that a documented **non-goal** is undefended is not a vulnerability; a report that a **stated
guarantee** does not hold is, and is welcome.
