# Security policies

This page collects the project's standing security policies: how secrets are
managed, how access to sensitive resources is granted, which versions are
supported, and the thresholds at which dependency and code-scanning findings must
be remediated. For how to report a vulnerability, see
[Reporting a vulnerability](reporting.md). For what notenv defends and its
non-goals, see the [threat model](threat-model.md).

## Secrets and credentials

notenv's build and release pipeline is designed to hold no long-lived secrets:

- **PyPI publishing** uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
  (OIDC). No API token exists to store or leak.
- **Release signing** uses keyless [cosign](https://github.com/sigstore/cosign),
  which mints a short-lived certificate from an OIDC identity at signing time. No
  private signing key is held.
- **The GitHub Actions token** (`GITHUB_TOKEN`) is minted per run, scoped to the
  least privilege each workflow needs, and expires when the run ends.

The policy that follows from this:

- **Storing.** Secrets are never committed to the repository in any form, plaintext
  or otherwise. Any secret that genuinely must exist lives only in GitHub Actions
  encrypted secrets, scoped to the protected `release` environment.
- **Accessing.** Privileged credentials are reachable only from a release run,
  which is gated on the `release` environment and pauses for manual approval before
  it can build, sign, or publish. Day-to-day CI runs with a read-only token.
- **Rotating.** Because the pipeline uses OIDC rather than static tokens, there are
  no standing credentials to rotate on a schedule. If a static secret is ever
  introduced, it is rotated on a fixed cadence and immediately on any suspected
  compromise, and this policy is updated to name it.

(Rotation of the secrets notenv stores *for its users* is a product feature, not a
project-infrastructure concern; see [credential rotation](../recipes.md) in the
recipes.)

## Access to sensitive resources

Sensitive resources are merge rights on the primary branch, the protected
`release` environment, and repository administration. Access to any of these is
granted only after the collaborator has been reviewed, is granted at the least
privilege sufficient for the work, and is revoked when no longer needed. notenv is
currently maintained by a single person; this policy governs the grant of access
as collaborators are added.

## Supported versions

notenv is pre-1.0 and developed on a rolling basis. Security fixes land on the
latest release, and only the latest release is supported: a version stops
receiving security updates as soon as a newer release ships. There is no backport
to older lines while pre-1.0. A formal supported-versions and end-of-life policy,
including any longer support window, will be defined at the 1.0 release.

## Dependencies (software composition analysis)

The dependency surface is kept deliberately small and is patched continuously:

- **Tooling.** [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  runs on every pull request and blocks the build. It reports only vulnerabilities
  that reachable code actually calls, so a finding is real rather than advisory.
  [Dependabot](https://github.com/DvGils/notenv/blob/main/.github/dependabot.yml)
  opens weekly updates for Go modules and pinned GitHub Actions.
- **Remediation threshold.** Any vulnerability `govulncheck` reports as reachable
  blocks merge and blocks release, and must be resolved (update, patch, or drop the
  dependency) before the next release. A vulnerability in a dependency that is *not*
  reachable from notenv does not block a release; it is tracked through Dependabot,
  patched on the normal cadence, and recorded as not-affecting in a VEX statement
  (see [Suppressions](#suppressions-and-vex)) so downstream scanners see the same
  determination.
- **Licenses.** Dependencies must be under an OSI-approved license. Strong copyleft
  licenses (GPL, AGPL) are not accepted into the dependency surface.
- **Release gate.** No release ships with a known reachable vulnerability.

## Code scanning (static analysis)

- **Tooling.** [CodeQL](https://codeql.github.com) code scanning and `go vet` run on
  changes to the codebase.
- **Remediation threshold.** A High or Critical alert blocks merge. A Medium alert
  is remediated within 30 days. Low and informational alerts are tracked. No release
  ships with an open High or Critical alert.
- **Enforcement.** Code scanning is a required check on the primary branch, so a
  violating change cannot merge.

## Suppressions and VEX

A finding may be set aside only when it is genuinely not exploitable in notenv, and
only with a recorded reason:

- A code-scanning alert is dismissed with an explicit dismissal reason (false
  positive, or used in tests, or won't fix with justification).
- A dependency vulnerability that does not affect notenv is documented as
  not-affected in a [VEX](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex_508c.pdf)
  ([OpenVEX](https://github.com/openvex)) statement, so the not-affected
  determination travels with the release and downstream scanners do not re-flag it.

A suppression is never silent: if a finding is not fixed, the reason it is safe is
written down.
