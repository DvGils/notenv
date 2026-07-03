# Contributing to notenv

Thanks for your interest. notenv is a small, security-focused CLI, so contributions are held to a
high bar for clarity and test coverage. This file covers how to report issues, how to propose
changes, and what a change has to clear before it merges.

## Reporting bugs and requesting features

Open an issue at [github.com/DvGils/notenv/issues](https://github.com/DvGils/notenv/issues). For a
bug, include the notenv version (`notenv --version`), the OS, and the exact commands and output. Do
**not** paste real secret values; show the masked form (`<notenv-masked:NAME>`) or a placeholder.

Security vulnerabilities are different: do not open a public issue. Report them privately as described
in [SECURITY.md](./SECURITY.md).

## Proposing a change

1. Open or comment on an issue first for anything beyond a typo, so the approach can be agreed before
   you write code. notenv has settled design positions (see below), and a PR that cuts against one is
   hard to merge however good the code is.
2. Fork, branch, and make your change with tests.
3. Run `make lint` and `make test` locally; both must pass.
4. Open a pull request describing what changed and why, and link the issue.

## What a change has to clear

- **Tests.** New functionality and bug fixes ship with tests that fail before the change and pass
  after. The suite runs under the race detector (`make test`).
- **Formatting and vetting.** `make lint` runs [golangci-lint](https://golangci-lint.run) with the
  set configured in `.golangci.yml`: `gofmt`, `go vet`, `gocyclo` (functions over a complexity of 15
  fail), `ineffassign`, `gosec`, and more. Keep functions under the threshold rather than raising it.
  golangci-lint is not a `go.mod` tool dependency, so
  [install it](https://golangci-lint.run/welcome/install/) at the version CI pins (see
  `.github/workflows/ci.yml`).
- **CI.** Pull requests run the full matrix: the race suite, native key-store tests on macOS and
  Windows, backend conformance against a real rclone, the fuzz smoke, a cross-build for all six
  release targets, and `govulncheck`. All jobs must be green.
- **Changelog.** User-visible changes get an entry in [CHANGELOG.md](./CHANGELOG.md) under the
  unreleased section, in the existing style.

## Coding conventions

notenv has firm conventions; match them rather than introducing new patterns:

- **cgo-free.** The binary builds `CGO_ENABLED=0` static on Linux, macOS, and Windows. Platform key
  stores are reached through their CLIs or `x/sys`, never a cgo dependency.
- **No daemons, agents, or servers, ever.** notenv is a pure CLI. Anything long-lived is a subprocess
  scoped to one command's lifetime.
- **Reads fail closed.** An untrustable blob, a missing header, or a MAC mismatch is an error, never a
  silent skip.
- **One write path for all backends.** No per-backend conditional writes.

Match the surrounding code: its comment density, naming, and idioms.

## Crypto and storage changes

Changes to the crypto, the on-disk header, or the storage format get extra scrutiny because they
affect data already in users' vaults. Raise these as an issue before writing code, and expect a
request for a compatibility argument (can an older notenv still read a vault a newer one wrote, and
vice versa, within a major version). When in doubt, ask first.

## License

By contributing you agree that your contributions are licensed under the project's
[Apache-2.0](./LICENSE) license.
