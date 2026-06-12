# notenv

[![CI](https://github.com/DvGils/notenv/actions/workflows/ci.yml/badge.svg)](https://github.com/DvGils/notenv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DvGils/notenv?sort=semver)](https://github.com/DvGils/notenv/releases/latest)
[![Docs](https://img.shields.io/badge/docs-dvgils.github.io%2Fnotenv-blue)](https://dvgils.github.io/notenv/)
[![Go Reference](https://pkg.go.dev/badge/github.com/DvGils/notenv.svg)](https://pkg.go.dev/github.com/DvGils/notenv)
[![Go Report Card](https://goreportcard.com/badge/github.com/DvGils/notenv)](https://goreportcard.com/report/github.com/DvGils/notenv)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

> Your `.env`, encrypted and off your disk, with no infrastructure to run.

notenv replaces `.env` files. Your secrets are encrypted **on your machine** with
[age](https://github.com/FiloSottile/age), stored as ciphertext in a **local vault** or on
**storage you already own** (Backblaze B2, S3, Google Drive, SFTP, WebDAV, or anything
[rclone](https://rclone.org) speaks), and decrypted **only into the environment of the process you
run**. Plaintext never touches your disk.

```sh
notenv setup                   # a local vault: no accounts, no dependencies, one passphrase
notenv import .env             # your existing secrets, encrypted; delete the .env after
notenv run -- npm run dev      # secrets injected as env vars, gone when the process exits
```

There is no server to run, no SaaS to sign up for, and nothing to install beyond notenv itself. You
hold the key; storage only ever sees ciphertext. When syncing across machines starts to matter,
`notenv vault copy` moves the same vault to a cloud remote in one command.

## Documentation

Full docs live at **[dvgils.github.io/notenv](https://dvgils.github.io/notenv/)**:

- [Quick start](https://dvgils.github.io/notenv/getting-started/quick-start/) and
  [installation](https://dvgils.github.io/notenv/getting-started/installation/)
- Guides: [teams and keys](https://dvgils.github.io/notenv/guides/teams-and-keys/),
  [cloud remotes](https://dvgils.github.io/notenv/guides/cloud-remotes/),
  [CI](https://dvgils.github.io/notenv/guides/ci/),
  [AI agents](https://dvgils.github.io/notenv/guides/ai-agents/)
- Reference: [commands](https://dvgils.github.io/notenv/reference/commands/),
  [configuration](https://dvgils.github.io/notenv/reference/configuration/)
- Concepts: [how it works](https://dvgils.github.io/notenv/concepts/how-it-works/),
  [keys and slots](https://dvgils.github.io/notenv/concepts/keys-and-slots/)
- Security: [threat model](https://dvgils.github.io/notenv/security/threat-model/)

## Install

With Go:

```sh
go install github.com/DvGils/notenv/cmd/notenv@latest
```

Or download a prebuilt binary for Linux, macOS, or Windows (amd64 / arm64) from the
[Releases](https://github.com/DvGils/notenv/releases) page and put `notenv` on your `PATH`. Releases
are reproducible, signed with [cosign](https://github.com/sigstore/cosign) (keyless), and carry SLSA
build provenance; the
[installation guide](https://dvgils.github.io/notenv/getting-started/installation/) shows how to
verify a download.

## Quick start

```sh
notenv setup                   # 1. set up this machine once (local vault by default)
cd my-project && notenv init   # 2. declare the project (writes notenv.toml, which you commit)
notenv import .env && rm .env  # 3. import existing secrets (or `notenv set KEY` one at a time)
notenv run -- npm run dev      # 4. run anything with the secrets injected
```

That is the whole loop. notenv is a process wrapper, so it works with any language that reads
environment variables. On a new machine, `git clone` the project, run `notenv setup` with your
escrowed passphrase, and you are ready. See the
[quick start](https://dvgils.github.io/notenv/getting-started/quick-start/) for the full walkthrough.

## Why notenv

The secrets-tooling space is good, but there is a specific gap:

- **[SOPS](https://getsops.io) + age** nail client-side encryption and process injection, but you
  hand-roll the storage and the onboarding.
- **[Teller](https://github.com/tellerops/teller)** brokers cloud secret managers (Vault, AWS / GCP
  Secret Manager), but it is per-provider code and the provider holds your secrets.

notenv is the middle ground: SOPS-style client-side encryption, the storage reach of rclone, and
dotenv ergonomics, with zero infrastructure.

| | notenv | teller | SOPS + age (DIY) |
|---|---|---|---|
| Plaintext on disk | never | never | never |
| You hold the key | yes | no (provider does) | yes |
| Storage backends | local vault or any rclone remote | per-provider code | you wire it up |
| Infrastructure to run | none | none (uses your cloud) | none |
| One-command onboarding | yes | partial | no |

## How it works

```text
notenv run -- cmd
  |
  |-- fetch ciphertext   <- rclone <-  your B2 / S3 / Drive / ...
  |-- unlock the master key (from your passphrase; cached after first use)
  |-- decrypt secrets in memory
  |-- build the child environment from notenv.toml
  |-- exec cmd, stream its I/O, exit with its code
        nothing written to disk
```

Secrets are encrypted with a random **master key** that never exists in plaintext at rest: a small
header object holds it wrapped under one or more **key slots** (a person's passphrase, or a
machine's age public key), the same approach LUKS and restic use. The header is authenticated and version-pinned,
so a party that can write your storage but holds no key cannot tamper with it or roll it back
undetected. Full detail in
[Concepts](https://dvgils.github.io/notenv/concepts/how-it-works/).

## For AI agents

A `.env` on disk eventually enters a coding agent's context. notenv removes the file and gives the
agent a verb that separates *using* a credential from *knowing* it:

- `notenv run -- cmd` injects secrets into the child only; the value never appears in what the model
  reads, and captured output is masked.
- `notenv list` tells the agent which secrets exist and what they are for, never their values.

There is also an experimental MCP server (`notenv mcp`). See the
[AI agents guide](https://dvgils.github.io/notenv/guides/ai-agents/) for the full surface and its
honest limits.

## Security

At rest, anywhere, only age ciphertext exists; it is useless without your key, which lives in your
password manager, not on the storage backend. The
[threat model](https://dvgils.github.io/notenv/security/threat-model/) covers what notenv defends,
against whom, and the explicit non-goals. To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## Building from source

```sh
git clone https://github.com/DvGils/notenv
cd notenv
make build       # compile ./notenv
make test        # run the test suite
make install     # install into $(go env GOPATH)/bin
```

Releases are produced with [GoReleaser](https://goreleaser.com); `make snapshot` builds the full set
of release artifacts locally without publishing.

## Status

Actively developed and being tested. See the
[roadmap](https://dvgils.github.io/notenv/project/roadmap/) for what works today, what is planned,
and the non-goals.

## License

[Apache-2.0](./LICENSE).
