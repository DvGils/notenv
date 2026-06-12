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

Your secrets are probably in a `.env` file right now. That means:

- **Everything on your machine can read them.** Your test runner, some package's postinstall
  script, and any coding agent working in your checkout are one read away. An agent that opens
  your `.env` while debugging has just copied your production credentials into a model context and
  a transcript you don't control.
- **Sharing them means pasting them.** A teammate needs the project's secrets, so the file goes
  over chat. Now it lives in message history, in a downloads folder, on a laptop that will
  eventually be sold. And when someone leaves, nothing expires: there is nothing to revoke.
- **The official fixes want you to become an operator.** Run a Vault server, or create and manage
  a cloud account just to have somewhere to put five secrets: a subscription, IAM wiring, an SDK
  in your app, and a provider sitting between you and your own credentials.

notenv removes the file instead of guarding it. Secrets are encrypted on your machine, live as
ciphertext in a local vault or on storage you already own, and exist in plaintext only inside the
environment of the process you run, for as long as it runs. Storage means **anything
[rclone](https://rclone.org) speaks**: Backblaze B2, S3, Google Drive, Dropbox, SFTP, WebDAV,
dozens more. Your vault can live on the NAS under your desk, and nobody can stop you from keeping
it on the SFTP server in your smart fridge. There is nothing to operate and nobody else to trust:
you hold the key, storage holds ciphertext, and the
[threat model](https://dvgils.github.io/notenv/security/threat-model/) says precisely what that
does and does not protect.

Reach for it when:

- **you're one developer who wants to do this right**, without standing up an account at a cloud
  provider and managing it forever just to have a key vault: `notenv setup` is one passphrase,
  zero accounts, and you're done;
- **a coding agent works in your repository**, and "the agent can run the app without ever seeing
  the database password" should be a property, not a hope;
- **a teammate needs in**: onboarding is one command and a string over chat, their first use
  replaces it with a credential only they know, and offboarding re-encrypts everything, so leaving
  actually revokes;
- **CI needs thirty secrets**, and the CI secret store should hold one;
- **a laptop dies**, and the recovery plan should be "the passphrase in my password manager", not
  "which machine had the newest .env".

And honestly, when not: notenv is not a platform. There is no web console, no SSO, and access is
scoped per vault rather than per secret: everyone in a vault can read that vault, and you scope by
making vaults (one per project or per environment is one `setup` away). If your organization has a
platform team running Vault, keep Vault.

### How it compares

For readers who know the space: [SOPS](https://getsops.io) + age nail client-side encryption and
process injection but leave storage and onboarding to you; [Teller](https://github.com/tellerops/teller)
brokers cloud secret managers, where the provider holds your secrets. notenv is client-side
encryption with the storage and the onboarding built in, and no provider in the loop.

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
