# notenv

[![CI](https://github.com/DvGils/notenv/actions/workflows/ci.yml/badge.svg)](https://github.com/DvGils/notenv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DvGils/notenv?sort=semver)](https://github.com/DvGils/notenv/releases/latest)
[![Docs](https://img.shields.io/badge/docs-dvgils.github.io%2Fnotenv-blue)](https://dvgils.github.io/notenv/)
[![Go Reference](https://pkg.go.dev/badge/github.com/DvGils/notenv.svg)](https://pkg.go.dev/github.com/DvGils/notenv)
[![Go Report Card](https://goreportcard.com/badge/github.com/DvGils/notenv)](https://goreportcard.com/report/github.com/DvGils/notenv)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

> Encrypted secrets, no infrastructure, no plaintext on disk.

notenv replaces `.env` files: secrets are encrypted on your machine with
[age](https://github.com/FiloSottile/age), kept as ciphertext in a **local vault** or on **storage
you already own** (Backblaze B2, S3, Google Drive, SFTP, WebDAV, anything
[rclone](https://rclone.org) speaks), and decrypted **only into the environment of the command you
run**. Plaintext never touches disk.

## Why

A `.env` file is plaintext: everything on your machine can read it, and sharing it means pasting it
somewhere it will outlive. notenv removes the file instead of guarding it.

- **You hold the key, not a provider.** Secrets are age-encrypted locally; storage only ever sees
  ciphertext. There is no account to create, no SaaS to trust, no vendor that can read, lock, or lose
  your data.
- **Storage you already have.** A local folder, a home NAS, B2, S3, Drive, SFTP, WebDAV, dozens more.
  Move a vault from a folder to a cloud remote in one command when syncing starts to matter.
- **Nothing on disk to leak.** A test runner, a package postinstall script, or a coding agent in your
  checkout cannot read a secret that exists only inside the process you ran, only while it runs.
- **Joining and leaving are one command.** Onboard a teammate with a string sent over chat; their first
  run swaps it for a credential only they know. `notenv key rm` re-encrypts everything, so offboarding
  actually revokes, not just "please delete your copy."
- **Nothing to operate.** `notenv setup` is one passphrase and zero accounts. No server to stand up,
  patch, or pay for.

**Not this if** you want a platform: there is no web console or SSO, and access is scoped per vault,
not per secret (everyone in a vault can read that vault). If a platform team already runs Vault, keep
Vault.

## Install

```sh
uv tool install notenv                                  # also: pipx install notenv, or pip
go install github.com/DvGils/notenv/cmd/notenv@latest   # with Go
```

Or download a prebuilt binary for Linux, macOS, or Windows (amd64 / arm64) from
[Releases](https://github.com/DvGils/notenv/releases) and put `notenv` on your `PATH`. Releases are
reproducible, signed with [cosign](https://github.com/sigstore/cosign) (keyless), and carry SLSA
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
environment variables. On a new machine: `git clone`, then `notenv setup` with your escrowed
passphrase, and you are ready. When syncing across machines starts to matter, `notenv vault copy`
moves the same vault to a cloud remote in one command.

## Documentation

Full docs live at **[dvgils.github.io/notenv](https://dvgils.github.io/notenv/)**:

- [Quick start](https://dvgils.github.io/notenv/getting-started/quick-start/) and
  [installation](https://dvgils.github.io/notenv/getting-started/installation/)
- Guides: [share a vault with your team](https://dvgils.github.io/notenv/guides/teams-and-keys/),
  [cloud remotes](https://dvgils.github.io/notenv/guides/cloud-remotes/),
  [export or delete a vault](https://dvgils.github.io/notenv/guides/export-and-delete/),
  [AI agents](https://dvgils.github.io/notenv/guides/ai-agents/)
- Reference: [commands](https://dvgils.github.io/notenv/reference/commands/),
  [configuration](https://dvgils.github.io/notenv/reference/configuration/)
- Concepts: [how it works](https://dvgils.github.io/notenv/concepts/how-it-works/),
  [keys and slots](https://dvgils.github.io/notenv/concepts/keys-and-slots/)
- Security: [threat model](https://dvgils.github.io/notenv/security/threat-model/)

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

A random **master key** encrypts every secret and never exists in plaintext at rest: a small header
holds it wrapped under one or more **key slots** (a person's passphrase or a machine's age public
key), the way LUKS and restic do it. The header is authenticated and version-pinned, so a party who
can write your storage but holds no key cannot tamper with it or roll it back undetected. Full detail
in [Concepts](https://dvgils.github.io/notenv/concepts/how-it-works/).

## For AI agents

A `.env` on disk eventually lands in a coding agent's context. notenv gives the agent a verb that
separates *using* a credential from *knowing* it:

- `notenv run -- cmd` injects secrets into the child only; the value never appears in what the model
  reads, and captured output is masked.
- `notenv list` shows which secrets exist and what they are for, never their values.

For a scoped session, `notenv handoff -- <agent>` runs the agent against an ephemeral vault holding
only one namespace, so it never holds the key to the rest of your vault. An installable agent skill
(`skills/notenv/`) teaches it the commands. See the
[AI agents guide](https://dvgils.github.io/notenv/guides/ai-agents/).

## How it compares

| | **notenv** | dotenvx | 1Password (`op run`) | SOPS + age |
|---|---|---|---|---|
| Where the ciphertext lives | **storage you own** (B2, S3, Drive, a NAS, a folder) | committed to your git repo | 1Password's servers | a file you place yourself |
| What you depend on to read a secret | **only your key** | only your key | 1Password, your account and plan | only your key |
| Account or service to sign up for | **none** | none | required | none |
| Onboard a teammate | **one command**, with a verifiable vault fingerprint | hand over the private key | invite them in the app | add their key, redistribute the file |
| Offboarding actually revokes | **yes**: `key rm` re-encrypts the vault | rotate the key, re-encrypt by hand | remove them from the vault | rotate, re-encrypt by hand |
| Move to other storage | **one command**, any rclone remote | it lives in git | not applicable, it is their cloud | move the file yourself |

[dotenvx](https://dotenvx.com) and `op run` both nail encrypted injection; the difference is the master.
dotenvx keeps the encrypted file in your repo and leaves distributing and rotating the private key to
you; 1Password is excellent but is a service that holds your secrets and that you depend on.
[SOPS](https://getsops.io) + age give you the keys but leave storage and onboarding as homework. notenv
is the one combination of all three: keys you hold, storage you already own, and onboarding built in,
with nobody in the loop.

## Security

At rest, anywhere, only age ciphertext exists; it is useless without your key, which lives in your
password manager and never on the storage backend. The
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
[roadmap](https://dvgils.github.io/notenv/project/roadmap/) for what works today, what is planned, and
the non-goals.

## License

[Apache-2.0](./LICENSE).
