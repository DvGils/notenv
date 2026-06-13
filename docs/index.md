# notenv

> Encrypted secrets, no infrastructure, no plaintext on disk.

notenv replaces `.env` files. Your secrets are encrypted **on your machine** with
[age](https://github.com/FiloSottile/age), stored as ciphertext in a **local vault** or on
**storage you already own** (Backblaze B2, S3, Google Drive, SFTP, WebDAV, or anything
[rclone](https://rclone.org) speaks), and decrypted **only into the environment of the process
you run**. Plaintext never touches your disk.

```sh
notenv setup                   # a local vault: no accounts, no dependencies, one passphrase
notenv import .env             # your existing secrets, encrypted; delete the .env after
notenv run -- npm run dev      # secrets injected as env vars, gone when the process exits
```

There is no server to run, no SaaS to sign up for, and nothing to install beyond notenv itself.
You hold the key; storage only ever sees ciphertext. When syncing across machines starts to
matter, `notenv vault copy` moves the same vault to a cloud remote in one command.

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Start here**

    ---

    Install notenv, set up a machine, and run your first command with secrets injected.

    [:octicons-arrow-right-24: Quick start](getting-started/quick-start.md)

-   :material-console:{ .lg .middle } **Command reference**

    ---

    Every command, what it does, and the flags that change its behavior.

    [:octicons-arrow-right-24: Commands](reference/commands.md)

-   :material-shield-lock:{ .lg .middle } **Security model**

    ---

    What notenv protects, against whom, and what it deliberately does not.

    [:octicons-arrow-right-24: Threat model](security/threat-model.md)

-   :material-robot:{ .lg .middle } **For AI agents**

    ---

    Give a coding agent a verb that separates *using* a credential from *knowing* it.

    [:octicons-arrow-right-24: AI agents](guides/ai-agents.md)

</div>

## Why notenv

A `.env` file is plaintext: everything on your machine can read it, and sharing it means pasting it
somewhere it will outlive. notenv removes the file instead of guarding it.

- **Nothing on disk to leak.** A test runner, a package's postinstall script, or a coding agent in
  your checkout cannot read a secret that exists only inside the process you ran, only while it runs.
- **You hold the key, not a provider.** Secrets are age-encrypted locally; storage only ever sees
  ciphertext, so it can live anywhere: a local vault, the NAS under your desk, B2, S3, Drive, dozens
  more.
- **Nothing to operate.** No server, no SaaS, no cloud account to stand up and babysit. `notenv
  setup` is one passphrase and zero accounts.
- **Joining and leaving are one command.** Onboard a teammate with a string over chat; their first
  run swaps it for a credential only they know. Offboarding re-encrypts everything, so leaving
  actually revokes.
- **Built for agents and CI.** `notenv run` lets a process *use* a secret without *seeing* it, and
  your CI secret store holds one credential instead of thirty.

**Not this if** you want a platform: there is no web console or SSO, and access is scoped per vault,
not per secret (everyone in a vault can read that vault). If a platform team already runs Vault, keep
Vault.

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

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext
at rest: a small header object next to your secrets holds it wrapped under one or more **key slots**,
the same approach LUKS and restic use. A slot is either a person's
**passphrase** (escrowed in their password manager) or a machine's **age public key** (its identity
lives in the platform's secret store). Unlocking any slot yields the master key for the session.

The header is authenticated and carries a monotonic revision, so a party that can write your storage
but holds no key cannot tamper with it or roll it back undetected.

## License

notenv is [Apache-2.0](https://github.com/DvGils/notenv/blob/main/LICENSE) licensed.
