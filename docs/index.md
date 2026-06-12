# notenv

> Your `.env`, encrypted and off your disk, with no infrastructure to run.

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

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext
at rest: a small header object next to your secrets holds it wrapped under one or more **key slots**,
the same approach LUKS and restic use. A slot is either a **passphrase** (yours, escrowed) or a
teammate's **age public key**, so you can grant access without sharing a secret. Unlocking any slot
yields the master key for the session.

The header is authenticated and carries a monotonic revision, so a party that can write your storage
but holds no key cannot tamper with it or roll it back undetected.

## License

notenv is [Apache-2.0](https://github.com/DvGils/notenv/blob/main/LICENSE) licensed.
