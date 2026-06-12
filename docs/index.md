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
[threat model](security/threat-model.md) says precisely what that
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

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext
at rest: a small header object next to your secrets holds it wrapped under one or more **key slots**,
the same approach LUKS and restic use. A slot is either a person's
**passphrase** (escrowed in their password manager) or a machine's **age public key** (its identity
lives in the platform's secret store). Unlocking any slot yields the master key for the session.

The header is authenticated and carries a monotonic revision, so a party that can write your storage
but holds no key cannot tamper with it or roll it back undetected.

## License

notenv is [Apache-2.0](https://github.com/DvGils/notenv/blob/main/LICENSE) licensed.
