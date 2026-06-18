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

    Hand a coding agent a scoped session: it uses your secrets without ever holding the
    key to the rest of your vault, and its MCP servers can pull credentials from notenv too.

    [:octicons-arrow-right-24: AI agents](guides/ai-agents.md)

</div>

## Why notenv

A `.env` file is plaintext: everything on your machine can read it, and sharing it means pasting it
somewhere it will outlive. notenv removes the file instead of guarding it.

- **You hold the key, not a provider.** Secrets are age-encrypted locally; storage only ever sees
  ciphertext. No account to create, no SaaS to trust, no vendor that can read, lock, or lose your data.
- **Storage you already own.** A local folder, the NAS under your desk, B2, S3, Drive, SFTP, WebDAV,
  dozens more, and you can move between them when syncing across machines starts to matter.
- **Nothing on disk to leak.** A test runner, a package's postinstall script, or a coding agent in
  your checkout cannot read a secret that exists only inside the process you ran, only while it runs.
- **Easy to share, clean to leave.** Share a vault with a collaborator in seconds, and when they
  leave, they can no longer read it, instead of you just hoping they deleted their copy. No lock-in either; you can leave with your secrets for a different solution easily.
- **Nothing to operate.** Setup is one passphrase and zero accounts. No server to stand up, patch, or
  pay for.

**Not this if** you want a platform: there is no web console or SSO, and access is scoped per vault,
not per secret (everyone in a vault can read that vault). If a platform team already runs Vault, keep
Vault.

### How it compares

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
next to your secrets holds it wrapped under one or more **key slots** (a person's passphrase or a
machine's age public key), the way LUKS and restic do it. The header is authenticated and
version-pinned, so a party that can write your storage but holds no key cannot tamper with it or
roll it back undetected. The full walkthrough is in [How it works](concepts/how-it-works.md).

## License

notenv is [Apache-2.0](https://github.com/DvGils/notenv/blob/main/LICENSE) licensed.
