# Quick start

This is the whole loop: set up a machine once, declare a project, add secrets, and run anything
with those secrets injected as environment variables.

## 1. Set up this machine once

The default is a local vault: no accounts, no rclone, nothing but a passphrase. (Picking a cloud
remote instead is the second option in the same prompt, and a local vault can move to one later.)

```sh
notenv setup
```

You choose a passphrase and escrow it in your password manager.

!!! warning "Your passphrase is the only key"

    That passphrase is the only key to your secrets. Keep it safe: lose it and the ciphertext is
    unrecoverable by design.

## 2. Set up a project

Declare that this project uses notenv:

```sh
cd my-project
notenv init          # writes notenv.toml, which you commit
```

## 3. Add secrets

Have a `.env` already? Import it whole (every value encrypted, every key declared), then delete it:

```sh
notenv namespace import .env && rm .env
```

Or add values one at a time, prompted hidden:

```sh
notenv secret set DATABASE_URL
notenv secret set STRIPE_KEY
notenv namespace inspect          # shows key names only, never values
```

## 4. Run anything

Run any command with the secrets injected as environment variables:

```sh
notenv run -- npm run dev
notenv run -- python main.py
notenv run -- go test ./...
```

That is the whole loop. notenv is a process wrapper, so it works with any language that reads
environment variables.

## What you just created

| File | Committed? | What it is |
|---|---|---|
| `notenv.toml` | yes | The project contract: which environment variables this project needs. No secret values. |
| `notenv.local.toml` | no (git-ignored) | What this checkout agreed to: which storage it uses and which namespace it reads. |
| `~/.config/notenv/config.toml` | no (per machine) | Your machine's named storages (vaults). Written by `notenv setup`. |

Moving to another computer? See [On a new machine](new-machine.md).
