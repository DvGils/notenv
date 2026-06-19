# Recipes

Task-first snippets for the situations notenv shows up in. Each one is the short version; the link
takes you to the guide with the full artifact and the reasoning.

## Solo developer

### Start with a local vault

No accounts, no rclone, one passphrase.

```sh
notenv setup                   # local vault (the default)
cd my-project && notenv init   # writes notenv.toml (commit it)
notenv namespace import .env && rm .env  # or: notenv secret set KEY one at a time
notenv run -- npm run dev      # secrets injected for this process only
```

→ [Quick start](getting-started/quick-start.md)

### Use a cloud remote instead

Run `notenv setup` and choose the cloud option; notenv walks you through selecting or creating an
rclone remote (Backblaze B2, S3, SFTP, WebDAV, anything rclone speaks).

→ [Cloud remotes](guides/cloud-remotes.md)

### Move a local vault to a remote

Same vault afterward, nothing re-encrypted, every credential still works.

```sh
notenv vault copy
```

→ [Cloud remotes](guides/cloud-remotes.md#move-a-local-vault-to-a-remote)

### Set up on another of your machines

```sh
git clone <your-project> && cd <your-project>
notenv setup                   # enter your escrowed passphrase
notenv run -- ...              # ready
```

→ [On a new machine](getting-started/new-machine.md)

## Teams

### Onboard a teammate

```sh
notenv credential add alice           # prints a one-time onboarding string; send it over a private channel
```

Alice points her machine at the same storage, runs `notenv setup`, and enters the string; her first
command replaces it with a passphrase only she knows.

→ [Share a vault with your team](guides/teams-and-keys.md#add-a-teammate)

### Offboard a teammate or machine

`credential delete` removes the slot **and** re-keys the vault (fresh master, every secret re-encrypted), so the
removed credential decrypts nothing new. Then rotate the storage credential at your provider, which
notenv cannot do for you.

```sh
notenv credential delete alice            # re-keys automatically; surviving slots keep working
# then: rotate the bucket/SFTP credential at your provider
```

→ [Share a vault with your team](guides/teams-and-keys.md#remove-a-teammate)

### Change a passphrase, or re-key as a precaution

```sh
notenv credential rotate              # rewraps your slot (header only; secrets untouched)
notenv credential rotate-master       # fresh master, every secret re-encrypted, all slots kept
```

→ [Share a vault with your team](guides/teams-and-keys.md#everyday-key-tasks)

## AI agents

### Hand off a scoped session to an agent

```sh
notenv handoff -- claude        # ephemeral, scoped vault; your master key out of reach
```

Runs the agent against an ephemeral vault holding only this project's namespace, so a compromised or
prompt-injected agent can leak at most that namespace, never your whole vault. Install the
[agent skill](https://github.com/DvGils/notenv/tree/main/skills/notenv) (once into
`~/.claude/skills/notenv/`, or commit it to `.claude/skills/notenv/`) so the agent uses `notenv run`
and never prints a value.

→ [AI agents](guides/ai-agents.md)

## Operations

### Check a vault's health

Read-only; names any recoverable problem state and the way out.

```sh
notenv doctor
```

→ [Recover from problems](guides/recovery.md)

### Pull a change made on another machine

```sh
notenv run --refresh -- ...    # bypass the local cache for this run
```

→ [Caching](concepts/caching.md#pulling-another-machines-changes)

### Recover after a lost or dead machine

Nothing to restore but your passphrase: it lives in your password manager, not on the storage. On a
new machine, `git clone`, `notenv setup`, and you are back.

→ [On a new machine](getting-started/new-machine.md)

### Rotate after a suspected compromise

```sh
notenv credential rotate-master       # fresh master; anything captured stops decrypting new writes
# then: rotate the storage credential at your provider
```

→ [Share a vault with your team](guides/teams-and-keys.md#everyday-key-tasks)

### Export your secrets, or delete a vault

```sh
notenv namespace export > backup.env     # one namespace; `notenv vault export` for the whole vault
notenv vault delete <name>     # destroy a vault you no longer want (asks the passphrase)
```

→ [Export or delete a vault](guides/export-and-delete.md)

### A secret will not decrypt

```sh
notenv run --skip-corrupt -- ...   # read the one-generation backup
notenv namespace recover <namespace>       # rebuild from the last good backup (last resort)
```

→ [Recover from problems](guides/recovery.md)
