# Export or delete a vault

## Take your secrets out

`notenv namespace export` prints a namespace as a `.env` file to standard output, the
inverse of `import`:

```sh
notenv namespace export > backup.env       # one namespace
notenv vault export > all.env    # every namespace in the vault
```

It asks for the vault's primary passphrase even when your session is cached,
because this is plaintext leaving the vault on purpose, and it refuses without a
terminal (a machine cannot export). notenv never writes the file itself; you
redirect it.

The output is for `notenv namespace import`, not for `source`: values are written literally,
so one containing `$(...)` or backticks is data to notenv but a shell would
execute it. Round-trip a namespace with `notenv namespace export | notenv namespace import`.

!!! tip "Moving to another tool"

    `notenv namespace export --json` emits a structured object instead of `.env`, if the
    tool you are moving to wants JSON.

## Move a vault to different storage

To copy a vault to another storage (local to cloud, say) and keep using notenv,
use `notenv vault copy`: it is the same vault afterward, nothing re-encrypted. See
[Cloud remotes](cloud-remotes.md#move-a-local-vault-to-a-remote).

## Delete a vault

To destroy a vault you no longer want:

```sh
notenv vault delete <name>
```

This permanently removes the vault's encrypted objects, this machine's trust state
for it, and its entry in your config. It asks for the vault's primary passphrase
and makes you type the vault's name to confirm, so you only ever destroy a vault
you can prove you own.

!!! warning "It deletes the live vault, not every copy"

    A versioned remote's history and any backups you made are the provider's to
    purge. If you have lost the passphrase, delete the storage yourself (a local
    vault is its directory; a remote's objects are yours to remove) and run
    `notenv credential forget` to clear this machine's trust state.

---

**Under the hood:** revoking a person's access (rather than deleting the vault) is
[Share a vault with your team](teams-and-keys.md#remove-a-teammate); what export
exposes and what deletion does not reach is in the
[threat model](../security/threat-model.md).
