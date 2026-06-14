# Recover from problems

Start with `notenv doctor`. It reads your storage without changing anything,
reports any known problem state, and names the way out of each:

```sh
notenv doctor
```

The rest of this page is those ways out.

## A secret will not decrypt (corrupt or missing)

If a namespace's stored blob is damaged (bit-rot, a truncated upload, tampering), a
read fails closed rather than serve something it cannot verify. notenv keeps a
one-generation backup of each namespace, so there are two moves:

- **Read what survives.** Fall back to the backup for this run:

    ```sh
    notenv run --skip-corrupt -- ...
    notenv list --skip-corrupt
    ```

    It serves the previous generation and reports exactly what it dropped; the most
    recent write may be lost.

- **Repair the namespace.** Rebuild it from what survives so ordinary writes work
  again:

    ```sh
    notenv key evict <namespace>
    ```

    This rewrites the namespace from its backup (or empty, if that is gone too) and
    drops the corrupt blobs. It is a last resort and acknowledges the loss.

## A write did not finish

If a write to a remote was interrupted and a later command says the header write
may not have landed, restore the header from the backup notenv keeps before every
write:

```sh
notenv key restore-backup
```

## "The vault changed" (rollback or substitution alarm)

If notenv refuses a vault because its revision went backward, its identity changed,
or its header vanished, it is protecting you from a rollback or a swapped-in vault.
If you know the change is legitimate and it carries no signed proof:

```sh
notenv key trust       # shows what changed, then asks before re-pinning
```

If you deliberately reset or abandoned a vault and want this machine to forget its
pin and cached key for that storage:

```sh
notenv key forget
```

---

**Under the hood:** why reads fail closed and what the one-generation backup
guarantees are in [Storage and concurrency](../concepts/storage.md); what the
rollback and substitution alarms defend is in the
[threat model](../security/threat-model.md).
