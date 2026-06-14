# Cloud remotes

A local vault needs no accounts and no dependencies, and is the default. When syncing across machines
starts to matter, notenv stores the same ciphertext on **storage you already own**, reached through
[rclone](https://rclone.org): Backblaze B2, S3, Google Drive, SFTP, WebDAV, or anything rclone
speaks. notenv treats the remote as a dumb object store; the provider only ever sees ciphertext.

## Requirements

- [rclone](https://rclone.org/install/) on your `PATH`.
- A storage remote you control. notenv can create the rclone remote for you during `notenv setup`.

!!! tip "Keeping storage credentials off the command line"

    When notenv creates the rclone remote for you, the provider credential is
    passed to rclone as command-line arguments, briefly visible to other processes
    on the same machine. To avoid that, create the remote yourself with
    `rclone config` (it prompts for the secret) and pick it during `notenv setup`.

## Start on a cloud remote

Run `notenv setup` and choose the cloud-remote option instead of a local vault. notenv walks you
through selecting or creating an rclone remote and the path within it, then runs the key ceremony.

## Move a local vault to a remote

If you started local, replicate the vault to a remote in one command. The source is untouched, and
it is the **same vault** afterwards: nothing is re-encrypted, every credential keeps working, and
this machine's trust state follows the vault's own identity.

```sh
notenv vault copy
```

The copy is verified byte for byte and registered as a named storage on this machine. The
destination must not already hold a vault (copies never merge).

## Backups

notenv keeps its own one-generation backup on every backend, so recovery never
depends on a remote's object-versioning being enabled. If your remote does keep
versions (Backblaze B2 does natively), that is a useful extra backstop for the
rarer case of a deleted object.

---

**Under the hood:** how the backup and the header swap work is in
[Storage and concurrency](../concepts/storage.md).
