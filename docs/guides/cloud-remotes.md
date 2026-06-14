# Cloud remotes

A local vault needs no accounts and no dependencies, and is the default. When syncing across machines
starts to matter, notenv stores the same ciphertext on **storage you already own**, reached through
[rclone](https://rclone.org): Backblaze B2, S3, Google Drive, SFTP, WebDAV, or anything rclone
speaks. notenv treats the remote as a dumb object store; the provider only ever sees ciphertext.

## Requirements

- [rclone](https://rclone.org/install/) on your `PATH`.
- A storage remote you control. notenv can create the rclone remote for you during `notenv setup`.

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

## Object versioning

Some remotes (Backblaze B2 natively) retain old object versions on overwrite. notenv does not depend
on that: it always keeps its own backups (a `.prev` sibling of the key header, and a one-generation
backup of each namespace blob), so recovery never relies on a remote feature notenv cannot verify is
configured. Where a remote does keep versions, it is a useful extra backstop for the rarer case of a
deleted object, which is an availability concern that detection alone cannot undo.
