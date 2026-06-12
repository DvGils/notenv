# Storage and concurrency

A namespace's secrets are stored as an **append-only set of encrypted segments** over periodic
**snapshots**. This layout is what lets multiple machines write the same vault with no server and no
locking, and never lose each other's writes.

## Append-only segments

Each `notenv set` appends a new, uniquely named, encrypted segment. It never overwrites a shared
object. A read **folds** a namespace's snapshots and segments together by a Lamport clock: last write
per key wins.

Because writes are append-only and every write is read back and verified, a botched or malicious
write is at worst denial-of-service, never silent data loss.

## Concurrent writes

If two people (or two machines) `set` *different* keys at the same time, both survive. No lost writes,
no locking, on any remote.

Setting the *same* key concurrently is a genuine conflict. One value wins deterministically; the other
is reported and kept recoverable in its segment until the next compaction. notenv warns you, and
re-running the `set` settles it.

## Compaction

Segments accumulate as you write. Once enough pile up, a `set` folds them back into a single snapshot
automatically. It is best-effort housekeeping that never fails your write, and reads are never
affected. `notenv compact` forces it on demand.

Compaction is safe to run while others are writing: their writes are never lost. Just do not run two
compactions of the same namespace at once.

## The object manifest

The authenticated header carries a **manifest**: a keyed fingerprint (MAC of the plaintext) of every
object in the vault, and every object names the key it was written under. Reads check both. This binds
each stored object to the header, so storage-level tampering with any single secret (reverting it,
deleting it, replaying an old one, or copying a real object into another namespace) alarms with the
object named, instead of silently changing what `notenv run` injects.

They still cannot forge a value: a substituted blob they cannot encrypt under the master fails to
decrypt, and reads **fail closed** (a corrupt or substituted object is surfaced as an error, never
silently skipped).

## Safe against a concurrent rotation

A write is also safe against a concurrent master rotation. Every write records itself in the manifest
through the header compare-and-swap, which re-reads and verifies the header first:

- If a rotation landed since the writer unlocked, the write rolls its own object back and tells you to
  re-run (which unlocks the new master and writes cleanly).
- The rotation's own header flip goes through the same swap, so it aborts if a write recorded itself
  after the rotation began, and it re-keys anything written under the old master during its run.

For every non-crash interleaving, no committed write ends up encrypted to a key nobody holds.

## Local vaults

A local vault stores exactly the bytes and layout a remote does, so a vault copied to a remote is
byte-identical and the same trust machinery runs unchanged. Its header writes get a **true
compare-and-swap** (an OS file lock), which is cooperative and same-machine only: a vault directory
inside Dropbox, syncthing, or NFS gets no cross-machine exclusion. Concurrent multi-machine use is
what remotes are for.

On a remote reached through rclone, the manifest swap is a **windowed** compare-and-swap rather than an
atomic one, because object stores expose no conditional write through rclone. The residual is narrow:
a detected race retries cleanly, and the one undetectable ordering leaves an
unrecorded-but-still-included object that the next compaction adopts, never a lost value and never an
alarm against an honest writer. A backend with native conditional writes can close the window for
real. See the [threat model](../security/threat-model.md#known-limitations).
