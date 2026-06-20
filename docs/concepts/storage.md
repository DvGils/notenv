# Storage and concurrency

A namespace's secrets live in a single encrypted blob on your storage backend.
Every write replaces that blob and repoints the vault's header at the new one,
under a compare-and-swap that serializes concurrent writers with no server and no
lock you manage.

## One blob per namespace

Each namespace is one age-encrypted object, sealed to the vault's master key.
There is no log, no per-write segments, no snapshots, and nothing to compact: the
blob holds the namespace's current secrets and their metadata, which is all a read
needs.

A write is read-modify-write. notenv decrypts the current blob, applies your
change, writes a new uniquely named blob, and updates the header to point at it.
Because the blob lands at a fresh name and the header swap is what makes it live,
a write that crashes before the swap leaves an unreferenced blob, never a
corrupted one. The next write to the namespace reclaims such leftovers, so there
is no garbage-collect step to run.

## Last write wins, serialized on the header

The vault's header is the single source of truth: it records, per namespace,
which blob is current. A write commits by a compare-and-swap on the header. It
re-reads the header, checks it has not moved since the write began, and swaps in
the new pointer, retrying if another writer got there first.

So two machines writing the same namespace serialize. The loser re-reads the
now-current blob, re-applies its change on top, and swaps again. Writes to
different keys both survive; only writes to the same key resolve last-writer-wins,
and the last write is simply the one that commits last. There is no conflict to
settle and nothing to merge by hand.

## A one-generation backup

Each write keeps the blob it superseded, recorded in the header as that
namespace's backup and vouched for by the same authentication as the current
blob. If the current blob is ever unreadable (bit-rot on a disk that does not
checksum, a truncated upload, tampering), a read fails closed by default: notenv
refuses rather than serve something it cannot verify. Two tools recover from
there:

- `notenv run --skip-corrupt` (and `list --skip-corrupt`) falls back to the
  verified backup, serving the previous generation and reporting exactly what it
  dropped. The most recent write may be lost; nothing is served unverified.
- `notenv namespace recover <namespace>` rebuilds the namespace from its
  one-generation backup and drops the corrupt blobs, so ordinary writes work
  again. If nothing readable survives (the backup is gone too) it stops without
  changing anything and points you to `notenv namespace delete`.

A remote that keeps its own object versions is an extra backstop, not something
notenv relies on: the one-generation backup is kept on every backend.

## Integrity: the manifest

The header carries a **manifest**: for each namespace, the current blob and its
backup, each fingerprinted by a MAC keyed from the master key. The whole header
is authenticated by a tag and stamped with a monotonic revision that each machine
pins locally. A read checks all of it: the blob must exist, decrypt under the
master, match its recorded MAC, and declare its own namespace.

This binds every blob to the authenticated header, so storage-level tampering with
a secret (reverting it, deleting it, replaying an old generation, or copying a
real blob into another namespace) is caught with the blob named, instead of
silently changing what `notenv run` injects. A party who can write your storage
but holds no key cannot forge a blob either: a substituted object will not decrypt
under the master, and reads fail closed.

## Local vaults and remotes

A local vault stores exactly the bytes and layout a remote does, so a vault copied
to a remote is byte-identical and the same trust machinery runs unchanged. The two
differ only in how the header compare-and-swap is enforced:

- A **local** vault gets a true compare-and-swap through an OS file lock. It is
  cooperative and same-machine only: a vault directory inside Dropbox, Syncthing,
  or NFS gets no cross-machine exclusion, so concurrent multi-machine use is what
  remotes are for.
- A **remote** reached through rclone has no conditional write, so the swap is
  read-compare-write-readback. That is sound on a read-after-write-consistent
  store, which every major object store is today, so concurrent header writers
  require such a remote: it is a contract, not a hope. A backend with native
  conditional writes could make the swap atomic.

For the keys, slots, and signed rotations the header carries, see
[Keys and slots](keys-and-slots.md). For what all this defends and what it does
not, see the [threat model](../security/threat-model.md).
