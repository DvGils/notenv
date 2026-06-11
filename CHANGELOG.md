# Changelog

Notable changes to notenv. This project follows [semantic versioning](https://semver.org);
while pre-1.0, minor versions may include breaking changes. Releases before 0.2.0 are listed
on the [GitHub releases](https://github.com/DvGils/notenv/releases) page.

## 0.3.0

This release makes concurrent writes safe: two machines changing secrets at the same time no
longer overwrite each other. There is no automatic upgrade from 0.2.x; see Breaking changes.

### Breaking changes

- **New on-storage layout, with no migration path from 0.2.x.** A namespace is now an
  append-only set of per-write segment objects (folded into an occasional snapshot) under a
  `<namespace>/` prefix, replacing the single `<namespace>.age` blob. To move from 0.2.x,
  re-add your secrets with `notenv set`. notenv is pre-1.0, so this is a one-time clean break.

### Added

- **Safe concurrent writes.** `notenv set` appends a uniquely named, encrypted segment instead
  of rewriting a shared blob, so two machines setting different keys at the same time never lose
  each other's change — on any remote, with no locking. Reads fold a namespace's segments over
  its snapshot, last write wins per key, ordered by a Lamport clock.
- **Conflict reporting.** Setting the *same* key concurrently on two machines is a genuine
  conflict: one value wins deterministically and the other is reported on the next read and kept
  recoverable in its segment until the next compaction.
- **Automatic compaction.** Once a namespace's segments pass a threshold, a `set` folds them
  into a single fresh snapshot so cold reads stay fast. It is best-effort (a compaction failure
  never fails the write) and write-path only (reads never mutate storage). `notenv compact`
  forces it on demand. Compaction writes the new snapshot before removing what it folded and
  only removes objects it read, so a write — or another compaction — that lands concurrently is
  never lost.

### Known limitations and planned work

- Don't run two compactions against the same namespace simultaneously: it's safe (no writes
  lost) but wasteful, briefly leaving redundant snapshots that the next compaction collapses.
- On an eventually-consistent remote a fold can briefly read stale (never lost) just after a
  compaction; strongly-consistent remotes (Backblaze B2, S3) are unaffected.

## 0.2.0

This release turns notenv from a solo, passphrase-only tool into a multi-user, multi-vault
secrets manager with full key management and tamper-evident storage. There is no automatic
upgrade from 0.1.x; see Breaking changes.

### Breaking changes

- **New on-storage header format and machine-config format, with no migration path from
  0.1.x.** To move from a 0.1.x install, run `notenv setup` to create a fresh vault and
  re-add your secrets with `notenv set`. notenv is pre-1.0 and 0.1.x shipped no key or team
  features, so this is a one-time clean break.
- **`~/.config/notenv/config.toml` now defines named storages** (`[storage.<name>]` tables
  plus a top-level `default`) instead of a single `[storage]` table. `notenv setup` writes
  the new form.

### Added

Team access and key management (`notenv key ...`), with no server:

- `notenv key add --recipient age1...` adds a teammate by their age public key; they never
  share a secret with you. The teammate runs `notenv key gen-identity` to create an identity
  on their machine, which then unlocks the vault with no passphrase.
- `notenv key add --passphrase` adds a backup or second-device passphrase slot.
- `notenv key rotate` changes your own passphrase. `notenv key rotate-master` mints a fresh
  master key and re-encrypts every secret while keeping all slots (a precaution if a machine
  may be compromised).
- `notenv key rm <name|index>` removes a slot **and re-keys the vault**, so the removed
  credential can no longer decrypt. This is real offboarding, not just deleting a credential.
- `notenv key list`, `notenv key set-primary`, `notenv key restore-backup`.

Multiple vaults per machine:

- `notenv setup` adds named storages and can be re-run to add more; the first becomes the
  default.
- A project binds to a storage at `notenv init` time, recorded in a git-ignored
  `notenv.local.toml` beside `notenv.toml`. `--storage NAME` overrides the choice for any
  command (useful in CI to pin the vault from outside the repo).

Integrity (authenticated, version-pinned headers):

- The key header is authenticated with an HMAC keyed from the master key and carries a
  monotonic revision that each machine pins locally. A party who can write your storage but
  holds no key cannot forge or alter the header undetected, and a rollback to an older header
  is detected and refused on any machine that has seen a newer one.
- `notenv key trust` re-pins after a master change you have confirmed is legitimate (for
  example, a teammate rotated the master on another machine).

Other:

- Unlock with a configured age identity (`NOTENV_IDENTITY`, or
  `~/.config/notenv/identity`) in addition to a passphrase.
- Reads recover automatically from a stale cached blob or master after a remote re-key,
  instead of failing with a misleading error.

### Security notes

- notenv does not own your storage, so it cannot revoke a former holder's storage **write**
  access. For complete offboarding, also rotate the storage credential at your provider after
  `notenv key rm`. notenv detects a rollback attempted by such a holder but, on dumb storage,
  cannot prevent it.
- Header integrity is trust-on-first-use: a brand-new machine has no prior revision to
  compare against on first contact with a vault.
- Primary-slot governance is advisory (tooling-enforced), not cryptographic: in shared-master
  team mode every slot holder has the master key.

### Known limitations and planned work

- No compare-and-swap on write yet: concurrent writers to one namespace race and the last
  write wins (object versioning on the remote preserves the overwritten bytes).
- Per-blob value-rollback detection and multi-machine signed key-continuity (so legitimate
  rotations need no manual `notenv key trust`) are planned.
- Native key/blob caching on macOS (Keychain) and Windows (DPAPI) is not wired up yet; those
  platforms prompt and fetch on every run.
