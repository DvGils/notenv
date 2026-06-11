# Changelog

Notable changes to notenv. This project follows [semantic versioning](https://semver.org);
while pre-1.0, minor versions may include breaking changes. Releases before 0.2.0 are listed
on the [GitHub releases](https://github.com/DvGils/notenv/releases) page.

## 0.6.0 (unreleased)

The agent release: notenv's founding property — plaintext never touches disk, exists only in
the child's environment — turns out to be exactly what AI agents need, because anything an
agent *reads* lands in a model's context and persists in transcripts. This release makes
captured output safe by default and documents the agent story with the same honesty as the
rest of the threat model.

### Added

- **Output masking.** `notenv run` now scrubs the exact secret values it injected from the
  child's stdout/stderr whenever the stream is captured (a pipe, a file, an agent or CI
  harness), replacing them with `<notenv-masked:NAME>` — so a server that echoes its
  connection string on boot no longer hands it to the log or the LLM reading the tool output.
  Streamed across write boundaries (split values are still caught); a live terminal is wired
  through untouched so colors and TUIs keep working; `--mask` forces masking on a terminal,
  `--no-mask` disables it. Best-effort by design: exact byte matching only, values shorter
  than 6 bytes pass through.
- **Joining an existing namespace is confirmed.** A fresh checkout whose derived namespace
  already holds secrets in the vault now asks once before exposing them (warns in CI). This
  closes the remaining namespace-pinning gap: a malicious repository *named after your
  project* could previously derive its namespace silently. A virgin namespace (the
  new-project flow) still pins without ceremony.
- **An agents section in the README**: the context-leak threat, `run`/`list` as the verbs
  that separate using credentials from knowing them, a copy-paste `AGENTS.md` recipe, and the
  limits stated plainly (same-UID extraction and child egress are not defended; no
  agent-containment claim until a broker mode exists).

### Changed

- `notenv run` waits up to 10 seconds for a lingering grandchild holding the output pipe
  after the child exits (previously it could wait forever when output was piped); the child's
  real exit code is preserved.

### Documentation

- Threat model: captured child output joins the security properties (masked, best-effort,
  qualified) and the adversary table; deliberate same-UID extraction and child exfiltration
  join the non-goals explicitly.
- Honest cost notes: passphrase unlock latency scales with the number of passphrase slots;
  SFTP/WebDAV passwords entered during setup briefly pass through argv (prefer key-based
  SFTP auth).

## 0.5.0 (unreleased)

A security-hardening release driven by an end-to-end review of the design against its own
threat model. It closes the one honest-parties data-loss race (writes concurrent with a master
rotation), stops a committed contract from silently retargeting a checkout at another project's
secrets, and makes every local trust decision visible and deliberate. It also folds in the
unreleased 0.4.1 correctness work.

### Security

- **Writes racing a master rotation can no longer strand ciphertext.** Previously, a `set` (or
  worse, a compaction) running concurrently with `notenv key rotate-master` / `key rm` could
  leave objects sealed under the replaced master — undecryptable by everyone once that key
  evaporated, poisoning every read of the namespace. Now every write confirms *after it lands*
  that the master it was sealed under is still the vault's master and rolls itself back
  otherwise (compaction checks before deleting anything and undoes its own snapshot); the
  rotation re-lists the namespace after its header flip and re-keys anything a not-yet-aware
  writer sealed under the old master. Covered for every non-crash interleaving; the
  (seconds-wide, crash-only) residual is documented in the threat model.
- **The namespace is pinned per checkout.** The committed `notenv.toml` chooses the namespace,
  and the namespace chooses which secrets reach a child process — so a cloned untrusted
  repository could name another project's namespace in your vault and have `notenv run` hand
  that project's secrets to its scripts. The git-ignored `notenv.local.toml` now records the
  namespace a checkout has accepted: an unusual namespace (not the directory's name) is
  confirmed interactively on first use, and a contract that later changes its namespace is
  refused until re-accepted with `notenv init`.
- **A vanished header is an alarm, not virgin storage.** A machine that has pinned a vault and
  then finds no header refuses to walk you through creating a fresh one (which also used to
  overwrite the pin, silencing the alarm forever). Restore the header, or use the new
  **`notenv key forget`** after a deliberate vault reset.
- **`notenv key trust` shows what it trades before clearing an alarm**: the pinned revision and
  master next to the observed ones, an explicit warning on a master change or rollback, and a
  confirmation prompt (`--yes` for scripts). Overriding a security check is no longer the path
  of least resistance.
- **Reads trust only rclone's not-found exit codes.** Whether a header "doesn't exist" drives
  the virgin-storage decision, and stderr-text matching (fragile across rclone versions and
  locales) could fake it; text matching survives only for housekeeping subcommands where a
  false match is harmless.
- **Header creation goes through the safe-write protocol** (read back, authenticate, re-unlock
  with the new passphrase) before you walk away believing escrow is done; its freshness check
  also refuses to clobber a header a concurrent setup wrote.

### Fixed

- **Concurrent `set`/`unset` on one machine can no longer collide.** The sequence-counter
  update in `NextSeq` is now locked, so two simultaneous writes never read the same counter and
  emit segments that share a sequence number (which could leave conflict resolution
  non-deterministic).
- **A write whose verify read-back merely lags is no longer deleted.** Writes are verified by
  reading them back; on an eventually-consistent backend that read can lag, and the old code
  deleted the possibly-landed object. It now deletes only on a genuine byte mismatch (real
  corruption) and otherwise surfaces an error for the caller to retry over.
- **`set`/`unset` no longer warn about a conflict the write itself just settled**; conflicts are
  reported from the post-write state.
- **Hidden prompts work on Windows when stdin is a pipe** (`notenv set --stdin`): prompts open
  the console device (`CONIN$`) directly, the same way `/dev/tty` is used elsewhere.
- **A fold that hits an undecryptable object now names it**, so recovery starts from an object
  key instead of a guess.

### Breaking changes

- **Pre-0.4 (versionless) segment and snapshot objects are no longer read.** That lenient path
  was migration logic with no remaining users. A v0 object is refused with a pointer at the
  upgrade path: compact the namespace with notenv 0.4 to rewrite it, or re-add its values.
- **`notenv key trust` now requires confirmation** (interactive prompt, or `--yes` in scripts).

### Documentation

- Threat model: the write/rotation concurrency guarantee and its crash residual, vanished-header
  detection, namespace pinning, and an explicit caveat that warm-cache runs defer the pin checks
  by up to one cache TTL.
- Clarified that the key header and the segment/snapshot payloads are versioned by separate,
  intentional rules; both now reject anything but their exact supported version.

## 0.4.0

A hardening release: more command coverage, and much deeper testing of the storage and
concurrency model under imperfect conditions.

### Added

- **`notenv unset KEY`** removes a stored secret value. It appends a tombstone the fold honors,
  never edits the committed contract, and warns if `notenv run` will now report the key missing.
- Same-key conflicts are now also reported on `set` and `unset`, not only on `run`/`list`.
- **Explicit on-storage format versioning.** Every segment and snapshot now carries a format
  version. A read refuses an object written by a newer notenv with a clear "upgrade notenv"
  message rather than misreading it. Objects written by 0.3.0 (which had no version field) read
  unchanged, so **0.3.0 → 0.4.0 is the first upgrade with no storage break.**

### Changed

- **Caching is documented as Linux-only by design.** macOS and Windows deliberately do not cache:
  no platform-native store (Keychain, Credential Manager/DPAPI) matches the RAM-backed,
  removed-on-logout cleanup guarantee the Linux cache gives, and notenv refuses to ship a weaker
  cache under the same name. This is a stated decision, not a pending feature. (No behavior
  change; caching was never implemented on those platforms.)

### Documentation

- **`THREAT_MODEL.md`**: a full statement of assets, adversaries, the properties that hold
  against each, and the explicit non-goals, plus **`SECURITY.md`** for private vulnerability
  reporting.

### Testing

- A fault-injecting `chaos` storage backend and a seeded, fuzzable multi-machine simulation
  (`go test -fuzz=FuzzSecretLog`) that check the fold and compaction invariants (no lost or
  wrong secrets, correct conflict reporting, transparent compaction) under concurrent, stale,
  and interrupted writes. A short fuzz run is part of CI.

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
  each other's change, on any remote, with no locking. Reads fold a namespace's segments over
  its snapshot, last write wins per key, ordered by a Lamport clock.
- **Conflict reporting.** Setting the *same* key concurrently on two machines is a genuine
  conflict: one value wins deterministically and the other is reported on the next read and kept
  recoverable in its segment until the next compaction.
- **Automatic compaction.** Once a namespace's segments pass a threshold, a `set` folds them
  into a single fresh snapshot so cold reads stay fast. It is best-effort (a compaction failure
  never fails the write) and write-path only (reads never mutate storage). `notenv compact`
  forces it on demand. Compaction writes the new snapshot before removing what it folded and
  only removes objects it read, so a write (or another compaction) that lands concurrently is
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
