# Changelog

Notable changes to notenv. This project follows [semantic versioning](https://semver.org);
while pre-1.0, minor versions may include breaking changes. Releases before 0.2.0 are listed
on the [GitHub releases](https://github.com/DvGils/notenv/releases) page.

## 0.13.0

The principals release: passphrases are for people, identities are for machines. A vault
concentrates risk, so no file at rest may be key-equivalent; this release makes that a
structural property instead of advice. Teammates onboard with a one-time passphrase and end
up with a credential only they know; machines enroll with an identity that lives in the
platform's secret store; the on-disk identity file ceases to exist.

### Added

- **Teammate onboarding with a one-time passphrase.** `notenv key add alice` generates a
  high-entropy onboarding passphrase (six wordlist words), prints it once, and marks the
  slot provisional. Alice's first notenv command refuses to proceed until she replaces it
  with a passphrase only she knows; the one-time passphrase stops working at that moment,
  and the issuer no longer knows any credential of hers. An interceptor would need the
  passphrase and storage read access during that window; `key rotate-master` is the remedy
  if you suspect one.
- **Machine enrollment.** `notenv key add --machine ci` enrolls a CI job or agent: it
  prints a new age identity exactly once, for the platform's secret store, and saves it
  nowhere. `--recipient age1...` enrolls a public key the machine generated itself. Pair
  with `NOTENV_READONLY=1` and a read-only storage credential where the machine only reads.
- **`key list` speaks principals.** The table shows human (passphrase), human
  (provisional), or machine (identity), plus when each slot was added, and warns about
  provisional slots older than a week (the holder never finished onboarding). The `--json`
  shape gains `provisional` and `added`, both omitted when unset.

### Changed

- **Header format v4.** Slots carry the provisional flag and an advisory creation time.
  Older builds refuse a v4 header loudly; this build does not read v3 vaults (pre-1.0,
  no migration path, consistent with earlier format bumps).
- **`key add` is name-first.** The slot name is a positional argument; the `--passphrase`
  and `--name` flags are gone. Adding a backup passphrase slot for yourself is the same
  flow as onboarding a teammate: replace the one-time passphrase on first use.
- **`NOTENV_IDENTITY` is the only identity source.** Inline value, or a path your platform
  materialized. notenv no longer reads (or writes) any identity file of its own.

### Removed

- **`notenv key gen-identity` and the default identity file.** A plaintext age identity at
  a well-known path was the one key-equivalent artifact notenv left at rest, exactly the
  kind of path infostealers harvest. Humans never need one (passphrases plus the session
  cache cover every interactive flow), and machines get theirs from a secret store. There
  is no notenv-owned credential path left for a stealer list to name.

### Documentation

- **The threat model states the credential model.** A new "Credentials at rest" section
  sets the bar (no file at rest may be key-equivalent), scores every unlock path against
  it, and names the honest residuals of concentrating secrets in a vault: the offline
  brute-force surface against a passphrase slot, and the onboarding window. The teams, CI,
  agents, and new-machine guides are rewritten around the split.

## 0.12.0

The documentation release. notenv gets a proper documentation site, the README becomes a
landing page that points into it, and the user-facing output gets a polish pass. Nothing
about the storage format or command behavior changes.

### Documentation

- **A documentation site** at <https://dvgils.github.io/notenv>, built with MkDocs
  (Material) and published from `docs/` by a GitHub Pages workflow. It covers getting
  started, task guides (teams and keys, cloud remotes, CI, AI agents, caching and
  performance), a command and configuration reference, the concepts behind the design,
  and the full threat model.
- **The README is now a landing page.** It keeps the pitch, the comparison table, and a
  quick start, and links into the site for everything deeper.
- **The threat model and security policy moved into the site.** `THREAT_MODEL.md` is now
  a pointer to the site's threat model; `SECURITY.md` keeps the private vulnerability
  reporting link and points its scope there too.

### Changed

- **Clearer error for a vault in an unreadable older format.** Two messages pointed at
  `notenv key migrate`, removed back in 0.9. A vault written in a storage format this
  build no longer reads now says exactly that, instead of naming a command that no longer
  exists.
- **Consistent house style in CLI output.** Removed em-dashes from messages, prompts, and
  help text. Wording only; no flags, output shapes, or exit codes changed.

## 0.11.0

The agent-surface release. Software that uses your vault on your behalf — coding agents,
MCP clients, CI — can now discover what exists, address it from anywhere, parse what it
reads, and be constrained to read-only; and the payload format takes its last change
before the v1 freeze.

### Added

- **Per-secret descriptions and write timestamps.** `notenv set KEY --description "…"`
  records what a secret is and how to use it; every write now also carries an advisory
  wall-clock timestamp (informational only — Lamport order remains the truth). `list`
  shows both in a table on a terminal; piped output stays bare names, one per line.
  A `set` without `--description` carries the existing note forward (`--description ""`
  clears); imports carry notes forward too. Both fields survive compaction and ride the
  winning write under conflicts. This is deliberately the **last payload change before
  the freeze** — the fields are advisory and omitted when empty, so the format version
  does not bump and 0.10 vaults are read unchanged.
- **Projectless vaults: a global `--namespace` flag.** `notenv run --storage b2
  --namespace ops -- psql` works from any directory — no `notenv.toml`, no checkout.
  The flag bypasses the contract entirely: `run` injects every secret in the namespace
  under its storage key, and the contract-sync conveniences don't apply. First use of a
  namespace that already holds secrets is confirmed once per (storage, namespace) and
  recorded user-level (there is no checkout to pin in); `notenv key forget` drops those
  acceptances with the rest of a storage's trust state.
- **Read-only mode (policy).** `read_only = true` on a storage entry, or
  `NOTENV_READONLY=1` for the whole process, refuses every mutating command — set,
  unset, import, compact, the mutating `key` family, vault copy — and refuses to create
  a vault on virgin storage from a read command. Honestly framed: this constrains
  cooperating clients (an honest agent having an accident), it does not contain
  adversaries — anyone who can decrypt can forge writes with their own tooling.
  *Enforced* read-only is the storage credential's job: put a read-only B2 application
  key behind the rclone remote, or read-only directory permissions on a local vault.
- **`--json` on `list` and `key list`.** Frozen, additively-extensible shapes designed
  for machine consumers: `list --json` gives `{namespace, secrets: [{name, description?,
  modified?}]}` (never values); `key list --json` gives `{vault_id, revision, slots}`.
  Golden tests pin both shapes.
- **`run` exit codes agents can read** (docker's convention): the child's own code
  passes through untouched; **125** is notenv's own failure, **126** the command was
  found but cannot run, **127** the command was not found. Until now notenv's failures
  exited 1, indistinguishable from a child that exited 1.
- **`notenv mcp` (experimental).** A Model Context Protocol server over stdio with two
  tools: `list_secrets` (names, descriptions, modified times — never values) and
  `run_with_secrets` (inject and execute; returns exit code and output with every
  injected value masked). An MCP-driven agent on a machine with no checkout can discover
  secrets, use them, and never see one. Hand-rolled minimal protocol: zero new
  dependencies. Experimental: the tool surface may still change.

### Changed

- **Local vaults no longer cache folded blobs.** The blob cache exists to skip a network
  round-trip, and its warm path skips manifest verification — a trade justified against
  a network, not against the same disk. A local vault now verifies the manifest on every
  read and keeps no second ciphertext copy; `cache_ttl` is remote-only. (The master-key
  cache is unchanged.)
- The local folded-blob cache layout is now versioned and carries the secret metadata;
  blobs cached by earlier versions are silently re-fetched once.

## 0.10.0

The adoption release. Until now the first secret was twenty minutes away — install rclone,
make a bucket, mint credentials, walk a config wizard. It is now three commands on a clean
machine: `notenv setup` (a passphrase), `notenv import .env`, `notenv run -- …`.

### Added

- **Local vaults.** `notenv setup` now defaults to a vault in a local directory: no
  accounts, no rclone, nothing to install beyond notenv. It stores byte-identical layout to
  a remote vault — same encryption, same authenticated header and manifest, same trust
  machinery — and its header writes get a *true* compare-and-swap (an OS file lock that the
  kernel releases if the holder dies), strictly stronger than the windowed swap on remotes.
  Confidentiality is unchanged (the same ciphertext that would sit on a provider); the
  honest trade is durability — no off-device copy, no versioning — so the setup message says
  exactly that, and `vault copy` is the way out. Local vaults are single-machine by design;
  syncing across machines is what remotes are for.
- **Promptless creation for agents and CI.** With `NOTENV_IDENTITY` set, `setup` creates
  the vault non-interactively with that identity as its only credential — the whole
  zero-prompt path from nothing to `notenv run` now works headless. Only the environment
  variable triggers this; an identity file on disk never silently changes what setup
  creates.
- **`notenv import`.** Parse an existing `.env` (documented dotenv subset: comments,
  `export` prefixes, quoted and multiline values — and never any variable expansion),
  validate everything up front, and store every value in a single recorded write: an import
  either fully happens or doesn't, and N secrets cost one header round-trip, not N. Keys
  are declared in the contract; `--dry-run` previews names, never values.
- **`notenv vault copy`.** Replicate a vault to new storage and register it as a named
  storage: every object byte-verified, the header installed last (the copy isn't live until
  complete), races with concurrent writes reconciled, the source never touched. No
  re-encryption, no new ceremony — pins follow the vault's own identity, exactly what that
  identity was designed for. Local→cloud is the intended ramp; local→local works too
  (removable media).
- Multiple storages may now be local, remote, or any mix; config entries are validated to
  be exactly one kind.

### Changed

- **rclone is now an optional dependency**, required only for cloud remotes. The
  rclone-missing failure moved from setup's front door into the remote path.

## 0.9.0

The no-shims release: 0.8.0's one-shot migration has done its job and is gone, and the
project's scarcest quality resource — fuzzer-hours — now accumulates every night.

### Added

- **Nightly fuzzing.** All three simulation targets (the secret log, rotation interleavings,
  storage-level attacks) run twenty minutes each every night with full input minimization,
  against the in-memory store for maximum path throughput. The working corpus persists
  between nights and compounds on top of the committed seeds; a crashing input is uploaded
  as an artifact, ready to be committed as a regression seed alongside its fix. (A separate
  nightly soak against a real remote is planned next.)

### Removed

- **`notenv key migrate`** and the version-1 payload reading path, per the rule that
  migration logic lives exactly one release. A vault still on the old formats upgrades by
  running notenv 0.8's `notenv key migrate` once, then returning here; this version's errors
  say exactly that.

## 0.8.0

Every stored secret is now bound to the vault's authenticated header. Until now the header was
tamper-evident but the objects holding the values were not: a party with storage write access
(but no key) could delete a write, revert it via a versioned remote, resurrect a compacted one,
or copy a real object into another namespace — all silently. Each of those now alarms, naming
the object. This is the last planned storage-format change before v1 freezes the format.

### Added

- **The object manifest.** The header records every segment and snapshot: its object key and a
  keyed fingerprint of its content (keyed from the master, so the world-readable header is no
  guessing oracle against secret values; computed over plaintext, so rotations re-encrypting in
  place don't disturb it). Folds trust the manifest, not the storage listing — anything missing,
  altered, relocated, or replayed fails closed with the object named. Objects also carry the key
  they were written under inside the encrypted payload, killing copy/rename attacks including
  cross-namespace injection.
- **Conditional header writes.** Every `set`/`unset`/`compact` records itself in the manifest
  through a header compare-and-swap that doubles as the master-epoch check (replacing the
  post-write verify of 0.5): concurrent writers retry against fresh state instead of clobbering
  each other, and a write racing a rotation rolls itself back exactly as before. On rclone the
  swap is read-compare-put-readback — a windowed best effort whose one undetectable ordering
  self-heals (see below); a backend with native conditional writes can implement it atomically.
- **In-flight write adoption.** A write whose recording never landed (crashed writer, lost swap
  race) still folds — with a warning — and the next compaction records it durably. Snapshots
  track each machine's folded sequence high-water mark, which is what lets a fold tell an
  honest in-flight segment from a maliciously resurrected one, exactly.
- **A storage-attacker simulation.** Arbitrary honest histories, then one storage-level attack;
  the next fold must catch it naming the object (or, for the provably value-neutral moves,
  change nothing). Fuzzed in CI alongside the existing two simulations, which now also drive
  crashed writers. CI fuzzing was also unstarved (bounded minimization) and the curated corpora
  now live in `testdata/fuzz/`, replaying as regular tests; `gocyclo -over 15` joins CI.

### Breaking changes

- **Header format version 3** (adds the manifest) and **payload format version 2** (objects are
  self-naming). Run `notenv key migrate` once per existing vault: it rewrites every object in
  place under your unlocked master and records the manifest in one verified header write. The
  command now migrates version-2 vaults only (upgrade older vaults with notenv 0.7 first) and
  will be removed once version-2 vaults are gone.
- The header revision now advances on every write, not just key operations (each write is a
  header write). Pins advance along with it; no action needed.

## 0.7.0

Multi-machine key continuity: legitimate master rotations now carry cryptographic proof, so
they propagate to every machine silently — and the master-changed alarm, freed from false
positives, finally means what it says. This is the release that makes shared vaults usable by
teams and fleets whose members come and go.

### Added

- **Signed rotation transitions.** Every `key rotate-master` / `key rm` records a transition
  signed by the *outgoing* master (an Ed25519 key derived from the master secret — nothing new
  is stored or escrowed). A machine still pinned at that master verifies the chain — multiple
  rotations deep if it was offline for them — and moves its pin forward without a prompt.
  `notenv key trust` remains only for changes that carry no proof: a non-holder cannot forge a
  transition, so the alarm now identifies genuinely unauthorized changes. (An **ex-holder** can
  forge them — they held the key — so offboarding still ends with rotating the storage
  credential; the threat model spells out this sharpened limit.)
- **Vault identity.** Each vault mints a random ID at creation. Local pins are keyed by it, so
  trust survives relocating a vault to a new remote or base; each storage location is bound to
  the vault it held, so substituting a *different* vault at a known location is refused —
  however internally consistent the impostor is.
- **`notenv key migrate`** upgrades a vault written by an older notenv to the current header
  format: one lossless, end-to-end-verified header rewrite under your unlocked master. The
  command is temporary and will be removed once old-format vaults are gone.
- **Rotation interleaving fuzzing.** The multi-machine simulation now drives master rotations
  racing writes, compactions, and stale-key recoveries, enforcing after every step that a fold
  under the vault's current master succeeds (no object stranded under a dead key) and that
  rotations are value-transparent. A short run joins CI.

### Breaking changes

- **Header format version 2** (adds the vault ID and signing public key). Run
  `notenv key migrate` once per existing vault; newer notenv versions refuse the old format.
- Local trust state (`pins.json`) is restructured around vault IDs; prior pins are not carried
  over — the first unlock per vault re-pins (trust on first use), or run `notenv key trust`.

## 0.6.0

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

## 0.5.0

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
