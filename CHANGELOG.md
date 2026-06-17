# Changelog

Notable changes to notenv. This project follows [semantic versioning](https://semver.org);
while pre-1.0, minor versions may include breaking changes. Releases before 0.2.0 are listed
on the [GitHub releases](https://github.com/DvGils/notenv/releases) page.

## 0.20.0

An input-integrity pass: notenv now defines exactly what a secret value may contain
and stores it byte-for-byte, so a value is always handed back exactly as it went in
and can never leak control characters into a `.env` file or a terminal.

**Breaking, on purpose: the namespace blob format is now version 2 and an older (v1)
vault is not read by this version.** Each blob now stores its values and descriptions
base64-encoded, so any stored byte round-trips exactly; the previous format kept them
as raw JSON strings, where Go's JSON encoder silently rewrites invalid UTF-8 to the
replacement character (a value you could never get back intact). There is no in-place
upgrade (pre-1.0, no stable release): `notenv export` from the old binary and
`notenv import` into a fresh 0.20.0 vault.

### Added

- **`notenv inspect handoff` tells a launched program whether it is in a scoped
  handoff session.** A coding agent started with `notenv handoff -- <agent>` holds
  only a scoped, ephemeral copy of one namespace; one started with `notenv run`
  instead has the raw values in its environment and no scoped vault. This subcommand
  lets the program tell the two apart at startup: exit `0` means it is inside a live
  handoff, exit `1` means it is not, and `--json` adds the single namespace it was
  scoped to. It reads only its own environment and the ephemeral vault on disk, so it
  never unlocks a vault, asks for a passphrase, or prints a secret value. The "yes"
  answer is corroborated against live ground truth (the named ephemeral vault must
  still exist and its supervisor still be running), so a stale or clobbered
  `NOTENV_SESSION` fails safe to "no" rather than a false sense of being scoped.
- **`notenv run` nudges toward `handoff` when the command looks like a coding agent.**
  Running a known agent (Claude Code, Codex, Copilot, Gemini, Aider, OpenHands,
  Continue, OpenCode, Cursor) through `run` injects this namespace's real secret
  values into its environment; `handoff` instead gives it a scoped ephemeral vault and
  keeps your master key out of reach. The guard asks before proceeding (default no),
  and only ever asks a human at a terminal: a non-interactive caller, or a process
  already inside a handoff session, proceeds untouched. It is accident-proofing, not
  enforcement: a wrapper invocation like `npx <agent>` is not matched.

### Changed

- **A secret value must be valid UTF-8 with no control characters other than newline,
  tab, and carriage return.** A value becomes an environment variable and may be
  written back out as a `.env`, so it has to survive both: a NUL cannot ride in an
  environment variable at all, an ESC and friends cannot be represented in a `.env`,
  and invalid UTF-8 was silently corrupted at rest. notenv now refuses these on `set`,
  `import`, and `edit`, early and with a clear message, and enforces it at the storage
  layer that every write funnels through. Binary belongs base64-encoded, which is
  itself valid text and passes; the error says so. The newline family is allowed
  because real secrets carry it (PEM keys, JSON blobs, CRLF certs).

### Fixed

- **`vault copy` and `vault delete` can no longer destroy unrelated data.** Copying a
  vault to a local `--to-path` reconciled the destination by deleting anything the
  source did not have, so pointing it at a populated directory (a home directory, a
  project, `/`) deleted that directory's other files; `vault delete` likewise removed
  its whole configured path or, on a remote, every object under its prefix, taking out
  other data a shared bucket happened to keep there. notenv now recognizes its own
  objects (reserved plumbing and `<namespace>/data-*.age` blobs) and only ever deletes
  those: copy refuses a destination that already holds a file it did not write, delete
  refuses any storage (local or remote) that holds an object notenv did not create, and
  `--to-path` rejects the filesystem root and your home directory outright. An empty
  destination, or one holding only the blobs of an interrupted earlier copy, is still
  accepted. A remote delete now also removes the vault's header objects, which it
  previously left behind.
- **Remote operations work with older rclone versions again.** Deleting an object that
  is already gone is a no-op, but older rclone (around 1.60) reports a missing target
  with a generic exit code rather than the dedicated not-found one, so notenv treated it
  as a real failure. notenv now confirms the object is actually absent (a check that
  behaves the same on every rclone version) before reporting success, so a delete of a
  missing object no longer errors on an older rclone.

### Hardened

- **The `handoff` builder can no longer cache your real master key.** Caching the
  source vault's master during a handoff would leave it where the agent (which runs as
  you) could read it and open your real vault. A no-cache lease already suppressed this
  machine-wide, but the builder now also unlocks the source with a hard-coded zero cache
  TTL, so it cannot store the master even if the lease is somehow absent, and never
  honors a `cache_ttl` an agent might have rewritten into your config. Warm reads and
  the post-build cache drop are unchanged; only the store is foreclosed.
- **`export` never writes a raw control byte into the `.env`.** Carriage return now
  joins newline and tab as an escaped sequence (`\r`), and because values are
  validated no other control byte can occur, so an exported value can no longer break
  a third-party dotenv parser's line splitting or inject a terminal escape sequence
  when the file is viewed. The dotenv reader decodes `\r`, so the `export | import`
  round-trip stays exact.
- **Secret descriptions are escaped when displayed.** A control character in a
  description (shown by `list` and `inspect`, and written as a comment by `export`) is
  rendered as a visible escape, so a description can no longer break the table layout
  or inject a terminal escape sequence (for instance a teammate's booby-trapped
  description shown by `notenv list`). Descriptions are still stored faithfully and
  `--json` output is left exact; only the human-facing rendering is sanitized.
- **The "RAM-only on Linux" guarantee is now verified, not assumed.** The blob
  cache, the `edit` buffer, and the `handoff` ephemeral vault live under
  `XDG_RUNTIME_DIR`, which notenv took on faith to be the spec's tmpfs (RAM-backed,
  owner-only). A misconfigured or overridden value (some `sudo`/cron/SSH contexts, or
  a hand-exported one) could silently put cached ciphertext or a plaintext buffer on
  persistent disk. notenv now checks the directory is owner-only and on a
  tmpfs/ramfs filesystem before trusting it: the blob cache disables itself rather
  than cache on real disk, and `edit` (always) and `handoff` (only when the source is
  a remote vault, since a local one already keeps ciphertext on this disk) ask before
  falling back to a temporary file on disk, naming the fix. macOS and Windows are
  unchanged; the temp-dir fallback is the documented norm there.
- **Passphrases are harder to brute-force offline.** Since storage is dumb, anyone
  who copies a vault (or sits on the wire) can grind its key slots offline, so the
  bar is raised on both axes. The passphrase notenv generates, at creation and for
  onboarding, is now eight words rather than six (about 83 bits of entropy, up from
  62), and every passphrase slot is wrapped with scrypt at work factor 2^19 instead
  of age's default 2^18, doubling both the time and the memory each offline guess
  costs. The work factor is the one lever that also hardens a passphrase you chose
  yourself. It is backward compatible: age records the work factor in each wrapped
  slot, so existing vaults keep opening and a slot adopts the stronger cost the next
  time its passphrase is set or rotated.
- **The warm cache honors the handoff session guard.** A `notenv run`/`list` inside
  a handoff session that hit the local cache could return a vault other than the
  session's straight from cache, skipping the guard the cold path applies. The
  handed-off source vault was never exposed (its master is dropped and held out of
  the cache for the session), but another vault left warm in the cache could be. The
  warm path now applies the same guard.
- **A cached blob is bound to its namespace, not just the master.** The warm cache's
  tamper check proved an entry came from the master but not which namespace it
  belonged to, so a same-machine writer of the cache directory could move one
  namespace's cached entry into another's slot and have it served as that namespace.
  The check now covers the entry's (scope, namespace) too, the same binding the
  on-storage blob already carries, so a cross-namespace entry is rejected and the
  authenticated read runs instead.
- **`notenv key evict` runs the onboarding gate like every other write command.** A
  holder still on the temporary onboarding passphrase (which the inviter also knows)
  could run the lossy `evict` repair without first replacing it; it now requires
  setting an own passphrase first, matching `set`/`import`/`edit`/`add`/`rm`.
- **`notenv edit` wipes its scratch buffer on a terminal hangup, not just Ctrl-C.**
  The buffer holding the values you type was removed on `SIGINT`/`SIGTERM` and on a
  clean exit, but a `SIGHUP` (the terminal or an SSH connection closing) or `SIGQUIT`
  could leave it behind. It now unlinks the buffer synchronously on every signal a
  process can catch. `SIGKILL` and power loss run no handler and cannot be cleaned
  synchronously, but the buffer is RAM-backed in the normal case (discarded on
  reboot/logout regardless) and reaches persistent disk only in the fallback that
  now prompts first; this is not papered over with a flaky next-run sweep.
- **Object reads are size-capped, so a hostile remote cannot exhaust memory.**
  Storage is treated as dumb and possibly hostile, but neither backend bounded how
  much a single read pulled into memory: rclone buffered the child's whole stdout,
  the local backend read the whole file, and the header is JSON-parsed before its
  master-keyed tag can be checked, on paths that never unlock (`inspect --all`, the
  namespace first-use check). A remote could serve a multi-gigabyte header (or one
  packed with millions of slots) and OOM the machine with no credential, pre-auth.
  Reads now stop at a generous cap (8 MiB for the header, 64 MiB for a namespace
  blob, far above any real vault) and fail closed with a clear error instead; the
  rclone child is killed the instant it overruns rather than left streaming. Object
  *listings* are bounded the same way (64 MiB of object-key names, ~a million
  keys), so a remote cannot OOM the `doctor`, `vault copy`, or cleanup paths by
  serving millions of object names either.
- **Unlocking won't burn unbounded scrypt work on attacker-planted slots.** age's
  decrypt side accepts a work factor up to 2^22 (minutes and gigabytes per
  attempt), and `Unlock` trial-decrypts every passphrase slot before the master or
  the header tag is known, so a storage-write attacker with no key could plant
  slots stamped at a huge work factor and make the victim's next unlock grind
  through them, pre-auth, per slot. notenv now clamps the accepted work factor to
  just above what it writes (a higher-cost slot is refused before any scrypt runs)
  and refuses a header with an absurd number of slots. A planted slot could never
  open the vault anyway (its key is not a recipient of the master); these bounds
  only stop the wasted work. The companion to the read-size caps above: together
  they close the pre-auth resource-exhaustion surface.

## 0.19.1

A correctness and footgun pass after 0.19.0, plus internal cleanup. No storage-format
or surface change.

### Changed
- **Full CLI message sweep**: A full pass of the user-facing CLI messages was done and many were updated for consistency and UX.

### Fixed

- **`import` no longer stores an empty value's trailing comment as the secret.** A
  hand-written line like `PASSWORD= # set me later` parsed to the value
  `# set me later` (the whitespace before `#` was trimmed away before the comment was
  detected), which was then encrypted and injected as the secret. It now reads as an
  empty value, as documented.
- **`key`, `export --all`, and `vault copy` now honor `NOTENV_STORAGE`.** Their header
  path resolved storage by `--storage` / project binding / machine default only, so a
  process pointed at a vault solely via `NOTENV_STORAGE` (an agent, CI, or `handoff`)
  silently operated on the machine default instead, and `export <ns>` and `export --all`
  could resolve to two different vaults in one environment. They now use the same
  selection as the rest of the CLI.
- **`notenv edit` confirms before wiping a whole namespace.** A truncated or emptied
  buffer (an editor that wrote nothing, a stray select-all-delete) used to delete
  every secret without asking. An all-delete now requires confirmation, and aborts
  where there is no terminal to confirm on.
- **`edit`/`set`/`import` no longer corrupt a contract whose `[secrets]` header has
  inner spaces.** `Declare` matched only the exact string `[secrets]`, so a
  hand-written `[ secrets ]` made it append a second `[secrets]` table that the next
  parse rejected. The header is now matched structurally, and re-declaring an
  existing key is a no-op.
- **A sub-second `crypto.cache_ttl` no longer disables expiry on Linux.** A value
  like `500ms` truncated to 0 seconds, which clears the kernel-keyring timeout (the
  key never expires); it is now floored to 1 second.
- **Concurrent handoffs of the same vault keep the no-cache lease.** The lease is now
  refcounted (one marker per supervisor), so the first session to end no longer drops
  the protection while another handed-off agent is still running.
- **`notenv edit` refuses values it cannot represent instead of corrupting them.** Its
  single-line, no-quoting buffer cannot round-trip a value with surrounding whitespace
  or an embedded newline; editing such a namespace used to silently trim or mangle the
  value on save. `edit` now refuses up front, naming the keys and pointing to
  `notenv set --stdin`.
- **A header is never overwritten without a recoverable backup (rclone).** The backup
  step treated any "not found" in rclone's output as "no header yet" and skipped the
  backup, but rclone emits that text for non-absent failures too, so a transient
  failure could let a write overwrite the live header with no `.prev`. The safe-write
  protocol now backs up only when a header exists and fails closed if the backup
  fails, and skips it entirely on virgin storage (one fewer request on the first
  write).
- **`set --stdin` no longer keeps a trailing `\r` from CRLF input.** A value piped from
  a Windows-style source (`secret\r\n`) stored a hidden trailing carriage return; the
  trailing line terminator (`\r\n` or `\n`) is now stripped as a unit.
- **A handoff session refuses `export` / `run --no-mask` / `vault delete` against a
  vault other than its own.** These re-authenticate through a path that did not check
  the handoff-session guard, so they prompted instead of failing closed when pointed at
  a different vault inside a session; they now fail closed like the rest of the unlock
  surface. (Defense-in-depth: that path never caches the master.)
- **Registering a storage no longer silently repoints an existing name.** Reusing a name
  for a different location overwrote the old entry without asking, orphaning the vault that
  name addressed. The exposed path was `vault copy` (which also did it *after* a full copy);
  it now refuses unless you pass `--force`, and checks before copying so a large copy is
  never spent only to be rejected. Re-registering the same location stays a no-op.
- **`handoff` cleans up after a session that was killed before teardown.** A `SIGKILL`,
  power loss, or Ctrl-C during the vault-build phase could leave the ephemeral vault's
  trust pin (and, off tmpfs, its directory) behind. The build phase now tears down on
  Ctrl-C, and each `handoff` sweeps leftovers from earlier dead sessions (live sessions are
  left untouched).

## 0.19.0

The agent release: a scoped, ephemeral handoff so a coding agent can use a namespace's secrets
without ever holding the key to the rest of your vault.

### Added

- **`notenv handoff -- <agent>`.** Runs an agent against an ephemeral vault holding only the resolved
  namespace (from the project `notenv.toml`, or `--namespace`), under a fresh key minted in a
  short-lived builder subprocess that exits before the agent starts. Your master key is never in the
  agent's reach, so a compromised or prompt-injected agent can decrypt at most the namespace you
  handed it, never the rest of your vault. The ephemeral vault is destroyed at exit. This protects the
  master key; it is not a sandbox (the agent still runs as you). See
  [Agent handoff](https://dvgils.github.io/notenv/concepts/agent-handoff/) and
  [AI agents](https://dvgils.github.io/notenv/guides/ai-agents/).
- **`NOTENV_STORAGE`.** Point a process at a vault by configured name or a self-contained spec
  (`local:<absolute-path>` or `rclone:<remote>:<base>`): the env-shaped sibling of `--storage`.
- **`notenv inspect`.** Metadata about what a vault holds, never a value: `inspect KEY` (a secret's
  existence, length, description, and modified time, exit 1 if absent), `inspect` (the namespace's
  secrets with lengths and a count), and `inspect --all` (the vault's namespaces, id, revision, and
  storage, read from the header alone so it needs no passphrase). `--json` throughout.

### Changed

- **A handoff holds a no-cache lease on its source vault.** While an agent session is live, the
  source vault's master key stays out of the shared session cache, so unlocking the same vault in
  another terminal re-prompts for the duration instead of caching. Other vaults are unaffected.
- **The agent skill is slimmer**, pointing the agent at `notenv --help` for the full surface rather
  than enumerating it, with guidance for working inside a handoff session.

### Removed

- **The MCP server (`notenv mcp`).** It added a second agent-integration surface and mental model
  without offering much over `handoff`, the stronger, shell-first path. If you relied on it, open an
  issue and we will reconsider re-implementing it.

## 0.18.0

The storage-simplification release, and the last big break before the v1 format freeze. The
append-only change log (per-write segments folded over snapshots by a Lamport clock, with
compaction, per-machine sequence counters, and replay detection) is gone, replaced by a single
encrypted blob per namespace under last-write-wins. Every write decrypts the current blob, applies
its change, writes a fresh blob, and points the header at it under the same compare-and-swap that
already guards the manifest. The hardened machinery being removed is exactly where the gnarliest
concurrency bugs lived, so this deletes whole bug classes, not just code.

**Breaking, on purpose: this does not read a vault written by an earlier notenv.** The header format
is now version 6 and an older vault fails closed with a clear message. There is no in-place upgrade
(pre-1.0, no stable release): to move secrets across, `notenv export` from the old binary and
`notenv import` into a fresh 0.18.0 vault.

### Changed

- **One encrypted blob per namespace, last-write-wins.** Two people writing the same namespace
  serialize on the header swap; the loser re-reads the now-current blob and re-applies its change, so
  writes to different keys both survive and only same-key writes resolve last-writer-wins. The
  property the log gave up is lock-free parallel writing, which the rare-interactive-write premise
  never needed. Same-key concurrent edits no longer surface as a "conflict": there is one current
  value, the last write.
- **A corrupt namespace blob falls back to a one-generation backup.** Each write keeps the blob it
  superseded (recorded by a `prev` pointer the header still vouches for), so a bit-rotted or truncated
  current blob loses at most the most recent write instead of the whole namespace. Kept on every
  backend; a remote's own version history is a bonus, not something notenv relies on.
- **`notenv key evict-object <object>` is now `notenv key evict <namespace>`.** It rewrites a
  namespace whose current blob is unreadable from what survives (its backup, or empty if that is gone
  too) and drops the corrupt blobs, the per-namespace shape of the salvage story.
- **`notenv doctor` reports per namespace.** It verifies each namespace's current blob (and notes a
  missing or corrupt backup), and reports a stored object no manifest entry references as an orphan
  from a crashed write; the next write to that namespace reclaims it.
- **Orphan blobs are reclaimed automatically, with no garbage-collect step.** A blob a crashed write
  left behind (written but never recorded in the manifest) is deleted by the next successful write to
  its namespace, scoped to what existed before that write so a concurrent writer's in-flight blob is
  never touched. Cleanup rides every write instead of being a chore you run.

### Removed

- **`notenv compact`.** There is no log to collapse; a namespace is always exactly one blob (plus its
  one-generation backup). Auto-compaction and the per-machine sequence-counter state it needed are
  gone with it.
- **The `versioned` machine-config field, and every behavior keyed on it.** notenv no longer guesses
  whether a remote keeps object versions (it never verified the guess, and the fallback it pointed at
  was a manual `rclone` step it could not perform). It now always keeps its own `.prev` header backup,
  so `notenv key restore-backup` works on every backend, including B2. A `versioned = ...` line in an
  existing machine config is ignored.

### Hardened

- **A header write that commits but cannot be confirmed no longer destroys the write.** On an
  eventually-consistent remote a post-swap read-back can fail after the swap has already landed; the
  write path now treats that as committed-but-unverified and keeps the blob the live header
  references, instead of deleting it and stranding the namespace. It reports "may have landed; run
  `notenv doctor` / `notenv key restore-backup`" rather than a false "nothing was stored".
- **`export` and `vault delete` run the rollback/substitution check** that every `run`/`list` read
  does, so plaintext egress and deletion refuse a rolled-back or wholesale-replaced vault instead of
  acting on stale or foreign state.
- **Namespace existence is judged by the authenticated manifest, not the raw object listing,** so an
  orphan blob from a crashed write no longer makes an empty namespace look populated (which could
  trigger a spurious "expose these secrets?" prompt).
- **Removing the last secret drops the namespace entirely.** An `unset` that empties a namespace no
  longer leaves an empty blob behind, so the namespace stops reporting as holding secrets (no spurious
  first-use prompt, no false "found existing secrets" on init).
- **MCP namespace discovery reads the authenticated manifest,** not the raw object listing, so an
  orphan blob from a crashed write can no longer surface as a phantom namespace over MCP.
- **macOS: the cached master key no longer passes through `security`'s argv.** It is fed to the
  Keychain over stdin (the tool's interactive mode) instead of as a `-w` argument, so it can no longer
  be read from the process listing or captured by an EDR/MDM agent. This matches Linux (the kernel
  keyring) and Windows (DPAPI), which already keep the key out of argv. No cgo; the build stays static.
- **The onboarding fingerprint widened from 60 to 80 bits** (12 to 16 base32 characters), raising the
  bar against an attacker who grinds a colliding vault identity on a compromised onboarding channel,
  while still fitting in a chat message. The code is recomputed, not stored, so this only affects an
  onboarding string generated by one version and verified by another.
- **An interrupted `key rm` says plainly when revocation is incomplete.** If re-encryption fails
  *after* the re-key commits, the removed credential can still read the namespaces not yet re-keyed;
  `key rm` now tells you to treat that credential as not revoked and re-run, instead of a generic
  error that reads like nothing changed.
- **`edit` no longer silently clears a description** when a blank line falls between a key's
  description comment and the key (an editor reflow, say). An absent comment now keeps the stored
  description; clear one with `notenv set KEY --description ""`.
- **The warm local cache now verifies a master-keyed MAC before serving.** Cached ciphertext is
  bound to the master with a MAC a cache-writing attacker can't forge (age encryption is to the
  master's public recipient, which the header exposes, so ciphertext alone wasn't proof of origin); a
  forged or tampered cache entry is rejected and the authenticated read runs instead.
- **`NOTENV_ACCEPT_NAMESPACE` is now a per-invocation override, not a permanent grant.** Accepting a
  namespace via the env var no longer persists it, so a later run without the env re-confirms. An
  interactive accept still persists, as before.
- **`edit` warns on Linux when `XDG_RUNTIME_DIR` is unset,** because the buffer then falls to `/tmp`
  on persistent disk where a typed value could linger if the editor or notenv is killed. Point
  `XDG_RUNTIME_DIR` at a RAM-backed dir to avoid it; existing values never reach the buffer.
- **`export` warns that its output is for `notenv import`, not `source`.** Values are emitted
  literally, so a value containing `$(...)` or backticks is data here but a shell would execute it on
  `source`; the warning is in the command help and at the top of the output (the dotenv parser ignores
  it, so the import round-trip is unaffected).
- **`notenv key evict` refuses if the namespace changed since it read,** so a concurrent repair that
  landed mid-evict is not clobbered by the older salvaged state.
- **Re-stating a value with `set` or `import` no longer reverts a description** another machine
  changed concurrently: the existing description is carried forward from the live blob at write time,
  not a stale earlier read.
- **Object listings exclude storage plumbing consistently across backends.** The header and its
  backup are filtered out of every backend's object listing through one shared definition, locked by a
  conformance test, so whole-vault and orphan-cleanup operations can never mistake the header for a
  stray object (the local and remote backends previously disagreed on what a listing returned).

## 0.17.1

A patch release: the session-key cache on macOS and Windows could store an entry that read back
already expired.

### Fixed

- **The session-key cache on macOS (Keychain) and Windows (DPAPI) no longer expires an entry the
  instant it is stored.** Both recorded the expiry deadline at one-second resolution, so an entry
  written just before a second boundary rounded its deadline down and could read back as already
  expired: the first `Get` after `Store` missed, forcing an unnecessary re-prompt (and a flaky cache
  test). The deadline is now nanosecond-resolution, so a TTL lasts its full duration. Linux was
  unaffected (the kernel keyring enforces the timeout natively). A cache entry written by an earlier
  version is treated as expired and re-fetched once.

## 0.17.0

The ergonomics-and-offboarding release. The first run loses its rough edges, output masking gets
meaningfully stronger (it now scrubs a secret's common encodings, not just its literal bytes), and a
clean way out arrives: export your plaintext and delete a vault, without notenv ever writing a secret
to a file.

### Added

- **`notenv export`: take your secrets and leave.** Prints a namespace (or, with `--all`, the whole
  vault) as `.env` to standard output, the inverse of `import`, so `notenv export | notenv import`
  round-trips a namespace. notenv never opens a plaintext file itself; it writes only to stdout, and
  redirecting it (`notenv export > .env`) is your deliberate act, so the no-plaintext-on-disk promise
  holds. There is deliberately no `--output` flag. Bulk plaintext egress is gated like `run
  --no-mask`: it asks for the vault's primary passphrase even when the session key is cached, refuses
  without a terminal, and a machine identity cannot perform it. `--json` emits a structured form.
- **`notenv vault delete`: remove a vault for good.** Deletes a configured vault's objects, this
  machine's trust state for it (the rollback pin and cached key), and its entry in the machine
  config, behind the primary passphrase and a type-the-name confirmation. notenv removes the live
  vault; a versioned remote's history and your own backups are the provider's to purge, and the
  message says so. There is no `--force`: notenv only ever destroys a vault you can prove you own. If
  you have lost the passphrase, delete the storage yourself and run `notenv key forget`.

### Changed

- **Output masking now catches a secret's common encodings, not just its literal bytes.** Because
  notenv knows the exact values it injected, it scrubs each one along with its base64 (standard and
  URL, padded and not), hex (upper and lower), and percent-encoded forms from captured output, with
  none of the false-positive risk a guessing scanner carries. So a token base64'd into an auth header
  or a password percent-encoded into a logged URL is caught now. It stays accident-proofing, not a
  boundary: a value transformed in a way notenv does not anticipate, or embedded in a larger blob
  before encoding, still passes, as do values shorter than 6 bytes. A first-byte index keeps matching
  fast as the pattern set grows, so injecting many secrets stays snappy.
- **A smoother first run.** `notenv init` no longer prompts for a namespace: it defaults to the
  directory name and shows it in the result (`--namespace` still overrides). A first-time `notenv
  setup` no longer asks "add another storage?" right after creating your first vault (re-running
  setup still offers it). And `notenv init` confirms before scaffolding a project in your home
  directory or a filesystem root, so a mistyped `cd` does not quietly make `$HOME` a notenv project.

### Documentation

- The masking limits are restated now that common encodings are caught: the example of what defeats
  masking is a transform notenv does not anticipate (piping a value through `rev`), not `base64`,
  which is now masked. The threat model, the AI-agents guide, and the `run` help text reflect this.

## 0.16.0

The pre-v1 hardening release. A five-way bug hunt across the storage, crypto, key-management,
backend, and CLI layers, run before the v1 freeze with every finding fixed; the first slice of
the credential broker; a way out of a corrupt object; and a crypto format that now describes its
own algorithms, so a future KDF or post-quantum recipient is an additive change instead of a
format break.

### Security

- **The vault credential no longer leaks into child environments.** A recipient identity supplied
  via `NOTENV_IDENTITY` decrypts the whole vault, and `run`, `mcp run_with_secrets`, and the
  `edit` editor all built the child's environment from the parent's unfiltered, so the
  master-equivalent key was inherited by every child and could land in a log, a crash report, or
  an `env` dump. `NOTENV_IDENTITY` is now stripped from the child. This is the broker's first
  slice: accident-proofing for the credential, the analog of the output masker, not a containment
  wall. A same-uid child can still read the value deliberately (that is the OS boundary's job, and
  the threat model says so), but the accidental leak is closed. A nested `notenv run -- notenv …`
  still works, because the inner notenv unlocks from the session cache rather than the variable.
- **`Remote` and `Base` are validated before they reach rclone.** They were taken raw and kept
  safe only by the end-of-options marker at the exec boundary. They are now rejected on write for
  a leading dash, control characters, and (for the base) `..` path segments, so a later refactor
  that trusts the marker less cannot reopen flag injection.

### Added

- **A way out of a corrupt or missing object.** A single recorded object that was missing,
  undecryptable, or failed its manifest MAC used to fail every read and every compaction for the
  whole namespace, with no tool-supported recovery. Now `notenv key evict-object <key>` drops the
  object from the manifest and storage (acknowledged data loss, gated behind `--yes`), and
  `notenv run|list --skip-corrupt` reads past untrustable objects non-destructively, resolving
  every key it still can and naming each one it dropped. The default fold stays fail-closed:
  salvage is opt-in, so a dropped or tampered object is never silently skipped. `doctor` now
  decrypts and MAC-checks every recorded object when a session key is cached, so a
  present-but-corrupt object is caught before a read trips over it, and its advice no longer points
  at a compaction that cannot run.
- **The crypto format is now self-describing.** The header records the cipher suite it uses and
  each passphrase slot records its KDF, and a build refuses, fail-closed, any suite or KDF it does
  not implement. notenv ships exactly one of each, so nothing changes today, but a future stronger
  KDF or a hybrid post-quantum recipient becomes an additive registry entry rather than a format
  break. notenv owns the choice entirely; there is no user-facing suite concept.

### Fixed

- **A reset or migrated sequence counter no longer causes a false replay lockout.** Replay
  detection assumed a machine's sequence counter only moves forward, but that counter is local,
  per-scope state classified as silently migratable, while the high-water it is checked against
  lives on the remote keyed by the durable machine id. Losing or migrating the counter (a restore
  that omits it, or renaming a remote, which restarts it at zero) while the machine id survived
  could make an honest write look like a replayed deletion and fail the namespace closed for every
  machine. A write's sequence number is now floored at the fold's observed high-water for that
  machine, so a lost counter can never reissue a number already on storage.
- **Concurrent `rotate-master` no longer strands teammates with a false rollback alarm.** The
  rotation history lived in a separate object with no compare-and-swap, so two machines rotating
  from the same master could have the loser's write erase the winner's transition record, leaving a
  third machine pinned at the old master unable to find a signed path forward. The history now rides
  inside the header, so a master change and its signed record land in one compare-and-swap.
- **`Unlock` no longer aborts on a slot that decrypts but does not open the master.** A stale slot
  from an interrupted `key rm`, or one planted under a known passphrase, could shadow a valid later
  slot sharing that passphrase. The loop now skips a slot whose key is not a recipient of the
  master and continues, failing only once every slot is exhausted, with a distinct message when a
  passphrase matched a slot that could not open the vault (a tampered or half-rotated header).
- **`restore-backup` re-pins after restoring.** Every other header writer advances the local pin;
  this one did not, so restoring a one-revision-old backup after the pin had moved ahead raised a
  rollback alarm on the operator's own recovery and pointed them at a security override. It now
  re-pins to the restored header (gated on the cached master verifying it), so an honest restore no
  longer reads as an attack.
- **`set-primary` onto a machine slot is refused.** Assigning primary to a recipient
  (machine/teammate) slot froze governance: transferring or removing primary then required that one
  identity, and losing it made primary unrecoverable. Primary is a human governance anchor; a
  machine identity can no longer hold it.
- **A Ctrl-C during a hidden prompt no longer leaves the terminal with echo off.** Hidden prompts
  now restore terminal state before exiting on a signal, so a subsequently typed secret is not
  invisible.
- **The MCP output masker no longer skips short values.** The CLI masker skips values under six
  bytes to avoid shredding tokens like `8080`; on the MCP surface the masked stream feeds a model's
  context, where a short PIN should not pass through, so the MCP masker has no floor.
- Tidies: a leading byte-order mark on an imported `.env` is stripped instead of becoming part of
  the first key; the local backend's path guard rejects a `..` path component rather than any `..`
  substring; object names now carry 64 bits of randomness.

### Breaking changes

- **Header format version 5.** The rotation history moved into the header, and the header gained
  the cipher-suite and per-slot KDF identifiers. v4 vaults (0.13 through 0.15) are not readable by
  this build (pre-1.0, no migration path, consistent with earlier header bumps). The
  segment/snapshot payload format is unchanged at version 3.

### Documentation

- The threat model and the agents/CI guidance frame the broker's first slice: what the credential
  strip contains (accidental leakage into child environments) and what it does not (a same-uid
  process that is actively looking, or the orchestrator that holds the credential by necessity),
  with the OS trust boundary that real containment requires.

## 0.15.0

Deletions become durable, the passphrase prompt stops being a tax on macOS and Windows,
and the agent surface ships in both formats agents come in.

### Fixed

- **A deleted key can no longer resurrect.** Deletions were the only operation whose
  evidence compaction destroyed: tombstones were dropped at fold time, so a write that was
  in flight while the namespace compacted (a slow upload, a laptop suspended mid-`set`)
  could bring a deleted key back, silently, even when the deletion was strictly newer, with
  the outcome depending on whether a cleanup happened to run in the window. Snapshots now
  retain tombstones with full provenance, so a deletion keeps winning exactly what the
  ordering rule says it wins, compaction is value-transparent again, and a late write that
  loses is reported as a conflict. The storage format version bumps to 3; 0.14 vaults are
  not readable by this build (pre-1.0, no migration path). The 0.11 notes called the
  previous payload change "deliberately the last before the freeze": that claim was wrong
  and is withdrawn, not replaced. The simulation fuzzer's oracle is now asserted in the
  compaction world too; three inputs already in its corpus trip the old behavior.

### Added

- **Session key caching on macOS (Keychain) and Windows (DPAPI).** Unlock once per session
  on every platform instead of once per command. The native stores hold the cached key as
  ciphertext under your login credentials, the same custody class machine identities
  already use; what is weaker than the Linux kernel keyring is stated in the
  [caching guide](https://dvgils.github.io/notenv/guides/caching/): the TTL is enforced
  lazily on read, and an expired entry persists encrypted until its next touch. Set
  `crypto.cache_ttl = "0"` to prompt every time. CI now runs the full test suite on macOS
  and Windows, not just cross-builds.
- **The MCP server grows up and drops its experimental label.** Four tools, none of which
  accepts or returns a secret value, none of which writes to a vault: `list_namespaces`
  (the discovery hop, no unlock needed), `list_secrets`, `run_with_secrets`, and `doctor`
  (the checkup findings as data). Results are typed (`structuredContent` with declared
  output schemas) and the read tools carry `readOnlyHint`. A golden file pins the entire
  tool surface. The headless recipe is documented: session-cached key or `NOTENV_IDENTITY`
  to unlock, `NOTENV_ACCEPT_NAMESPACE` for first use of existing namespaces.
- **An installable agent skill** at `skills/notenv/SKILL.md`: the CLI surface and the
  never-see-values rules in the Agent Skills format shell-first agents understand. A skill
  for agents with a shell, MCP for agents without one, the same surface either way.

## 0.14.0

The hardening and dailiness release. A security audit of 0.13 (no High or Medium findings)
and a sweep of the threat model's own caveats drive most of it: the gaps that were wrinkles
rather than physics get closed, and the daily loop gets its missing verb.

### Added

- **`notenv edit`: bulk editing that never displays a value.** The `$EDITOR` buffer shows
  every existing value as `<keep>`: replace it to set, delete the line to unset, add lines
  to create, edit the comment above a key to change its description. The diff lands as one
  recorded write, new keys are declared in the contract, and a key that also changed on
  another machine while the buffer was open stops the save with the key named. The buffer
  never contains stored plaintext, so it can leak at most what you typed into it; it lives
  in the RAM-backed runtime dir on Linux and is removed on exit and on signals.
- **The onboarding string now proves which vault it is for.** `key add` prints the one-time
  passphrase with a short fingerprint of the vault appended; the invited teammate's first
  contact verifies the served header against it before anything is trusted, so a
  substituted vault is refused instead of silently pinned. A legitimate re-key between the
  invite and first contact passes by proving itself through the signed rotation chain.
  Trust-on-first-use is closed for onboarded teammates.
- **`notenv doctor`.** One read-only checkup for the known problem states: a vanished or
  unreadable header, a pending rollback, a replaced vault, unfinished onboarding, objects a
  crashed write left unrecorded, recorded objects that are missing. It recommends and never
  fixes, never prompts, and exits 1 on findings so CI can run it.
- **Generated root passphrases.** `setup` accepts Enter to generate a six-word passphrase,
  printed once; typed passphrases under 12 characters draw a warning naming the offline
  brute-force attack, at creation, at `key rotate`, and during onboarding.

### Changed

- **Namespace confirmation fails closed without a terminal** (audit finding). The first use
  of a namespace that already holds secrets used to warn and proceed in CI and agent
  harnesses; a malicious repository's committed contract on a shared runner could reach
  another project's secrets that way. It now refuses unless `NOTENV_ACCEPT_NAMESPACE` names
  the exact namespace; the value is a list of names rather than a yes-flag, because a
  contract cannot write the runner's environment. Breaking for CI flows that relied on the
  warn-and-proceed behavior: add the variable to the pipeline.
- **`run --no-mask` asks for a freshly typed passphrase**, even when the session key is
  cached. Sending raw secret values to a captured stream is now a human's act: prompts read
  the terminal device, so an agent holding a warm cache cannot complete one. Strict on
  purpose: no identity satisfies it and no environment variable bypasses it.
- **rclone invocations carry an end-of-options marker** (audit hardening). The argv builder
  separates flags from paths itself, so the guarantee that no name is ever parsed as a flag
  lives at the exec boundary instead of in upstream validation.

### Documentation

- The threat model narrows its trust-on-first-use limitation (closed for onboarded
  teammates), upgrades the malicious-contract property to cover headless runners, and
  cross-references `doctor` from the known limitations. The teams, new-machine, CI, agents,
  and environment pages cover the onboarding string, `NOTENV_ACCEPT_NAMESPACE`, and the
  unmask gate.

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
