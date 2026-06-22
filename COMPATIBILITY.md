# Compatibility

This is notenv's promise about what stays stable across versions, and what may
change. It exists because a secrets tool is only trustworthy if upgrading it cannot
lose your data or quietly break your scripts.

## The promise, from 1.0 to 2.0

From 1.0 until a future 2.0, notenv is trusted not to break. A vault written by
any 1.x release is readable and writable by any other 1.x release, in either
direction, indefinitely. Scripts and integrations built against the 1.x interface
keep working. The three tiers below say exactly what that covers and where the line
is, because the guarantees differ by tier on purpose.

## Why storage is the strict tier: mixed-version fleets

A single vault is shared by machines that upgrade independently. A 1.0 laptop and a
1.3 CI runner read and write the same storage. This is stricter than an ordinary
"no breaking changes" promise, and it rules out even additive format changes:

Go's JSON decoding silently drops fields it does not recognize. So if a newer
machine wrote a blob carrying a new optional field, an older machine that later
rewrote that namespace (a compaction, an unrelated edit) would drop the field
without warning, destroying data an honest party was trusting notenv to keep. There
is therefore no "additive field" escape hatch on storage. notenv enforces this with
an exact-match version check: a blob or header whose format version is not exactly
the one this build understands is refused, in both directions, rather than parsed
best-effort.

The consequence is stark and deliberate: **any change to the storage format is a 2.0
change, never a 1.x one.**

## The three tiers

| Tier | Promise from 1.0 to 2.0 |
|---|---|
| **Storage** | **Frozen, bit-for-bit.** A 1.0 machine and any 1.x machine interoperate on one vault forever. |
| **Interface** | **Stable and additively extensible.** New commands, flags, and output fields may appear; nothing that exists changes meaning or disappears. |
| **Local state** | **Fungible.** Per-machine files may be migrated in place; the only promise is that an upgrade never loses your pins or trust state. |

### Storage: frozen bit-for-bit

Locked at 1.0 and unchanged until 2.0:

- The key header (format v6) and its fields: the cipher suite tag, vault id,
  signing key, revision counter, encrypted master, key slots, manifest, and rotation
  transitions.
- The single encrypted blob per namespace and its payload (blob format v3): each
  secret's value, description, timestamp, and author, the per-namespace metadata,
  and the reserved sensitivity and egress fields, with values and descriptions
  base64-encoded so any byte sequence round-trips intact.
- The manifest entry that binds each namespace to its blob (the blob pointer and its
  MAC, plus the one-generation backup pointer and MAC).
- Object naming and on-storage layout (`.header.json`, its `.prev` backup, the write
  lock, the connectivity probe, staged temp files, and the per-namespace
  `data-<random>.age` blobs).
- The cipher suite `x25519-hmacsha256-ed25519`: age over X25519 for encryption,
  scrypt for the passphrase, HKDF-SHA256 for key derivation, HMAC-SHA256 for the
  header and manifest, and Ed25519 for rotation signatures.
- The onboarding-fingerprint construction used to close trust-on-first-use.

### Interface: stable, additively extensible

These keep their names and meaning. New ones may be added; existing ones never
change behavior or vanish:

- Command names and semantics, flags, and exit codes. The `run` and `handoff` paths
  follow the docker convention (125 for notenv's own failure, 126 for a command
  found but not runnable, 127 for not found, otherwise the child's own exit code);
  `secret inspect` exits 1 for a missing key and `doctor` exits 1 when it has
  findings.
- Every `--json` output shape: `secret inspect`, `namespace inspect`, `vault
  inspect`, `credential inspect`, `handoff inspect`, `namespace export`, `vault
  export`, and `doctor`. Fields may be added; existing fields keep their name and
  meaning.
- The three config-file schemas: `notenv.toml` (the committed per-project contract),
  `config.toml` (the user's global config), and `notenv.local.toml` (the local,
  git-ignored binding).
- The environment variables `NOTENV_IDENTITY`, `NOTENV_READONLY`,
  `NOTENV_ACCEPT_NAMESPACE`, `NOTENV_STORAGE`, and `NOTENV_SESSION`, and the
  `NOTENV_STORAGE` grammar (`name`, `local:<abs-path>`, or `rclone:<remote>:<base>`,
  split on the first colon, which is why a configured storage name never contains a
  colon).
- Security semantics: pin and trust-on-first-use behavior, the masking policy, and
  the anti-rollback epoch guarantees.

### Local state: fungible

Per-machine files (the trust pins, the machine identity, the cache layout) may be
moved or migrated in place by any upgrade. The only promise is that an upgrade never
loses your pins or trust state, so notenv never silently re-trusts a vault you had
already verified.

## Not covered

Human-facing text is never part of the contract: prompt and message wording, warning
and error phrasing, spinner and progress labels, help text, and the exact layout of
non-`--json` output. These may improve in any release.

## Crypto can improve without a storage break

Freezing the storage format freezes the format *mechanism*, not the *set* of
algorithms. The cipher suite is named by an identifier stored in the header, that
identifier is covered by the master-keyed authentication tag (so a downgrade attempt
needs the master), and an unrecognized identifier is refused rather than parsed
best-effort. A future 2.0 can add a new vetted suite (for example a
post-quantum-hybrid recipient) alongside the current one without breaking the format,
and only ever additively and under a stated compatibility contract. Reading any vault
written under a suite a build knows remains supported.
