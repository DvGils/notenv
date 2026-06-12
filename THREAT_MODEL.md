# notenv threat model

This document states what notenv protects, against whom, and (just as importantly) what it
deliberately does **not** protect. It is meant to make the security assumptions legible enough to
review. It describes the design as of the current release; where reality is weaker than the ideal,
that is called out rather than glossed.

If you find a discrepancy between this document and the code, treat it as a bug in whichever is
wrong and please report it (see [Reporting](#reporting-a-vulnerability)).

## Assets

In priority order, the things notenv exists to protect:

1. **Secret values (plaintext).** The whole point. They must never be readable by the storage
   provider, never written to disk, and never exposed beyond the process that needs them.
2. **The master key.** A random X25519 key that encrypts every secret. Compromise of the master
   key compromises every secret in that vault.
3. **The unlocking credentials.** A passphrase (escrowed by the user in a password manager) or a
   teammate's age identity. These unwrap the master key.

The passphrase and age identities live **outside** notenv's storage: in the user's password
manager or on the user's machine. notenv never stores them on the backend.

## Architecture and trust boundaries

notenv is client-side-encryption-on-dumb-storage. The boundary is sharp: **everything on the
storage backend is ciphertext or key-wrapping metadata; plaintext exists only in RAM, only on the
machine running the command, only for as long as the command runs.**

- Secrets are encrypted with [age](https://github.com/FiloSottile/age) (X25519) under a random
  **master key**.
- The master key is stored once, in a **header** object, age-encrypted to one or more **key
  slots**. A slot is either a passphrase (the master is reachable via a slot keypair whose private
  key is scrypt-wrapped under the passphrase) or a teammate's age public key. This is the LUKS /
  restic pattern: changing a passphrase or adding/removing a teammate rewraps only the header, not
  the secrets.
- The header is **authenticated** with an HMAC keyed from the master, and carries a **monotonic
  revision** that each machine pins locally.
- Secret values for a namespace are stored as an **append-only set of encrypted segments** over
  periodic **snapshots**; reads fold them, last-write-wins per key. Every write is read back and
  verified before it is trusted.
- Storage is reached through [rclone](https://rclone.org); notenv treats it as a dumb object store
  and assumes nothing about its consistency or honesty beyond "stores and returns bytes."
- On Linux, the master key (kernel keyring) and ciphertext blobs (tmpfs) may be cached in RAM, both
  reclaimed by the OS on logout/reboot. macOS and Windows do **not** cache (see
  [README](./README.md#caching-is-linux-only-by-design)).

## Security properties

What holds, and against whom.

### Confidentiality of secret values

- **Against the storage provider, or anyone with read access to your storage** (a stolen read-only
  credential, a subpoenaed provider, a leaked bucket): they see ciphertext and the header only. The
  header contains no plaintext key, only the master wrapped to slots. Without a slot credential
  they cannot decrypt. ✅
- **Against a network adversary on the storage transport:** rclone uses TLS to the provider, but
  notenv does not rely on it. The payload is already ciphertext, so a broken transport still leaks
  only ciphertext. ✅
- **Against a local adversary with your disk but not a live session** (lost/stolen laptop, a
  forensic image, an old backup): no plaintext and no persistent secret cache exist on disk. On
  Linux the caches are RAM-only and gone after logout; macOS/Windows cache nothing. A disk image
  yields ciphertext, which is useless without the key (the key lives in your password manager, not
  on the disk). ✅

### Integrity

- **Against an adversary with write access to your storage but no key:** they cannot forge or
  silently alter the header (HMAC), and rolling it back to an older revision is detected on any
  machine that has already seen a newer one. **Deleting the header outright is also detected**: a
  machine that has pinned a vault refuses to treat its missing header as virgin storage (the
  deliberate-reset escape hatch is `notenv key forget`). **Replacing the vault wholesale is
  detected**: each storage location is bound locally to the vault identity it held, so a
  different vault appearing there — however internally consistent — is refused. They cannot
  forge a secret value: a blob they cannot encrypt under the master fails to decrypt, and reads
  **fail closed** (a corrupt or substituted object is surfaced as an error, never silently
  skipped). Because writes are append-only and verified on read-back, a botched or malicious
  write is at worst denial-of-service, not silent data loss. ✅ (with caveats; see
  [Known limitations](#known-limitations)).
- **Master rotations carry their own proof.** Each rotation records a transition signed by the
  outgoing master; a machine still pinned at that master verifies the chain and follows the
  change silently. The master-changed alarm therefore fires only for a change that **no holder
  of the pinned master authorized** — it is no longer the routine cost of a teammate rotating,
  which had trained the `notenv key trust` reflex that defeats the alarm's purpose. A non-holder
  cannot forge a transition (no old signing key); an **ex-holder can**, which is why offboarding
  still ends with rotating the storage credential (see
  [Known limitations](#known-limitations)). ✅
- **Against an honest race — writes concurrent with a master rotation:** every write confirms,
  after it lands, that the master it was sealed under is still the vault's master, rolling itself
  back otherwise; the rotation re-lists the namespace after its header flip and re-keys anything a
  not-yet-aware writer sealed under the old master. A write that escapes both would have to land
  after the rotation's re-list yet confirm before its flip — impossible, since the write lands
  before it confirms. So for every non-crash interleaving, no committed write ends up readable by
  nobody (the crash residual is in [Known limitations](#known-limitations)). ✅
- **Against a malicious committed contract (a cloned repository):** the contract cannot choose
  where this machine reads or writes (storage is machine-config only), and the **namespace it
  names is pinned per checkout** on first use — pinning a namespace other than the directory's
  name requires interactive confirmation, and a contract that later renames its namespace is
  refused until explicitly re-accepted (`notenv init`). A malicious clone cannot silently point
  `notenv run` at another project's secrets in your vault. ✅ (what running untrusted code does
  with its *own* pinned namespace remains out of scope; see [Non-goals](#non-goals).)

### Captured output (logs, CI, agent context)

- **Against accidental disclosure through a child's output:** `notenv run` scrubs the exact
  values it injected from the child's stdout/stderr whenever the stream is captured (not a
  terminal), replacing them with named placeholders — so a server that echoes its connection
  string on boot does not hand it to the CI log, the shell pipeline, or the LLM reading the
  tool output. Best-effort by construction: exact byte matching (an encoded or transformed
  value passes through), values shorter than 6 bytes are skipped, and a live terminal is wired
  through untouched unless `--mask` is given. This is **accident-proofing for the dominant
  real-world leak, not a boundary** — see [Non-goals](#non-goals). ✅ (qualified)

### No-residue

- When a `notenv run` exits, the plaintext (which lived only in the child process's environment) is
  gone, and on Linux the RAM caches are reclaimed on logout. "The process exits and nothing secret
  is left behind to discover later" is a real property, and is the reason caching is refused on
  platforms that cannot guarantee it. ✅

## Adversaries and outcomes (summary)

| Adversary | Confidentiality | Integrity | Notes |
|---|---|---|---|
| Storage provider / read-only credential | Holds (ciphertext only) | n/a | Metadata leaks (below) |
| Network MITM on storage | Holds | Holds | Payload is ciphertext regardless of TLS |
| Storage **write** credential, no key | Holds | Holds, with caveats | Can DoS / fork history; detected, not prevented |
| Former key holder (had the master) | **Lost for past secrets** | n/a | Rotate master + storage credential to limit future |
| Local attacker, no live session | Holds | Holds | Nothing secret on disk |
| Local attacker **with** live session + cached key | **Lost** | n/a | Out of scope (see below) |
| Captured child output (logs, agent context) | Holds for accidents (masked, best-effort) | n/a | Deliberate extraction out of scope |
| Malicious notenv build / supply chain | n/a | n/a | Mitigated by reproducible + signed releases |

## Non-goals

notenv does **not** defend these, by design. Treating them as in-scope would be misleading.

- **Metadata.** Anyone with read access to your storage learns which namespaces exist, roughly how
  many secrets each holds and their sizes, and when writes happened (object names, counts, sizes,
  timestamps). Only the *values* are confidential.
- **A compromised live machine that holds the key.** An attacker with your running session and your
  cached/unlocked key can decrypt. notenv shrinks the window (no `.env` files; plaintext only in the
  child's environment for its lifetime) but cannot defend a fully compromised host.
- **Code you choose to run under `notenv run`.** The child process receives the pinned namespace's
  secrets; that is the product. Namespace pinning stops a malicious repository from *silently*
  reaching another project's secrets, not from misusing the secrets you knowingly hand it.
- **Deliberate extraction by anything running as your user.** An agent (or any code) with your
  UID can run `notenv run -- printenv KEY` or read the session key cache; output masking catches
  accidents, not intent. The same trust model as ssh-agent. A broker that holds the unlocked key
  in a separate trust domain — agents *use*, provably cannot *extract* — is planned, and until it
  exists notenv makes no agent-containment claim.
- **Exfiltration by a process legitimately holding a secret.** A child handed `$KEY` can send it
  anywhere it has network access to. No secrets manager fixes egress; that is sandbox and
  network-policy territory.
- **Storage availability.** An adversary with write/delete access can delete or corrupt objects.
  This is denial-of-service, not a confidentiality break; object versioning (default on Backblaze
  B2) recovers prior bytes, but notenv does not guarantee availability.
- **A weak passphrase.** Someone with read access to your storage can attempt an offline brute-force
  against the scrypt-wrapped passphrase slot. scrypt raises the cost, but a weak passphrase is the
  weak link. The passphrase is the root of trust; use a strong one.
- **The passphrase / identity files themselves.** Protecting your password manager and any on-disk
  age identity (`NOTENV_IDENTITY`) is the user's responsibility.
- **Traffic analysis / timing side channels** beyond the metadata noted above.
- **Revoking access to secrets a person has already seen.** Cryptography cannot un-share a value
  someone already decrypted. Offboarding (`notenv key rm` + master rotation) prevents decrypting
  *future* values; rotate the underlying secret if a person should lose access to its current value.

## Known limitations

These are real, documented gaps, not oversights:

- **Trust on first use.** On a machine's *first* contact with a vault it has no prior revision to
  compare against, so it cannot detect a rollback or substitution that predates its first sight.
- **Warm-cache runs defer the pin checks.** With the master key cached, a run never reads the
  header, so rollback / master-change / vanished-header detection happens on cold unlocks — at
  most one cache TTL (default 1 hour) after the event, not instantly. Writes are unaffected: they
  re-read the header after every write regardless.
- **A write-capable former holder can fork history — and signed transitions make the fork
  *quiet* for machines behind the fork point.** Someone who kept a previous master had full
  authority while they held it, including its signing key: they can author transitions onto
  their own fork that verify exactly like legitimate ones. A machine whose pin predates the fork
  follows it silently; a machine pinned past the fork (the owner's, after the rotation that
  removed the ex-holder) finds no signed path and alarms. This is the fundamental limit of any
  scheme on dumb storage and the reason offboarding ends with rotating the **storage
  credential**: no write access, no fork. notenv advises this on `key rm` but, not owning the
  storage, cannot enforce it.
- **A crash inside a rotation's flip→narrow window.** If `rotate-master` crashes after its header
  flip but before the narrow pass completes, a write that landed during the widen window can be
  left sealed under the replaced master. The fold then fails closed naming the object; re-set that
  key (or recover the object's prior version on a versioned remote). The window is seconds wide
  and requires the crash inside it. This residual is accepted deliberately: the alternative — a
  rotation-in-progress marker writers must honor — puts a lock-like object on every write path
  and adds a stuck-marker failure mode that blocks all writers until manually cleared.
- **Primary-slot governance is advisory.** In shared-master team mode every slot holder has the
  master key, so "who may remove slots" is tooling-enforced, not cryptographic.
- **Tombstone garbage collection.** Compaction drops delete-tombstones; a stale concurrent write at
  an equal/lower logical clock can resurrect a deleted key that the tombstone would otherwise have
  shadowed. (Reachable only once `notenv unset` is in use; a "defer GC by one generation" mitigation
  is planned.)
- **Eventual-consistency reads.** On a storage backend with weak listing consistency, a fold can
  briefly read a stale value just after a compaction (never a lost write). Strongly-consistent
  remotes (Backblaze B2, S3) are unaffected.

## Supply chain

Releases are built reproducibly with GoReleaser, signed with [cosign](https://github.com/sigstore/cosign)
(keyless), and carry SLSA build provenance; the [README](./README.md#install) shows how to verify a
download. The client-side-crypto core is intentionally small and auditable: the tool never needs to
be trusted with anything at rest.

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/DvGils/notenv/security/advisories/new) rather
than a public issue. See [SECURITY.md](./SECURITY.md).
