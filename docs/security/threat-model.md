# Threat model

This page states what notenv protects, against whom, and (just as importantly) what it deliberately
does **not** protect. It is meant to make the security assumptions legible enough to review. It
describes the design as of the current release; where reality is weaker than the ideal, that is called
out rather than glossed.

If you find a discrepancy between this document and the code, treat it as a bug in whichever is wrong
and please [report it](reporting.md).

## Assets

In priority order, the things notenv exists to protect:

1. **Secret values (plaintext).** The whole point. They must never be readable by the storage
   provider, never written to disk, and never exposed beyond the process that needs them.
2. **The master key.** A random X25519 key that encrypts every secret. Compromise of the master key
   compromises every secret in that vault.
3. **The unlocking credentials.** A person's passphrase (escrowed in their password manager) or a
   machine's age identity (provisioned through a platform secret store). These unwrap the master
   key.

The credentials live **outside** notenv's storage and outside notenv's files entirely: a passphrase
in a person's head and password manager, an identity in the secret store that presents it via
`NOTENV_IDENTITY`. notenv never stores a credential on the backend or on disk (see
[Credentials at rest](#credentials-at-rest-passphrases-for-people-identities-for-machines)).

## Architecture and trust boundaries

notenv is client-side-encryption-on-dumb-storage. The boundary is sharp: **everything on the storage
backend is ciphertext or key-wrapping metadata; plaintext exists only in RAM, only on the machine
running the command, only for as long as the command runs.**

- Secrets are encrypted with [age](https://github.com/FiloSottile/age) (X25519) under a random
  **master key**.
- The master key is stored once, in a **header** object, age-encrypted to one or more **key slots**. A
  slot is either a person's passphrase (the master is reachable via a slot keypair whose private key
  is scrypt-wrapped under the passphrase) or a machine's age public key. This is the LUKS / restic
  pattern: changing a passphrase or adding/removing a slot rewraps only the header, not the
  secrets.
- The header is **authenticated** with an HMAC keyed from the master, and carries a **monotonic
  revision** that each machine pins locally.
- Secret values for a namespace are stored as an **append-only set of encrypted segments** over
  periodic **snapshots**; reads fold them, last-write-wins per key. Every write is read back and
  verified before it is trusted.
- Storage is a local vault directory (pure-Go backend) or a remote reached through
  [rclone](https://rclone.org); notenv treats both as a dumb object store and assumes nothing about
  consistency or honesty beyond "stores and returns bytes." A **local vault changes none of the
  confidentiality story**: it is the same ciphertext that would sit on a provider, on a strictly
  less-exposed medium, and the lost-laptop case below covers ciphertext at rest. What changes is
  durability and recovery (no off-device copy and no object versioning), so back the directory up, or
  replicate it to a remote with `notenv vault copy`. Local vaults are single-machine by design: their
  header writes get a true compare-and-swap (an OS file lock), which is cooperative and same-machine
  only.
- The master key is cached for the session so a passphrase is asked at most once: in the kernel
  keyring on Linux (RAM only, reclaimed on logout/reboot), in the Keychain on macOS and DPAPI on
  Windows (ciphertext at rest under your login credentials, purged lazily on the next read).
  Ciphertext blobs are additionally cached in RAM (tmpfs) on Linux only. See
  [Caching and performance](../guides/caching.md#what-each-platform-guarantees).

## Credentials at rest: passphrases for people, identities for machines

A vault **concentrates risk by design**: scattered `.env` files leak one project at a time, while a
vault credential opens every secret in every namespace, including projects the machine never
checked out. Concentration is only a win if the credential is harder to steal than the files were,
so notenv holds every unlock path to one bar: **no file at rest may be key-equivalent.** Every
promptless path must be rooted in something a filesystem sweep (the smash-and-grab infostealer, the
copied backup, the imaged disk) cannot take.

How each path meets the bar:

| Path | Where the credential lives | What a filesystem sweep gets |
|---|---|---|
| Passphrase slot | A person's head and password manager; scrypt-stretched on every unlock | Nothing |
| Session cache (Linux) | Kernel memory, TTL-bounded, never disk | Nothing |
| Machine identity | The platform's secret store, injected per run via `NOTENV_IDENTITY` | Nothing notenv put there |
| One-time onboarding passphrase | In transit between owner and teammate, minutes, then dead | Nothing (it is not stored) |

notenv deliberately owns **no identity file**: there is no notenv path for a stealer list to name.
A machine identity is key-equivalent by nature, which is exactly why its at-rest custody is
delegated to the secret store that already guards your deploy keys, and why humans never hold one.

Two honest residuals of concentration:

- **The offline brute-force surface.** Anyone who exfiltrates the header and ciphertext can attack
  a passphrase slot offline, a surface scattered `.env` files never offered. scrypt raises the
  cost; the strength of the passphrase carries the rest (see [Non-goals](#non-goals)). Generated
  one-time onboarding passphrases are high-entropy for the same reason.
- **The onboarding window.** A teammate's slot starts under a generated one-time passphrase that
  the owner, and any channel it crossed, briefly knows. An interceptor needs that passphrase
  **and** storage read access **during the window before the holder's first command replaces it**
  (notenv refuses to proceed for them until they do, and `key list` shows the slot as provisional
  until then). A suspected interception is remedied by `key rotate-master`: anything captured stops
  decrypting anything written after.

## Security properties

What holds, and against whom.

### Confidentiality of secret values

- **Against the storage provider, or anyone with read access to your storage** (a stolen read-only
  credential, a subpoenaed provider, a leaked bucket): they see ciphertext and the header only. The
  header contains no plaintext key, only the master wrapped to slots. Without a slot credential they
  cannot decrypt. :white_check_mark:
- **Against a network adversary on the storage transport:** rclone uses TLS to the provider, but notenv
  does not rely on it. The payload is already ciphertext, so a broken transport still leaks only
  ciphertext. :white_check_mark:
- **Against a local adversary with your disk but not a live session** (lost/stolen laptop, a forensic
  image, an old backup): no plaintext exists on disk. On Linux the caches are RAM-only and gone after
  logout; on macOS and Windows the only at-rest cache is the master key held as ciphertext in the
  platform store, encrypted under your login credentials, so a powered-off image cannot open it.
  Either way a disk image yields ciphertext, which is useless without the key (the key lives in your
  password manager, not on the disk). :white_check_mark:

### Integrity

- **Against an adversary with write access to your storage but no key:** they cannot forge or silently
  alter the header (HMAC), and rolling it back to an older revision is detected on any machine that has
  already seen a newer one. **Deleting the header outright is also detected**: a machine that has
  pinned a vault refuses to treat its missing header as virgin storage (the deliberate-reset escape
  hatch is `notenv key forget`). **Replacing the vault wholesale is detected**: each storage location
  is bound locally to the vault identity it held, so a different vault appearing there, however
  internally consistent, is refused. **Every stored object is bound to that authenticated header**: the
  header carries a manifest (object key to keyed MAC of its plaintext; keyed so the public header is no
  guessing oracle against secret values), each payload names the object key it was written under, and
  reads check both, so deleting a recorded object, reverting it to a different value, resurrecting a
  compacted one, or copying a real object to another name or namespace alarms with the object named.
  They cannot forge a secret value: a blob they cannot encrypt under the master fails to decrypt, and
  reads **fail closed**. Because writes are append-only and verified on read-back, a botched or
  malicious write is at worst denial-of-service, not silent data loss. :white_check_mark: (with
  caveats; see [Known limitations](#known-limitations)).
- **Master rotations carry their own proof.** Each rotation records a transition signed by the outgoing
  master; a machine still pinned at that master verifies the chain and follows the change silently. The
  master-changed alarm therefore fires only for a change that **no holder of the pinned master
  authorized**: it is no longer the routine cost of a teammate rotating, which had trained the
  `notenv key trust` reflex that defeats the alarm's purpose. A non-holder cannot forge a transition
  (no old signing key); an **ex-holder can**, which is why offboarding still ends with rotating the
  storage credential (see [Known limitations](#known-limitations)). :white_check_mark:
- **Against an honest race, writes concurrent with a master rotation:** every write records itself in
  the vault manifest through the header compare-and-swap, which re-reads and verifies the header first:
  a rotation that landed since the writer unlocked surfaces right there, and the writer rolls its object
  back. The rotation's flip goes through the same swap, so it aborts if any write recorded itself after
  the rotation began. For every non-crash interleaving, no committed write ends up readable by nobody.
  :white_check_mark:
- **Against a malicious committed contract (a cloned repository):** the contract cannot choose where
  this machine reads or writes (storage is machine-config only), and the **namespace it names is pinned
  per checkout** on first use: pinning a namespace other than the directory's name, or joining one that
  already holds secrets, requires interactive confirmation, and where nobody can answer (CI, agent
  harnesses) notenv **refuses** unless the runner's own environment names that exact namespace
  (`NOTENV_ACCEPT_NAMESPACE`; a committed contract cannot write the runner's environment). A contract
  that later renames its namespace is refused until explicitly re-accepted (`notenv init`). A malicious
  clone cannot silently point `notenv run` at another project's secrets in your vault, interactively or
  headless. :white_check_mark:

### Captured output (logs, CI, agent context)

- **Against accidental disclosure through a child's output:** `notenv run` scrubs the exact values it
  injected from the child's stdout/stderr whenever the stream is captured (not a terminal), replacing
  them with named placeholders, so a server that echoes its connection string on boot does not hand it
  to the CI log, the shell pipeline, or the LLM reading the tool output. Best-effort by construction:
  the value and its common encodings (base64, hex, percent) are matched, but a value transformed in a
  way notenv does not anticipate (compressed, reversed, encrypted, double-encoded) or embedded in a
  larger blob before encoding passes through, values shorter than 6 bytes are skipped, and a live
  terminal is wired through untouched unless `--mask` is given. This is
  **accident-proofing for the dominant real-world leak, not a boundary**. Turning masking off for a
  captured stream (`--no-mask`) requires a freshly typed passphrase even when the session key is
  cached, so it is a human's act, never an agent's; the same gate will guard any future command that
  prints stored values. See [Non-goals](#non-goals). :white_check_mark: (qualified)
- The experimental MCP server (`notenv mcp`) keeps the same line: its tools list names and descriptions
  or run commands with secrets injected, always masking the captured output: no tool returns a secret
  value to the model. The same qualification applies. :white_check_mark: (qualified)

### No-residue

- When a `notenv run` exits, the plaintext (which lived only in the child process's environment) is
  gone. On Linux the RAM caches are reclaimed on logout; on macOS and Windows the cached master key
  is ciphertext in the platform store under the user's login credentials, expiring lazily on its
  next read rather than at the deadline (see
  [Caching](../guides/caching.md#what-each-platform-guarantees)). "The process exits and no
  plaintext is left behind to discover later" holds on every platform; "nothing at all is left
  behind" is the Linux-only stronger form. :white_check_mark: (qualified on macOS/Windows)

## Adversaries and outcomes (summary)

| Adversary | Confidentiality | Integrity | Notes |
|---|---|---|---|
| Storage provider / read-only credential | Holds (ciphertext only) | n/a | Metadata leaks (below) |
| Network MITM on storage | Holds | Holds | Payload is ciphertext regardless of TLS |
| Storage **write** credential, no key | Holds | Holds | Object tamper alarms via the header manifest; DoS and wholesale history forks detected, not prevented |
| Former key holder (had the master) | **Lost for past secrets** | n/a | Rotate master + storage credential to limit future |
| Local attacker, no live session | Holds | Holds | Nothing secret on disk |
| Local attacker **with** live session + cached key | **Lost** | n/a | Out of scope (see below) |
| Captured child output (logs, agent context) | Holds for accidents (masked, best-effort) | n/a | Deliberate extraction out of scope |
| Malicious notenv build / supply chain | n/a | n/a | Mitigated by reproducible + signed releases |

## Non-goals

notenv does **not** defend these, by design. Treating them as in-scope would be misleading.

- **Metadata.** Anyone with read access to your storage learns which namespaces exist, roughly how many
  secrets each holds and their sizes, and when writes happened. Only the *values* are confidential.
- **A compromised live machine that holds the key.** An attacker with your running session and your
  cached/unlocked key can decrypt. notenv shrinks the window (no `.env` files; plaintext only in the
  child's environment for its lifetime) but cannot defend a fully compromised host.
- **Code you choose to run under `notenv run`.** The child process receives the pinned namespace's
  secrets; that is the product. Namespace pinning stops a malicious repository from *silently* reaching
  another project's secrets, not from misusing the secrets you knowingly hand it.
- **Deliberate extraction by anything running as your user.** An agent (or any code) with your UID can
  run `notenv run -- sh -c 'printenv KEY | rev'` (masking covers the value and its common encodings,
  but a transform it does not anticipate walks around it) or read the session key cache; output masking
  catches accidents, not intent. The
  same trust model as ssh-agent. A broker that holds the unlocked key in a separate trust domain
  (agents *use*, provably cannot *extract*) is planned, and until it exists notenv makes no
  agent-containment claim.
- **Read-only mode as containment.** `read_only = true` and `NOTENV_READONLY` make notenv refuse
  mutating commands: accident-proofing for cooperating clients, same family as masking. They do not
  constrain an adversary: with a single master key, **read capability is write capability** (the
  manifest MACs that authenticate objects derive from the master), so anyone who can decrypt can author
  valid writes with their own tooling. *Enforced* read-only comes from the storage credential.
  Cryptographic read-only identities require splitting decrypt from manifest-signing: a header
  redesign, explicitly v2 territory.
- **Exfiltration by a process legitimately holding a secret.** A child handed `$KEY` can send it
  anywhere it has network access to. No secrets manager fixes egress; that is sandbox and
  network-policy territory.
- **Storage availability.** An adversary with write/delete access can delete or corrupt objects. This
  is denial-of-service, not a confidentiality break; object versioning (default on Backblaze B2)
  recovers prior bytes, but notenv does not guarantee availability.
- **A weak passphrase.** Someone with read access to your storage can attempt an offline brute-force
  against the scrypt-wrapped passphrase slot. scrypt raises the cost, but a weak passphrase is the weak
  link. The passphrase is the root of trust; notenv offers to generate a strong one at creation (and
  always generates the onboarding ones), and warns about short choices, but cannot stop a determined
  weak choice.
- **The credential stores themselves.** Protecting your password manager, and the platform secret
  store that holds a machine's identity, is outside notenv. notenv's contribution is structural: it
  never writes a credential to disk, so there is no notenv-owned artifact to protect (see
  [Credentials at rest](#credentials-at-rest-passphrases-for-people-identities-for-machines)).
- **Traffic analysis / timing side channels** beyond the metadata noted above.
- **Revoking access to secrets a person has already seen.** Cryptography cannot un-share a value someone
  already decrypted. Offboarding (`notenv key rm` + master rotation) prevents decrypting *future*
  values; rotate the underlying secret if a person should lose access to its current value.

## Known limitations

These are real, documented gaps, not oversights. `notenv doctor` checks a storage for the
recoverable states described here and below and names the way out of each:

- **Trust on first use, narrowed.** On a machine's *first* contact with a vault it has no prior
  revision to compare against, so it cannot detect a rollback or substitution that predates its
  first sight. For **onboarded teammates this is closed**: the onboarding string carries a
  fingerprint of the vault's identity and signing key, the first contact verifies the served
  header against it before anything is pinned, and a re-key between invite and first contact
  proves itself through the signed rotation chain. Defeating it requires the vault's master key
  (or grinding a 60-bit digest collision) *in addition to* the intercepted one-time passphrase.
  TOFU remains for the vault creator's own machines and for identity-enrolled machines, whose
  operator provisioned the storage deliberately.
- **Warm-cache runs defer the pin checks.** With the master key cached, a run never reads the header, so
  rollback / master-change / vanished-header detection happens on cold unlocks, at most one cache TTL
  (default 1 hour) after the event, not instantly. Writes are unaffected: they re-read the header after
  every write regardless.
- **A write-capable former holder can fork history, and signed transitions make the fork *quiet* for
  machines behind the fork point.** Someone who kept a previous master had full authority while they
  held it, including its signing key: they can author transitions onto their own fork that verify
  exactly like legitimate ones. A machine whose pin predates the fork follows it silently; a machine
  pinned past the fork finds no signed path and alarms. This is the fundamental limit of any scheme on
  dumb storage and the reason offboarding ends with rotating the **storage credential**: no write
  access, no fork. notenv advises this on `key rm` but, not owning the storage, cannot enforce it.
- **A write that crashed mid-protocol and was then orphaned by a rotation.** A `set` lands its object,
  then records it in the vault manifest; a writer that dies between the two leaves an unrecorded object.
  Folds still include it (with a warning) and the next compaction records it durably, but a master
  rotation deliberately leaves unrecorded objects alone, so an orphan that meets a rotation first is
  left sealed under the replaced master. The fold then fails closed naming the object; remove it and
  re-set that key.
- **The manifest swap on rclone is a windowed compare-and-swap, not an atomic one.** Object stores
  expose no conditional write through rclone, so two machines recording writes in the same sub-second
  window can race. A detected loss retries cleanly; the one undetectable ordering leaves an
  unrecorded-but-still-included object that the next compaction adopts, never a lost value, never an
  alarm against an honest writer. A backend with native conditional writes can close the window for
  real.
- **Primary-slot governance is advisory.** In shared-master team mode every slot holder has the master
  key, so "who may remove slots" is tooling-enforced, not cryptographic.
- **Eventual-consistency reads.** On a storage backend with weak listing consistency, a fold can briefly
  read a stale value just after a compaction (never a lost write). Strongly-consistent remotes
  (Backblaze B2, S3) are unaffected.

## Supply chain

Releases are built reproducibly with GoReleaser, signed with
[cosign](https://github.com/sigstore/cosign) (keyless), and carry SLSA build provenance; the
[installation page](../getting-started/installation.md) shows how to verify a download. The release
pipeline is pinned to match: every GitHub Action it runs is fixed to an immutable commit SHA, the
GoReleaser build is pinned to an exact release, and publishing is gated on a protected environment, so
a pushed tag cannot ship a release on its own. The
client-side-crypto core is intentionally small and auditable: the tool never needs to be trusted with
anything at rest.

## Reporting

Found a discrepancy or a vulnerability? See [Reporting a vulnerability](reporting.md).
