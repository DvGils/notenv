# Threat model

notenv protects secrets with client-side encryption on storage it treats as dumb.
This page is the full account of what that defends and what it does not. It is
ordered for progressive disclosure: the short version and "what applies to you"
cover almost everyone; the rest is depth for reviewers and complex setups. For how
the encryption, header, and storage actually work, see
[How it works](../concepts/how-it-works.md).

If this document and the code disagree, treat it as a bug in whichever is wrong and
please [report it](reporting.md).

## The short version

Your secrets are encrypted on your machine with a key only you hold, derived from
your passphrase. Storage (a local folder or a cloud remote) only ever sees
ciphertext. Plaintext is never written to disk; it exists only inside the process
you run, only while it runs.

For a solo developer or a small team, that leaves two risks worth your attention:

1. **A weak passphrase.** It is the root of trust. Anyone who copies your storage
   can guess at it offline, so make it strong (notenv offers to generate one).
2. **Losing your key.** The passphrase lives in your password manager, not on the
   storage; lose it and the secrets are not recoverable, by design.

Everything below is detail. Almost all of the edge cases apply only to several
machines writing a shared remote at once; a solo developer on one machine meets
none of them.

## What applies to you

notenv's risk surface scales with how you use it. Find your row.

### A solo developer, one machine

A small envelope: a strong passphrase, and a backup of the vault so a dead disk
does not lose it. There is no concurrency to race, no second machine to reconcile,
no machine credential to leak. The properties below hold; the edge cases at the
end do not arise.

### A small team, or several machines on a shared remote

Add three things:

- **Use a read-after-write-consistent remote.** Every major provider (Backblaze
  B2, S3, and the like) is one. Concurrent writers rely on it to serialize safely.
- **Offboarding ends at the storage credential.** `notenv key rm` re-keys the vault
  so a removed teammate cannot read new writes, but someone who kept both the old
  key and *write* access to the storage could still fork its history. Rotate the
  storage credential at your provider to close that; notenv reminds you but cannot
  do it for you.
- **A machine's first contact with a vault is trust-on-first-use; a collaborator's
  is not.** `key add <name>` prints an onboarding string (a one-time passphrase plus
  a vault fingerprint) that verifies the served vault on first contact, so onboarding
  a teammate is not trust-on-first-use. A machine unlocking by `NOTENV_IDENTITY`
  carries no such fingerprint, so its first contact has nothing to verify against.

### Running agents (or any code you hand secrets to)

- `notenv run` lets a process **use** a secret without the value entering what an
  agent reads, and captured output is masked. This is accident-proofing, not a
  cage: code running as your user can still extract a value on purpose (see
  [Non-goals](#non-goals)).
- **Read equals write.** With a single master key, anyone who can decrypt can also
  author valid writes, so `read_only` is a guardrail for cooperating clients;
  *enforced* read-only is a read-only storage credential.

## What notenv assumes

The operating envelope, stated as requirements rather than scattered caveats. When
these hold, the properties in the next section hold.

- **Your passphrase is strong** and your password manager keeps it. It is the root
  of trust; notenv cannot defend a guessable one.
- **You do not lose your only credential.** There is no recovery backdoor, by
  design.
- **The machine running notenv is yours.** A live host with your unlocked key can
  decrypt; notenv shrinks the exposure but cannot defend a compromised machine.
- **Concurrent writers share a read-after-write-consistent remote.** Single-machine
  use and the local backend need nothing here.
- **Real revocation and real read-only come from the storage credential,** which
  notenv does not own. Its own re-key and `read_only` are the cooperating-client
  half.

## What it protects

Three assets, in priority: the secret values, the master key that encrypts them,
and the credentials that unwrap it. What holds, and against whom:

### Confidentiality of secret values

- **Against the storage provider or anyone who can read your storage** (a leaked
  bucket, a stolen read-only credential, a subpoena): they get ciphertext and a
  header that wraps the key to slots, never a plaintext key. :white_check_mark:
- **Against a network adversary:** the payload is already ciphertext, so notenv
  does not depend on the transport's TLS. :white_check_mark:
- **Against a lost or stolen disk with no live session:** no plaintext is on disk.
  On Linux the caches are RAM-only; on macOS and Windows the only at-rest cache is
  the master key, held as ciphertext under your login credentials. A powered-off
  image yields ciphertext, useless without the key in your password manager.
  :white_check_mark:

### Integrity

- **Against someone who can write your storage but holds no key:** they cannot
  forge or silently alter the authenticated header, roll it back to an older
  revision, delete it, or swap in a different vault without detection. Every stored
  blob is bound to the header by a keyed MAC, so deleting, reverting, replaying, or
  copying a blob into another namespace alarms with the blob named, and reads
  **fail closed** on anything they cannot verify. They cannot forge a value (it
  would not decrypt under the master). A bad write is at worst denial-of-service,
  recoverable from the one-generation backup, never silent data loss.
  :white_check_mark:
- **Master re-keys prove themselves.** Each rotation is signed by the outgoing
  master, so other machines follow a legitimate re-key silently and only an
  *unauthorized* master change raises the alarm worth a human's attention. (An
  ex-holder can still sign a fork; see offboarding above.) :white_check_mark:
- **Against a malicious cloned repository:** a committed `notenv.toml` cannot pick
  your storage (that is machine-local), and the namespace it names is pinned on
  first use, so a clone cannot silently point `notenv run` at another project's
  secrets. Headless, an unrecognized namespace is refused unless the runner's own
  environment names it. :white_check_mark:

### Captured output

- `notenv run` masks the values it injected out of captured stdout/stderr (a pipe,
  a file, an agent's context), so a process that prints its connection string does
  not leak it into a log or a model's context. It is **accident-proofing, not a
  boundary**: it matches the value and its common encodings, but a transform it
  does not anticipate walks around it, and values under 6 bytes pass through.
  Turning it off for a captured stream (`--no-mask`) takes a freshly typed
  passphrase, so it is a human's act. :white_check_mark: (qualified)

### No residue

- When a `notenv run` exits, the plaintext (which lived only in the child's
  environment) is gone. On Linux the RAM caches clear on logout; on macOS and
  Windows the cached master key is ciphertext under your login, expiring lazily.
  "Nothing is left to discover later" holds everywhere; "nothing at all is cached"
  is the Linux-only stronger form. :white_check_mark: (qualified on macOS/Windows)

## Credentials: people hold passphrases, machines hold identities

A vault concentrates risk on purpose: one credential opens every namespace, where
scattered `.env` files leaked one project at a time. That trade is worth it only if
the credential is harder to steal than the files were, so notenv keeps **no
key-equivalent file at rest**. A passphrase lives in a person's head and password
manager (scrypt-stretched on every unlock); a machine identity lives in the
platform secret store and is presented per run via `NOTENV_IDENTITY`. An
infostealer, a copied backup, or an imaged disk finds nothing notenv put there.

Two residuals come with concentration: the **offline brute-force** surface against
a passphrase slot (why passphrase strength matters), and the brief **onboarding
window** where a teammate's one-time passphrase is in transit (the slot stays
provisional and refuses to proceed until they replace it; a suspected interception
is cured by `key rotate-master`).

## Adversaries at a glance

| Adversary | Confidentiality | Integrity | Notes |
|---|---|---|---|
| Storage provider / read access | Holds (ciphertext only) | n/a | Metadata is visible (a non-goal) |
| Network MITM | Holds | Holds | Payload is ciphertext regardless |
| Storage **write** access, no key | Holds | Holds | Tamper alarms; DoS and history forks detected, not prevented |
| Former key holder | **Lost for past secrets** | n/a | Re-key + rotate the storage credential |
| Lost disk, no live session | Holds | Holds | Nothing secret on disk |
| Live machine + cached key | **Lost** | n/a | A compromised host is a non-goal |
| Captured child output | Holds for accidents | n/a | Deliberate extraction is a non-goal |
| Malicious build / supply chain | n/a | n/a | Reproducible, signed releases |

## Non-goals

notenv does not defend these, by design. Calling them out keeps the line honest.

- **Metadata.** Read access reveals which namespaces exist, roughly how many
  secrets and their sizes, and when writes happened. Only values are confidential.
- **A compromised live machine** that holds your unlocked key.
- **Code you choose to run.** `notenv run` hands the child the namespace's secrets;
  that is the product. Pinning stops a *silent* cross-project reach, not misuse of
  what you knowingly hand over.
- **Deliberate extraction by code running as you.** An agent can `printenv KEY |
  rev` around the masker or read the session cache; masking catches accidents, not
  intent (the ssh-agent trust model). A first step shipped: `NOTENV_IDENTITY` is
  stripped from child environments. A broker that lets agents *use* but not
  *extract* the key is planned; until it exists, notenv makes no agent-containment
  claim.
- **Read-only as containment.** `read_only` and `NOTENV_READONLY` stop a
  cooperating client's accidental writes, not an adversary: read equals write under
  a single master key. Enforced read-only is the storage credential; cryptographic
  read-only identities are v2 (a decrypt / sign split).
- **Egress by a process holding a secret.** A child handed `$KEY` can send it
  anywhere it reaches; that is sandbox and network-policy territory.
- **Availability.** Write or delete access can destroy objects (denial-of-service);
  a versioned remote recovers prior bytes, but notenv does not guarantee uptime.
- **A weak passphrase**, **the credential stores themselves** (your password
  manager, the platform secret store), **traffic analysis** beyond the metadata
  above, and **un-sharing a value someone already decrypted** (re-key prevents
  *future* reads; rotate the underlying secret to change the current value).

## Edge cases and recovery

These are real, documented gaps. **Almost all require multiple machines or a
remote; a solo developer on one machine meets none.** `notenv doctor` detects the
recoverable ones and names the fix; the [recovery guide](../guides/recovery.md)
walks through them.

- **A machine's first use is trust-on-first-use; a collaborator onboarded with the
  onboarding string is not.** The string `key add <name>` prints (a one-time
  passphrase plus a vault fingerprint) verifies the served header against that
  fingerprint, refusing a substituted vault before the first pin. A machine unlocking
  by identity has no fingerprint: with no prior revision to compare, a substitution
  predating its first contact cannot be caught. After first contact, rollback and
  substitution are detected for both.
- **Warm-cache runs defer the rollback check** by at most one cache TTL: with the
  key cached, a run does not re-read the header (writes always do). The cached blob
  carries a MAC checked before use, so a tampered cache entry is rejected.
- **A former holder with write access can fork history.** The fundamental limit of
  dumb storage, and why offboarding ends with rotating the storage credential.
- **Concurrent header writes need a read-after-write-consistent remote.** rclone
  has no atomic conditional write, so the swap is read-compare-write-readback;
  every major provider meets the requirement. In a rare same-instant race a losing
  write can be dropped (recover with `key restore-backup` or by re-running); the
  local file-lock backend and single-machine use are unaffected.
- **An interrupted remote write may be unconfirmed.** notenv keeps the object
  rather than risk deleting one the header now references; `key restore-backup`
  recovers if a later read fails. A write that crashed earlier just leaves an
  unreferenced blob the next write reclaims.
- **The first-use "expose these secrets?" prompt reads an unauthenticated header,**
  so a storage attacker could suppress it. It is an advisory prompt, not a
  boundary: the real read still verifies everything and fails closed.
- **`notenv edit` can touch persistent disk** when `XDG_RUNTIME_DIR` is unset (it
  falls back to the OS temp dir and warns): only values you type that session, in a
  0600 file removed on exit.
- **rclone setup passes the storage credential via argv** on the convenience path
  (briefly visible to same-user processes); these guard ciphertext storage, not the
  vault. Create the remote with `rclone config` yourself to avoid it.
- **Primary-slot governance is advisory:** every team slot holds the master, so
  "who may remove slots" is tooling-enforced, not cryptographic.

## Supply chain

Releases are built reproducibly with GoReleaser, signed with
[cosign](https://github.com/sigstore/cosign) (keyless), and carry SLSA build
provenance; the [installation page](../getting-started/installation.md) shows how
to verify a download. The release pipeline is pinned to match: every GitHub Action
it runs is fixed to an immutable commit SHA, the GoReleaser build is pinned to an
exact release, and publishing is gated on a protected environment, so a pushed tag
cannot ship a release on its own. The client-side-crypto core is intentionally
small and auditable: the tool never needs to be trusted with anything at rest.

## Reporting

Found a discrepancy or a vulnerability? See [Reporting a vulnerability](reporting.md).
