# Keys and slots

This page explains the key model in depth: how the master key is wrapped, how the header stays
honest, and how a re-key propagates across machines.

## The master key

Every secret in a vault is encrypted with a single random **master key** (X25519). Compromise of the
master key compromises every secret in that vault, so the master key never exists in plaintext at
rest. It is stored once, in the **header**, wrapped to one or more key slots.

## Key slots

A slot wraps the master key so that one credential can recover it. Passphrases are for people,
identities are for machines:

- **Passphrase slot (a person).** The master is reachable via a slot keypair whose private key is
  scrypt-wrapped under a passphrase. scrypt raises the cost of an offline brute-force. A teammate's
  slot starts out **provisional**: it is wrapped under a generated one-time onboarding passphrase,
  and no command proceeds for them until they replace it with a passphrase only they know.
- **Recipient slot (a machine).** An age public key whose private identity lives in the platform's
  secret store (CI, an agent harness), presented via `NOTENV_IDENTITY`. notenv never stores an
  identity on disk.

Unlocking any one slot yields the master key. This is the LUKS / restic pattern: changing a passphrase
or adding/removing a slot rewraps only the header, not the secrets.

## The authenticated header

The header carries the wrapped master, the slot set, and metadata. It is protected by:

- an **HMAC** keyed from the master, so it cannot be forged or silently altered by someone who cannot
  decrypt;
- a **monotonic revision** that each machine pins locally, so a rollback to an older header is detected;
- a **vault identity** bound to each storage location locally, so swapping in a different vault at the
  same location is detected; and
- an **object manifest** binding every stored secret object to the header (see
  [Storage and concurrency](storage.md)).

A machine refuses a header whose revision went backward, whose vault identity changed, or that
vanished where one was pinned. `notenv key forget` is the deliberate-reset escape hatch.

## Re-keys and signed transitions

Two operations mint a fresh master and re-encrypt every secret under it, keeping all slots:

- `notenv key rotate-master`: a precaution, for example if a machine may be compromised.
- `notenv key rm <name>`: offboarding. It also drops the removed slot.

A naive re-key would alarm every other machine (the master changed). Instead, each rotation records a
**transition signed by the outgoing master**. A machine still pinned at that master verifies the chain
and follows the change silently. The master-changed alarm therefore fires only for a change that *no
holder of the pinned master authorized*, which is the case worth a human's attention.
`notenv key trust` (which shows what changed and asks) remains only for changes that carry no such
signed proof.

!!! note "What signed transitions do and do not prevent"

    A non-holder cannot forge a transition: they lack the old signing key. An **ex-holder can**, which
    is why offboarding ends with rotating the storage credential. See the
    [threat model](../security/threat-model.md#known-limitations).

## Governance

In shared-master team mode, every slot holder has the master key, so "who may remove slots" is
tooling-enforced, not cryptographic. One slot is the advisory **primary**; `notenv key rm` refuses to
remove it, and `notenv key set-primary` transfers it. This is governance, not a security boundary.

## What lives where

| Material | Location | Notes |
|---|---|---|
| Secret values (plaintext) | RAM only, on the running machine, for the command's lifetime | Never on disk |
| Master key | The header, wrapped to slots; cached for a session in the platform key store (kernel keyring on Linux, Keychain on macOS, DPAPI on Windows) | Never plaintext at rest |
| Passphrase (a person) | Their head and their password manager | Never stored on the backend or on disk |
| age identity (a machine) | The platform's secret store, presented via `NOTENV_IDENTITY` | notenv stores no identity on disk, anywhere |
