# How it works

notenv is client-side encryption on dumb storage. The boundary is sharp: everything on the storage
backend is ciphertext or key-wrapping metadata; plaintext exists only in RAM, only on the machine
running the command, only for as long as the command runs.

## A `notenv run`, end to end

```text
notenv run -- cmd
  |
  |-- fetch ciphertext   <- rclone <-  your B2 / S3 / Drive / ...
  |-- unlock the master key (from your passphrase; cached after first use)
  |-- decrypt secrets in memory
  |-- build the child environment from notenv.toml
  |-- exec cmd, stream its I/O, exit with its code
        nothing written to disk
```

1. **Fetch.** notenv reads the namespace's ciphertext from your storage (a local vault directory or a
   remote reached through rclone). On Linux a warm cache can serve this with no network at all.
2. **Unlock.** The master key is recovered by unwrapping a key slot with your passphrase or age
   identity. It is cached in the platform key store for the session (the kernel keyring on Linux, the
   Keychain on macOS, DPAPI on Windows).
3. **Decrypt.** Secrets are decrypted into memory. Plaintext never touches disk.
4. **Build the environment.** notenv assembles the child's environment from the declarations in
   `notenv.toml` (or, in projectless mode, every secret in the namespace).
5. **Exec.** notenv runs the command, streams its I/O (masking injected values when the output is
   captured), and exits with the child's exit code.

## The master key and key slots

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext at
rest. A small **header** object next to your secrets holds it wrapped under one or more **key slots**,
the same approach LUKS and restic use. A slot is either:

- a **passphrase** (yours, escrowed in a password manager), or
- a teammate's **age public key** (so you can grant access without sharing a secret).

Unlocking any slot yields the master key for the session. Changing a passphrase or adding/removing a
teammate rewraps only the header, not the secrets.

## Integrity in one line

The header is authenticated (an HMAC keyed from the master key) and carries a monotonic revision that
each machine pins locally. A party who can write your storage but holds no key cannot forge it, alter
it, or roll it back undetected. Every stored secret object is bound to that authenticated header, so
tampering with any single object is detected too.

The full model, including signed rotations and the object manifest, is in
[Keys and slots](keys-and-slots.md) and [Storage and concurrency](storage.md). What it defends and
what it does not is in the [threat model](../security/threat-model.md).
