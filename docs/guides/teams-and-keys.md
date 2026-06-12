# Teams and key management

Several people (or machines) can share one vault with no server, using **key slots**. The
asymmetric path is the point: you add a teammate with only their **public** key, and they never
share a secret with you.

## How sharing works

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext at
rest: a header object holds it wrapped under one or more slots. A slot is either a **passphrase**
(yours, escrowed) or a teammate's **age public key**. Unlocking any slot yields the master key for
the session. Adding or removing a teammate rewraps only the header, never the secrets.

## Onboard a teammate

1. **Teammate** generates an identity and shares their public recipient:

    ```sh
    notenv key gen-identity      # saves an age identity locally, prints age1...
    ```

2. They send you that `age1...` recipient. It is public and safe to share in the clear.

3. **You** add them by recipient:

    ```sh
    notenv key add --recipient age1... --name alice
    ```

4. **Teammate** points at the same storage and runs:

    ```sh
    notenv setup
    notenv run -- ...
    ```

    Their identity unlocks the vault. No passphrase.

## Offboard a teammate

```sh
notenv key rm alice
```

This removes the slot **and re-keys the vault**: it mints a fresh master key and re-encrypts every
secret, so the removed credential can no longer decrypt. All surviving slots keep working, and the
re-key propagates to other machines automatically (see [below](#re-keys-propagate-silently)).

!!! warning "notenv does not own your storage"

    notenv cannot revoke a former holder's storage **write** access. For complete offboarding, also
    rotate that storage's credential at your provider. Otherwise a holder who kept both the old
    master key and write access could fork the vault's history. notenv **detects** such a fork but
    cannot prevent it; `key rm` reminds you to rotate the credential. See the
    [threat model](../security/threat-model.md).

## Other key operations

| Operation | Command | Effect |
|---|---|---|
| Add a backup passphrase | `notenv key add --passphrase` | A second passphrase slot (backup or second device). |
| Change your passphrase | `notenv key rotate` | Rewraps your slot. Header only; secrets untouched. |
| Re-key as a precaution | `notenv key rotate-master` | Fresh master key, every secret re-encrypted, all slots kept. |
| Transfer governance | `notenv key set-primary <name>` | Moves the advisory primary slot (the one `key rm` refuses to remove). |
| Inspect slots | `notenv key list` | Name, type, primary, fingerprint. `--json` for machines. |

## Re-keys propagate silently

Re-keys, including offboarding, reach the other machines automatically. Each rotation is signed by
the key it replaces, so every other machine verifies the chain and follows without prompts or
alarms. `notenv key trust` (which shows what changed and asks) is needed only for a master change
that carries no such signed proof.
