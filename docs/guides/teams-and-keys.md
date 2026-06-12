# Teams and key management

Several people and machines can share one vault with no server, using **key slots**. The rule that
keeps the model honest: **passphrases are for people, identities are for machines.** A person's
credential lives in their head and their password manager; a machine's credential lives in the
platform's secret store. Neither ever sits in a plaintext file that notenv owns.

## How sharing works

Your secrets are encrypted with a random **master key**. The master key never exists in plaintext at
rest: a header object holds it wrapped under one or more slots. A slot is either a **passphrase**
(a person's, escrowed in their password manager) or an **age public key** (a machine's; see
[CI](ci.md) and [AI agents](ai-agents.md)). Unlocking any slot yields the master key for the
session. Adding or removing a slot rewraps only the header, never the secrets.

## Onboard a teammate

1. **You** add them by name:

    ```sh
    notenv key add alice
    ```

    notenv generates a high-entropy **one-time onboarding passphrase** and prints it once.

2. Send that passphrase to Alice over a private channel (a chat message is fine; see the note below
   on what an interceptor would need).

3. **Alice** points her machine at the same storage and runs:

    ```sh
    notenv setup
    ```

    She enters the one-time passphrase, and notenv immediately makes her replace it with a
    passphrase only she knows. The one-time passphrase stops working at that moment. Until she does
    this, no notenv command will proceed for her, and `notenv key list` shows her slot as
    **provisional** so you can see the onboarding is not finished.

That is the whole flow. After step 3 you no longer know any credential of Alice's, and nothing
key-equivalent exists on her disk: her passphrase is in her head and her password manager, like
yours.

!!! note "What an interceptor would need"

    The one-time passphrase alone decrypts nothing: the vault lives on your storage, not in the
    chat. An adversary would need the passphrase **and** read access to your storage **during the
    minutes before Alice replaces it**. If you ever suspect that window was compromised, or a slot
    stays provisional suspiciously long, run `notenv key rotate-master` (and `notenv key rm` the
    slot): a fresh master key makes anything an interceptor captured useless.

!!! note "Onboarding needs write access"

    Replacing the one-time passphrase is a header write. If your team uses read-only storage
    credentials for some members, onboard with the write-capable credential first, then switch the
    member to the read-only one.

## Enroll a machine

CI jobs and agents are not teammates; they get **identities**, provisioned through the platform's
secret store:

```sh
notenv key add --machine ci
```

This prints a new age identity exactly once, for pasting into the secret store; notenv saves it
nowhere. The machine presents it via `NOTENV_IDENTITY`. If the machine generated its own identity,
enroll its public key instead: `notenv key add --machine ci --recipient age1...`. See the
[CI guide](ci.md) for the full recipe, including enforced read-only.

## Offboard a teammate or machine

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
| Change your passphrase | `notenv key rotate` | Rewraps your slot. Header only; secrets untouched. |
| Re-key as a precaution | `notenv key rotate-master` | Fresh master key, every secret re-encrypted, all slots kept. |
| Transfer governance | `notenv key set-primary <name>` | Moves the advisory primary slot (the one `key rm` refuses to remove). |
| Inspect slots | `notenv key list` | Name, principal, primary, added date, fingerprint. `--json` for machines. |

## Re-keys propagate silently

Re-keys, including offboarding, reach the other machines automatically. Each rotation is signed by
the key it replaces, so every other machine verifies the chain and follows without prompts or
alarms. `notenv key trust` (which shows what changed and asks) is needed only for a master change
that carries no such signed proof.
