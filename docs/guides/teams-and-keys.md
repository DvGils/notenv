# Share a vault with your team

Several people can share one vault with no server: each gets their own passphrase,
and you add or remove them without re-sharing anything. This page covers
onboarding, offboarding, and the everyday key tasks.

## Add a teammate

1. Add them by name:

    ```sh
    notenv credential add alice
    ```

    notenv prints a **one-time onboarding string**: a generated passphrase plus a
    short code that identifies your vault, like
    `pupil-spend-fresh-flap-skit-shun/5pa7xxh6xspq4m2n`.

2. Send the whole string to Alice over a private channel (a chat message is fine).

3. Alice points her machine at the same storage and runs `notenv setup`, entering
   the string at the passphrase prompt. notenv has her immediately set a passphrase
   only she knows; the one-time string stops working then.

Until Alice sets her own passphrase her slot shows as **provisional** in
`notenv credential inspect` and no command runs for her, so you can see when onboarding is
done. After that you know none of her credentials, and nothing key-equivalent sits
on her disk.

!!! note "Onboarding writes to the vault"

    Replacing the one-time passphrase is a write. If some members use read-only
    storage credentials, onboard with a write-capable credential first, then switch
    them to read-only.

## Remove a teammate

```sh
notenv credential delete alice
```

This removes Alice's slot and re-keys the vault (a fresh master key, every secret
re-encrypted), so her old credential can no longer decrypt. Surviving members keep
working and pick up the change automatically.

!!! warning "Also rotate the storage credential"

    notenv cannot revoke someone's access to the storage itself. For a complete
    offboard, also rotate that storage's credential at your provider, or a former
    member who kept write access could still tamper with the vault. `notenv credential delete`
    reminds you.

## Everyday key tasks

| Task | Command |
|---|---|
| Change your own passphrase | `notenv credential rotate` |
| Re-key the vault as a precaution | `notenv credential rotate-master` |
| Move the primary (governance) slot | `notenv credential set-primary <name>` |
| List who has access | `notenv credential inspect` |

---

**Under the hood:** how slots wrap the master key, how the onboarding code refuses
a substituted vault, and how a re-key proves itself to other machines without
prompts are in [Keys and slots](../concepts/keys-and-slots.md). What sharing
defends and what it does not is in the [threat model](../security/threat-model.md).
