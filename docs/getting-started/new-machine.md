# On a new machine

Joining your own project from another computer takes three commands:

```sh
git clone <your-project>
cd <your-project>
notenv setup         # enter your escrowed passphrase
notenv run -- ...    # ready
```

Nothing else to restore. The committed `notenv.toml` and your password manager are all you need.

!!! info "A lost or dead machine loses nothing"

    The only irreplaceable secret is your passphrase, which lives in your password manager, not on
    the storage backend. Retrieve it on a new machine and notenv works again.

## Joining someone else's vault

If you are joining a vault someone else owns (rather than restoring your own), you still end up
with a passphrase only you know; the owner just opens the door:

1. The owner runs `notenv credential add you` and sends you the **one-time onboarding string** it
   prints (a generated passphrase plus a code that fingerprints the vault), over a private
   channel.

2. Point this machine at the same storage and run:

    ```sh
    notenv setup
    ```

    Enter the whole string. notenv verifies you reached the vault you were invited to (not a
    substitute), then immediately makes you replace the passphrase with your own; the one-time
    passphrase stops working, and from then on the owner knows no credential of yours.

3. Escrow your new passphrase in your password manager and you are ready: `notenv run -- ...`

See [Teams and keys](../guides/teams-and-keys.md) for the full model and the
[command reference](../reference/commands.md) for every `notenv credential` operation.
