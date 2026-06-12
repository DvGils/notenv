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

If you are joining a vault someone else owns (rather than restoring your own), you join by **age
identity** instead of a passphrase. The vault owner adds you with only your public key, so you never
share a secret with them.

1. Generate an identity on your machine:

    ```sh
    notenv key gen-identity
    ```

    This saves an age identity locally and prints your public `age1...` recipient.

2. Send the owner that recipient. It is public and safe to share in the clear.

3. The owner runs `notenv key add --recipient age1... --name you`.

4. Point this machine at the same storage and run:

    ```sh
    notenv setup
    notenv run -- ...
    ```

    Your identity unlocks the vault. No passphrase needed.

See the [command reference](../reference/commands.md) for the full set of `notenv key` operations.
