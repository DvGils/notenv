# Caching and performance

To keep the workflow snappy, notenv caches two things on Linux:

- **Your master key** in the kernel keyring, so you are prompted for your passphrase at most once per
  session (default 1 hour, configurable via `crypto.cache_ttl`).
- **The encrypted blob** in `XDG_RUNTIME_DIR` (tmpfs), so a warm `notenv run` needs no network at all
  (default 1 hour, configurable via `storage.cache_ttl`).

!!! info "Remote vaults only"

    A local vault is its own disk, so its reads skip the blob cache and verify the vault manifest
    every time: no second ciphertext copy, nothing to go stale.

Both caches are RAM-backed and cleared on logout or reboot. This is not only a speed-up but a
**security property**: when the process exits there is no persistent cache for someone to discover
later. Only ciphertext is ever cached, never plaintext.

## Pulling another machine's changes

Changes you make on this machine refresh the cache immediately. To pull a change made on another
machine before the cache expires, use `notenv run --refresh` (or `notenv cache clear`). Set either
`cache_ttl` to `"0"` to disable caching.

## Caching is Linux-only, by design

| Platform | Cache | Persistence |
|---|---|---|
| Linux | RAM-backed (kernel keyring + tmpfs) | removed automatically on logout/reboot |
| macOS | **none, by design** | n/a |
| Windows | **none, by design** | n/a |

The Linux cache relies on the kernel keyring and `tmpfs`: secret material lives in RAM that the OS
reclaims on logout, so "the process exits and nothing is left behind" is a real guarantee. The
platform-native stores (macOS Keychain, Windows Credential Manager / DPAPI) give no such cleanup
guarantee: they persist to disk, and with no daemon there is nothing to evict them. Rather than ship
a weaker cache under the same name and quietly break the "nothing left behind" property, notenv
**does not cache on macOS or Windows**.

Those platforms prompt and fetch on each run. For a prompt-free workflow there, enroll the machine
(`notenv key add --machine`) and present its identity via `NOTENV_IDENTITY` from a secret store you
control, with no lifecycle managed by notenv. See [Teams and keys](teams-and-keys.md).

## Concurrent writes

`notenv set` never overwrites a shared object, so concurrent writers never lose each other. The
details (append-only segments, deterministic conflict resolution, automatic compaction, and safety
against a concurrent master rotation) are covered in
[Storage and concurrency](../concepts/storage.md).
