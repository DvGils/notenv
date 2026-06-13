# Caching and performance

To keep the workflow snappy, notenv caches two things:

- **Your master key** in the platform's key store, so you are prompted for your passphrase at most
  once per session (default 1 hour, configurable via `crypto.cache_ttl`): the kernel keyring on
  Linux, the Keychain on macOS, DPAPI on Windows.
- **The encrypted blob** in `XDG_RUNTIME_DIR` (tmpfs, Linux only), so a warm `notenv run` needs no
  network at all (default 1 hour, configurable per storage via its own `cache_ttl` key, e.g.
  `[storage.<name>] cache_ttl = "2h"`).

!!! info "Remote vaults only"

    A local vault is its own disk, so its reads skip the blob cache and verify the vault manifest
    every time: no second ciphertext copy, nothing to go stale.

On Linux both caches are RAM-backed and cleared on logout or reboot; on macOS and Windows the key
cache is ciphertext at rest under your login credentials (see the table below). Only ciphertext or
key material in a platform store is ever cached, never a plaintext file.

## Pulling another machine's changes

Changes you make on this machine refresh the cache immediately. To pull a change made on another
machine before the cache expires, use `notenv run --refresh` (or `notenv cache clear`). Set either
`cache_ttl` to `"0"` to disable caching.

## What each platform guarantees

The caches are not identical across platforms, and the differences are stated rather than papered
over:

| Guarantee | Linux (kernel keyring) | macOS (Keychain) / Windows (DPAPI) |
|---|---|---|
| Key cache at rest | nothing: RAM only | ciphertext under your login credentials |
| TTL | kernel-enforced at the deadline | lazy: checked and purged on the next read |
| Logout / reboot | gone | the entry persists, encrypted, until expiry-on-read |
| A live same-user process | can read the cache | can read the cache (same on every platform) |
| Blob cache | tmpfs, RAM-backed | none: every cold read fetches |

The macOS and Windows key caches live in the same custody class notenv already trusts for machine
identities: the platform secret store, encrypted at rest under the user's login credentials. What
they cannot promise is the kernel keyring's eviction-at-the-deadline; an expired entry persists
(encrypted) until the next notenv read touches and deletes it. If that difference matters to you,
set `crypto.cache_ttl = "0"` and notenv prompts every time.

Blob caching stays Linux-only: there is no RAM-backed location to promise elsewhere, and a cold
fetch is latency, not a prompt.

## Concurrent writes

`notenv set` never overwrites a shared object, so concurrent writers never lose each other. The
details (append-only segments, deterministic conflict resolution, automatic compaction, and safety
against a concurrent master rotation) are covered in
[Storage and concurrency](../concepts/storage.md).
