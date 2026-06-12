# Configuration files

notenv splits configuration across three files: one committed contract, one per-machine config, and
one per-checkout binding. Secret **values** live in none of them. They are always encrypted in your
vault.

## `notenv.toml` (committed)

Lives in your project and **is committed**. It declares which environment variables the project
needs. It contains no secret values.

```toml
namespace = "my-project"   # optional; defaults to the directory name

[secrets]
DATABASE_URL = { required = true }
SENTRY_DSN   = { required = false }
STRIPE_KEY   = { name = "stripe-secret-key" }   # use a different storage key name
```

| Field | Meaning |
|---|---|
| `namespace` | The namespace this project reads. Defaults to the directory name. Pinned per checkout. |
| `[secrets] KEY = { required = bool }` | Declare an environment variable. `required = true` fails `run` if it is missing. |
| `{ name = "..." }` | Store the secret under a different key name than the environment variable. |

## `~/.config/notenv/config.toml` (per machine, not committed)

Defines one or more named storages (vaults). Written for you by `notenv setup`.

```toml
default = "personal"               # storage used when a project has no local binding

[storage.local]
path      = "~/.local/share/notenv/vaults/local"   # a local vault directory (no rclone)

[storage.personal]
remote    = "s3-notenv"            # an rclone remote name
base      = "my-bucket/notenv"     # path within the remote
versioned = true                   # remote keeps old versions on overwrite (B2 does)
# read_only = true                 # refuse mutating commands here (policy, not enforcement)
# cache_ttl = "1h"                 # ciphertext cache lifetime (remote storages only); "0" disables

[crypto]
mode = "passphrase"
# cache_ttl = "1h"                 # master-key cache lifetime; "0" disables
```

### Storage entry fields

A storage is either a **local vault** (`path`) or a **cloud remote** (`remote` + `base`). Exactly one
of the two forms is set.

| Field | Applies to | Meaning |
|---|---|---|
| `path` | local | A local vault directory. Pure-Go backend, no rclone. |
| `remote` | cloud | An rclone remote name. |
| `base` | cloud | The path within the remote. |
| `versioned` | cloud | The remote retains old object versions on overwrite (B2 does natively), so notenv skips the extra server-side `.prev` backup copy. |
| `read_only` | both | Refuse every mutating command against this storage. Policy for cooperating clients, not enforcement; see [Environment variables](environment.md). |
| `cache_ttl` | cloud | Ciphertext cache lifetime. `"0"` disables. Remote storages only; a local vault does not blob-cache. |

### Crypto

| Field | Meaning |
|---|---|
| `mode` | `passphrase` (the default unlock mode). |
| `cache_ttl` | Master-key cache lifetime (Linux only). `"0"` disables. |

!!! note "Storage settings are machine-only by design"

    A committed `notenv.toml` cannot redirect where your machine reads and writes secrets. Storage
    lives only in the per-machine config, so cloning a project can never repoint your storage.

## `notenv.local.toml` (per checkout, not committed)

Written by `notenv init` and git-ignored. Records what *this checkout* has agreed to: which storage
it uses (when the machine has several) and which **namespace** it reads.

The namespace pin matters: the committed contract chooses the namespace, so without the pin a cloned
repository could silently point your machine at another project's secrets in the same vault. Using a
namespace other than the directory's name is confirmed once per checkout, and a contract that later
changes its namespace is refused until you re-accept it with `notenv init`. See
[Multiple vaults](../guides/multiple-vaults.md).
