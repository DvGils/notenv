# Multiple vaults

One machine can use several storages (vaults). `notenv setup` adds a named storage and can be re-run
to add more; the first becomes the default.

## How a project picks its vault

- A project chooses its storage at `notenv init` time. The choice is recorded, along with its
  namespace pin, in a git-ignored `notenv.local.toml` beside `notenv.toml`. With a single storage
  there is nothing to pick.
- `--storage NAME` overrides the choice for any command. Use it in CI to pin the vault from outside
  the repo.
- The committed `notenv.toml` never names a storage, and the namespace it names is pinned per
  checkout. So cloning an untrusted project cannot point your machine at a different vault, or
  silently at a different project's secrets within your vault.

## Namespaces

A **namespace** is the unit of secrets within a vault (it defaults to the project directory name).
The committed contract chooses the namespace, which is why notenv pins it per checkout: without that
pin, a cloned repository could silently point your machine at another project's secrets in the same
vault.

- Using a namespace other than the directory's name is confirmed once per checkout.
- A contract that later changes its namespace is refused until you re-accept it with `notenv init`.

## Address a vault directly

`--namespace NAME` (with `--storage NAME`) addresses a vault namespace from anywhere, with no project
and no checkout. The contract is bypassed entirely, so `run` injects every secret in the namespace.
This is how an agent or a machine with no git checkout reaches its credentials. First use of a
namespace that already holds secrets is confirmed once, recorded per user. See
[AI agents](ai-agents.md).
