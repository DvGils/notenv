# Roadmap

notenv is actively developed and being tested. This page tracks what works today, what is planned,
and what is deliberately out of scope.

## Working today

- **Onboarding.** `setup`, `init`, and `import`; local vaults as the zero-account default, with
  one-command replication to a cloud remote (`vault copy`).
- **The core loop.** `set`, `unset`, `list`, and `run`, with `compact` and `cache` for housekeeping.
- **Storage.** Append-only writes so concurrent `set`s never lose each other, automatic compaction
  keeping reads fast, and an authenticated, version-pinned header with a manifest binding every stored
  object (so storage-level tampering with any single secret alarms by name).
- **Keys and teams.** Full key and slot management (`notenv key ...`): team access by age recipient,
  passphrase and master-key rotation, offboarding by re-key, advisory primary governance, and signed
  rotation transitions so legitimate re-keys propagate to every machine without prompts.
- **Agents and CI.** Masked captured output, machine-readable `--json`, docker-style exit codes,
  projectless `--namespace` addressing, policy-level read-only mode, and an **experimental MCP server**
  (`notenv mcp`).
- **Platforms.** Linux, macOS, and Windows; Linux key/blob caching. Releases are reproducible,
  cosign-signed, and carry SLSA build provenance.

## Planned

- **A broker mode.** The unlocked key lives in a separate trust domain and execs children on behalf of
  agents, turning "agents shouldn't see credentials" from a convention into a boundary.
- **Hardware-backed key slots** (YubiKey, FIDO2, TPM) via age plugins: a human slot whose credential
  cannot be exfiltrated at all.
- **Homebrew / AUR / Scoop** packages.

## Non-goals

- **Secret caching on macOS and Windows.** Those platforms have no daemon-free way to guarantee a cache
  is cleaned up, so notenv prompts and fetches on each run rather than shipping a weaker cache under the
  same name. See [Caching is Linux-only, by design](../guides/caching.md#caching-is-linux-only-by-design).

See the [threat model](../security/threat-model.md) for the security properties and the explicit list
of what notenv does not defend.
