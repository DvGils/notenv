# Roadmap

notenv is stable and follows a compatibility contract: within the 1.x line the storage format and
documented interface stay compatible, so upgrading never breaks a vault or a script. This page
tracks what works today, what is planned, and what is deliberately out of scope.

## Working today

- **Onboarding.** `setup`, `init`, and `import`; local vaults as the zero-account default, with
  one-command replication to a cloud remote (`vault copy`).
- **The core loop.** `secret set`, `secret unset`, `secret inspect`, and `run`, with `cache` and `doctor` for housekeeping.
- **Storage.** One encrypted blob per namespace under last-write-wins, so concurrent writers serialize
  on the header swap without losing each other, plus a one-generation backup per namespace and an
  authenticated, version-pinned header with a manifest binding every stored object (so storage-level
  tampering with any single secret alarms by name).
- **Keys and teams.** Full key and slot management (`notenv credential ...`): team access by age recipient,
  passphrase and master-key rotation, offboarding by re-key, advisory primary governance, and signed
  rotation transitions so legitimate re-keys propagate to every machine without prompts.
- **Agents and CI.** A scoped, ephemeral [`handoff`](../guides/ai-agents.md) that runs an agent with
  your master key out of its reach, masked captured output, machine-readable `--json`, docker-style
  exit codes, projectless `--namespace` and `NOTENV_STORAGE` addressing, policy-level read-only mode,
  and an installable **agent skill** (`skills/notenv/`).
- **Platforms.** Linux, macOS, and Windows, with session key caching on all three (kernel keyring,
  Keychain, DPAPI); blob caching on Linux. Releases are reproducible, cosign-signed, and carry SLSA
  build provenance.

## Planned

- **Homebrew / AUR / Scoop** packages. (V1)
- **Post-quantum hybrid recipient** Make encryption robust against quantum computers (V1 or V2)
- **Hardware-backed key slots** (YubiKey, FIDO2, TPM) via age plugins: a human slot whose credential
  cannot be exfiltrated at all. (V1 or V2)
- **Cryptographic read-only** Support true read-only (currently policy backed only) (V2)
- **RBAC** Support RBAC (V2)
- **File encryption** Support encrypting files (V2)


## Non-goals

- **Blob caching on macOS and Windows.** The master key is cached on all three platforms, but the
  ciphertext blob cache stays Linux-only: there is no RAM-backed location to promise elsewhere that a
  logout or reboot reliably reclaims, and a cold fetch is latency, not a prompt. See
  [What each platform guarantees](../concepts/caching.md#what-each-platform-guarantees).

See the [threat model](../security/threat-model.md) for the security properties and the explicit list
of what notenv does not defend.
