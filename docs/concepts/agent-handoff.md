# Agent handoff

`notenv handoff -- <agent>` runs a coding agent against a **scoped, ephemeral
vault** instead of your real one. The agent can use the secrets you handed it, but
your master key is never in its reach, so the worst a compromised or prompt-injected
agent can leak is the one namespace you scoped in, not the rest of your vault.

This is one hard guarantee, not a sandbox. See [what it is and is not](#what-this-is-and-is-not).

## A `notenv handoff`, end to end

```text
notenv handoff -- claude
  |
  |-- resolve the namespace (project notenv.toml, or --namespace), like `run`
  |-- mint an ephemeral vault E (a fresh random key), in RAM where available
  |     builder subprocess: unlock your vault, copy the namespace into E, exit
  |-- spawn the agent pointed only at E (it never sees your real vault)
  |
  |   ... agent works: `notenv run -- pytest` resolves against E, real values ...
  |
  |-- agent exits -> destroy E and its key
```

1. **Resolve the namespace** the same way `run` does, so the agent's own
   `notenv run` resolves the same namespace it was handed.
2. **Mint the ephemeral vault `E`.** A short-lived builder subprocess unlocks your
   real vault, writes the namespace's current secrets into `E` under a **fresh,
   independent key**, and then exits. `E` is an ordinary local vault in the normal
   format, created in a RAM-backed directory where the platform has one.
3. **Spawn the agent pointed only at `E`** (`NOTENV_STORAGE` and `NOTENV_IDENTITY`
   are set to `E` and its fresh key). The agent's normal `notenv run` and
   `notenv namespace inspect` resolve against `E` and get the real values.
4. **Tear down at exit.** `E` and its key are destroyed on exit and on Ctrl-C.

## Why your master key is out of reach

The guarantee is narrow and precise: **the agent can never obtain your master key,
so it can never decrypt anything outside the scope you handed it.** It holds only
`E`'s fresh key, which reveals nothing about your master. Four things make that hold:

- **The builder exits before the agent starts.** The only process that ever unlocked
  your master is gone by the time the agent runs, so there is no live process for it
  to read the master out of.
- **`E`'s key is freshly generated**, not derived from or wrapped by your master, so
  having it tells the agent nothing about yours.
- **No cache to read.** For the whole session, handoff holds a *no-cache lease* on
  your real vault, so your master is never written to the shared session key cache,
  even if you unlock the same vault in another terminal (those other terminals
  re-prompt instead of caching, for the duration). See [Caching](caching.md).
- **A prompt inside the session fails closed.** `E` is unlocked by its key and never
  prompts, so any attempt to unlock a *different* vault from inside the session is a
  misconfiguration, and notenv refuses it rather than prompting you for your real
  passphrase.

One precondition makes this possible: the source vault must be **passphrase-gated**.
If your own vault is unlocked by an age identity (`NOTENV_IDENTITY`), the agent runs
as you and could replay that identity, so handoff refuses rather than give you a
false guarantee.

## Telling whether you are in a handoff

A launched agent can ask notenv, at startup, whether it is actually inside a scoped
handoff session:

```text
notenv handoff inspect   # exit 0 = inside a handoff, exit 1 = not
notenv handoff inspect --json   # {"handoff": true, "namespace": "api"}
```

The answer is the exit code, so an agent can branch without parsing, and `--json` adds
the single namespace it was scoped to (never an enumeration of your other namespaces).
It reads only its own environment and the ephemeral vault on disk: no vault is unlocked,
no passphrase is asked, and no secret value is ever printed.

This matters because an environment variable is only a claim. A detached or
long-outliving process can carry a stale `NOTENV_SESSION`, and an unrelated `export`
can clobber one variable but not another. So "yes" is corroborated against live ground
truth: the vault `NOTENV_STORAGE` names must be the ephemeral vault that session is
scoped to, still present on disk, and its handoff supervisor must still be running. A
lost or clobbered variable therefore fails to a safe "no" (a harmless nudge to restart
under handoff), never a false sense of being scoped.

The human side has a complement. If you run a recognized coding agent through
`notenv run` instead of `notenv handoff`, notenv notices and asks whether you meant
handoff before injecting your real values, so the unrecommended path is caught at the
moment you type it rather than only after the agent starts. Like the check above, it is
accident-proofing, not a boundary: it nudges, it does not enforce.

## What this is and is not

Handoff protects your **master key**. It does not contain the agent.

- **It bounds which keys the agent holds, not what it does.** The agent runs as you:
  it can read your files, reach the network, and use, store, or leak the secrets you
  scoped in. The values it reads stay valid after the session.
- **It is not non-extraction.** Scoping the set is not the same as sealing it. The
  agent has `E`'s key and can read everything in `E`.
- **Containment is the OS's job.** If you need to limit what the agent can do or
  where it can send bytes, run it under a sandbox with network-egress control.
  Handoff composes with that; it does not replace it.

In short: hand off only to an agent you trust, and use handoff to make sure a slip in
the namespace you trusted it with never becomes a compromise of your whole vault.

The full account of what notenv defends and what it does not is in the
[threat model](../security/threat-model.md); how to use handoff day to day is in
[AI agents](../guides/ai-agents.md).
