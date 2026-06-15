# notenv CLI message review

A review of user-facing messages across the CLI: cobra help text (`Short`/`Long`/`Example`/flag help), printed status lines (`ui.*`), interactive prompts, and errors that surface to the user.

**Scope:** all of `cmd/notenv/*.go` plus user-visible strings in `internal/`.
**What is flagged:** clarity, wordiness, friendliness/tone, actionability (does an error tell you the fix?), consistency, and correctness.
**What is not flagged:** lowercase/no-period Go error strings (idiomatic), and purely internal errors a user can't realistically hit.

Severity: **HIGH** = confusing/contradictory/wrong, worth fixing. **MED** = noticeably improvable. **LOW** = polish/consistency nit.

This is a scratch document for your review; delete it when done. Quotes are verbatim from source.

---

## Executive summary: the cross-cutting themes

These patterns recur across many files and are the highest-value fixes, because one decision fixes dozens of strings.

### 1. Internal vocabulary leaks into user-facing text (the biggest theme)

Implementation terms appear in help, prompts, status lines, and errors where an everyday user has no way to interpret them. Pick a plain-English word for each and apply it everywhere:

| Internal term | Suggested user-facing word | Example sites |
|---|---|---|
| `blob` / `blobs` / `objects` | "stored secret" / "value" / "data" | manifest.go:92, secrets.go:515, app.go:388, cmd_setup.go:260, cmd_vault.go:166/338 |
| `header` / `key header` | "vault" (the thing); keep "header" only when truly needed | app.go:254, cmd_key.go:186, master.go:96, cmd_doctor.go:98 |
| `ephemeral vault` | "temporary scoped vault" | cmd_handoff.go:89/126/160, session.go:41 |
| `master` (alone) | "master key" (use consistently) | cmd_handoff.go:126 vs "master key" elsewhere |
| `escrow` | "save (escrow)" or "back up" | cmd_key.go:498, master.go:152, cmd_init.go:115 |
| `ciphertext` | "encrypted data/secrets" | cmd_setup.go:246 |
| `no-cache lease` | "session isolation" | cmd_handoff.go:113 |
| `trust state` | "this machine's record of the vault" | cmd_vault.go:294/364 |
| `checkout` / `re-pinning` | "this project" / "switching" | cmd_init.go:101 |
| `MVP` | drop it (project-phase jargon) | config.go:619 |
| `untrustable` | "unreadable" / "corrupt" (non-standard word) | cmd_key.go:973, app.go:388 |

### 2. Composed errors read awkwardly once `%w` joins base + suffix (HIGH)

Several errors wrap a lowercase sentinel fragment with a capitalized full sentence, which reads jarringly, or worse, contradicts itself:

- [header.go:367](internal/crypto/header.go#L367) wraps `ErrWrongPassphrase` ("wrong passphrase"), so the user sees: **"wrong passphrase: a slot's passphrase matched but its key does not open the vault master..."** That is self-contradictory (the passphrase *did* match).
- [header.go:495](internal/crypto/header.go#L495) wraps `ErrNotRecipient` ("blob was not encrypted under the current master key"), producing jargon + a capitalized question mid-error.

These are messages users hit on a bad passphrase or a re-keyed vault, so they matter.

### 3. Everyday-command success lines use three different vocabularies and shapes

The four most-used verbs phrase "what changed" inconsistently:

- `set`: `"%s set in namespace %q"` (key-first)
- `unset`: `"%s removed from namespace %q"` (key-first, "removed")
- `edit`: `"edited namespace %q: %d set, %d unset"` (namespace-first, "unset")
- `import`: `"imported %d secrets into namespace %q (%d new, %d updated)"` (verb-first, "new/updated")

Three vocabularies for the same idea: set/removed, set/unset, new/updated. Worth settling on one verb set and one sentence shape.

### 4. Plural guarding is inconsistent

Most output uses the `secret(s)` / `change(s)` convention, but `import` uses bare `"%d secrets"` at [cmd_import.go:108](cmd/notenv/cmd_import.go#L108), [:169](cmd/notenv/cmd_import.go#L169), [:171](cmd/notenv/cmd_import.go#L171), which prints **"1 secrets"**. Standardize on `secret(s)`.

### 5. Terminology drift on a few recurring phrases

- Version errors: "this build understands" (secrets.go:247) vs "this version of notenv no longer reads" (secrets.go:249, header.go:409) vs "this notenv supports" (header.go:412). Pick one.
- "Vault replaced wholesale" recovery: cmd_key.go:104 says run `notenv key forget` "and connect again" (no such command); master.go:96 correctly says "and set up again". Align on "set up again".
- Setup prompts: "Where should this vault live?" (cmd_setup.go:122) vs "Where should encrypted secrets live?" (cmd_setup.go:383) for related steps.
- "storages" (the plural) is grammatically awkward but used consistently; keep or change everywhere, not piecemeal.

### 6. Two-part messages where only the unhelpful half bubbles up

Pattern: a helpful `Infof` with the fix, then a terse `errors.New("rclone missing")` that is what actually propagates. In non-interactive/log contexts the user sees only the useless half. Sites: cmd_setup.go:246/249, cmd_vault.go:159/160. Make the bubbled error self-sufficient.

### 7. One factual staleness bug (HIGH)

[config.go:287](internal/config/config.go#L287) writes this comment into **every generated config**:
> `# cache_ttl = "1h"   # master-key cache lifetime (Linux kernel keyring); "0" disables`

The master-key cache now also works on macOS (Keychain) and Windows (DPAPI), so this misleads non-Linux users into thinking caching is Linux-only. Fix:
> `# master-key cache lifetime (OS keystore: kernel keyring / Keychain / DPAPI); "0" disables`

---

## Findings by file

### Setup & onboarding

#### [cmd_setup.go:89](cmd/notenv/cmd_setup.go#L89) — MED > AGREE
- **Current:** `next: ` + "`notenv init`" + ` inside a project (it will let you pick which storage to use)`
- **Issue:** "it will let you pick which storage to use" only happens when multiple storages exist; overpromises a choice on a fresh single-storage setup.
- **Suggest:** `next: run `notenv init` inside a project to start using this storage`

#### [cmd_setup.go:234](cmd/notenv/cmd_setup.go#L234) — MED > AGREE
- **Current:** `this vault is encrypted at rest but exists on this machine only. Back up the directory, or attach a cloud remote later with ` + "`notenv vault copy`"
- **Issue:** Two sentences in one status line with mixed capitalization (lowercase start, capital "Back up" mid-line).
- **Suggest:** `this vault is encrypted at rest but lives on this machine only; back up the directory or attach a cloud remote later with `notenv vault copy``

#### [cmd_setup.go:349](cmd/notenv/cmd_setup.go#L349) — MED > AGREE
- **Current:** `storage name %q must be letters, digits, '-' or '_' (no dots or spaces)`
- **Issue:** Grammar: a name is not "letters", it's made of them.
- **Suggest:** `storage name %q may use only letters, digits, '-' or '_' (no dots or spaces)`

#### [cmd_setup.go:149](cmd/notenv/cmd_setup.go#L149) — MED > AGREE
- **Current:** `storage %q already exists (%s); pass --name for a second vault`
- **Issue:** "for a second vault" assumes intent; they may want to replace.
- **Suggest:** `storage %q already exists (%s); pass --name to add a separate vault`

#### [cmd_setup.go:260](cmd/notenv/cmd_setup.go#L260), [cmd_vault.go:166](cmd/notenv/cmd_vault.go#L166) — LOW > AGREE
- **Current:** `Bucket/path for encrypted blobs`
- **Issue:** "blobs" jargon in an interactive prompt.
- **Suggest:** `Bucket/path for encrypted secrets`

#### [cmd_setup.go:218](cmd/notenv/cmd_setup.go#L218), [cmd_vault.go:76](cmd/notenv/cmd_vault.go#L76) — LOW > AGREE
- **Current:** `Validating vault directory: write, read back, delete probe` / `Validating destination: write, read back, delete probe`
- **Issue:** Spinner label reads like a dev note; "write, read back, delete probe" parses awkwardly.
- **Suggest:** `Checking the destination is writable` (or wrap the steps in parens).

#### [cmd_setup.go:223](cmd/notenv/cmd_setup.go#L223) (and siblings at :280, cmd_init) — LOW > AGREE
- **Current:** `wrote storage %q to %s`
- **Issue:** Reads as if the vault was written to `%s`, but `%s` is the config-file path.
- **Suggest:** `saved storage %q to config (%s)`

#### onboarding (onboard.go)

##### [onboard.go:65](cmd/notenv/onboard.go#L65) / [onboard.go:93](cmd/notenv/onboard.go#L93) — MED > AGREE
- **Current:** `%s, so it needs a human to confirm with a passphrase, and there is no terminal to ask on`
- **Issue:** "no terminal to ask on" is ungrammatical; omits the fix. (Same awkward "to ask on" at namespace_guard.go:138.)
- **Suggest:** `%s, so it needs a human to confirm with a passphrase, but no terminal is available; run this command interactively`

##### [onboard.go:146](cmd/notenv/onboard.go#L146) — MED > AGREE
- **Current:** `your key slot still holds the temporary onboarding passphrase, and replacing it is a header write, but %s. Onboard once with a write-capable storage credential, then switch back`
- **Issue:** "replacing it is a header write" exposes internals.
- **Suggest:** `your key slot still holds the temporary onboarding passphrase; replacing it requires writing to storage, but %s. Onboard once with a write-capable credential, then switch back`

#### init (cmd_init.go)

##### [cmd_init.go:183](cmd/notenv/cmd_init.go#L183) — MED > AGREE
- **Current:** `wrote ./%s (namespace %q). Commit this; it's the secret *contract*, no values`
- **Issue:** `*contract*` renders literal asterisks in a terminal (other lines use `ui.Bold`).
- **Suggest:** `wrote ./%s (namespace %q). Commit it: it declares the contract, with no secret values` (use `ui.Bold` if you want emphasis).

##### [cmd_init.go:167](cmd/notenv/cmd_init.go#L167) — MED > AGREE, BUT VERIFY
- **Current:** `namespace %q must match %s`
- **Issue:** Dumps a raw regex at the user, unlike the prose rule used for storage names (cmd_setup.go:349).
- **Suggest:** Describe in words: `namespace %q may use only letters, digits, '-' or '_'` (verify against the actual pattern).

##### [cmd_init.go:115](cmd/notenv/cmd_init.go#L115) — MED > AGREE
- **Current:** `found existing secrets for namespace %q; you're ready: ` + "`notenv run -- <cmd>`" + ` (it will ask for your escrowed passphrase)`
- **Issue:** "escrowed passphrase" is jargon; users just think "my passphrase".
- **Suggest:** `...(it will ask for your vault passphrase)`

##### [cmd_init.go:101](cmd/notenv/cmd_init.go#L101) — LOW > AGREE
- **Current:** `re-pinning this checkout from namespace %q to %q`
- **Issue:** "checkout" and "re-pinning" are internal terms.
- **Suggest:** `switching this project from namespace %q to %q`

##### [cmd_init.go:37](cmd/notenv/cmd_init.go#L37) — LOW > AGREE
- **Current:** `Set up notenv for this project (chains into machine setup on first run)`
- **Issue:** "chains into" is dev phrasing for help text.
- **Suggest:** `Set up notenv for this project (also runs machine setup the first time)`

### Key & identity

#### [cmd_key.go:104](cmd/notenv/cmd_key.go#L104) — MED > AGREE
- **Current:** `this storage previously held vault %s but now presents vault %s: the vault was replaced wholesale. If you deliberately re-initialized it, run ` + "`notenv key forget`" + ` and connect again; otherwise treat the storage as compromised`
- **Issue:** "connect again" names no real command; master.go:96 says "set up again".
- **Suggest:** Replace "and connect again" with "and set up again".

#### [cmd_key.go:97](cmd/notenv/cmd_key.go#L97) — MED > AGREE
- **Current:** `%w; refusing to use this vault`
- **Issue:** Header verification failure with no next step.
- **Suggest:** Add guidance, e.g. `%w; refusing to use this vault. If a teammate changed it legitimately, run `notenv key trust`; otherwise treat the storage as compromised`

#### [cmd_key.go:939](cmd/notenv/cmd_key.go#L939) — MED > AGREE
- **Current:** `Rewrite a namespace whose current blob is unreadable from what survives (acknowledged data loss)`
- **Issue:** Short help is hard to parse ("unreadable from what survives" reads as one phrase).
- **Suggest:** `Repair a namespace with an unreadable blob by rewriting it from what survives (accepts data loss)`

#### [cmd_key.go:606](cmd/notenv/cmd_key.go#L606) — MED > AGREE
- **Current:** `it is their first passphrase plus a code that proves they reached this vault and not a substitute; their first notenv command makes them replace the passphrase with one only they know. Until then ` + "`notenv key list`" + ` shows the slot as provisional`
- **Issue:** One status line packing three ideas; dense.
- **Suggest:** `it bundles their first passphrase with a code proving they reached the real vault. Their first notenv command replaces the passphrase with one only they know; until then `notenv key list` shows the slot as provisional`

#### [cmd_key.go:767](cmd/notenv/cmd_key.go#L767) — LOW > DISAGREE, KEEP
- **Current:** `...rotate this vault's storage credential at the provider so the removed holder can't read or write the bucket`
- **Issue:** "the bucket" assumes cloud; inaccurate for local storage.
- **Suggest:** `...can't read or write the storage`

#### [cmd_key.go:787](cmd/notenv/cmd_key.go#L787) — LOW > AGREE
- **Current:** `more than one slot matches %q; remove it by index instead`
- **Issue:** Shared resolver also serves `set-primary`, so "remove" is wrong there.
- **Suggest:** `more than one slot matches %q; select it by index instead`

#### [cmd_key.go:973](cmd/notenv/cmd_key.go#L973) — LOW > AGREE
- **Current:** `untrustable blob %s: %s`
- **Issue:** "untrustable" is non-standard; surrounding evict text uses "corrupt"/"unreadable".
- **Suggest:** `unreadable blob %s: %s`

#### [identity.go:60](cmd/notenv/identity.go#L60) — LOW > AGREE
- **Current:** `%s holds no X25519 identity usable for vault creation`
- **Issue:** States the problem, not the fix.
- **Suggest:** `%s holds no X25519 identity usable for vault creation; set it to an AGE-SECRET-KEY-1... value or a file containing one`

#### [namespace_guard.go:155](cmd/notenv/namespace_guard.go#L155) — LOW > AGREE
- **Current:** `could not pin namespace %q in %s: %v (the contract-change guard stays off for this checkout)`
- **Issue:** "contract-change guard" / "checkout" jargon.
- **Suggest:** `...(notenv won't detect later contract changes for this project)`

### Secrets CRUD

#### [cmd_edit.go:305](cmd/notenv/cmd_edit.go#L305) — MED > AGREE
- **Current:** `%s is %s but holds no value yet; give it one (a literal %s value is not storable)`
- **Issue:** With the sentinel substituted twice plus "not storable", this is confusing for a new key.
- **Suggest:** `%s is new but its value is still %s; replace %s with the value you want to store`

#### [cmd_edit.go:70](cmd/notenv/cmd_edit.go#L70) — MED > AGREE
- **Current:** `namespace %q has secret(s) %s whose value has surrounding whitespace or spans multiple lines, which edit cannot represent; change them with ` + "`notenv set <KEY> --stdin`" + ` (or ` + "`notenv unset <KEY>`" + `), then edit the rest`
- **Issue:** One very long sentence with awkward "secret(s) ... whose value has" for plurals.
- **Suggest:** `edit cannot represent these secrets in namespace %q (their values have surrounding whitespace or span multiple lines): %s. Set them with `notenv set <KEY> --stdin` (or remove with `notenv unset <KEY>`), then edit the rest`

#### [cmd_edit.go:394](cmd/notenv/cmd_edit.go#L394) — MED > AGREE
- **Current:** `%s changed on another machine while you were editing; nothing was written. Re-run ` + "`notenv edit`" + ` to pick up the new state`
- **Issue:** When `%s` is a list of keys, singular "changed" and mid-sentence "while you were editing" read oddly.
- **Suggest:** `these keys changed on another machine while you were editing: %s. Nothing was written; re-run `notenv edit` to pick up the new state`

#### [cmd_import.go:93](cmd/notenv/cmd_import.go#L93) — MED > AGREE
- **Current:** `not valid environment variable names: %s (nothing was imported)`
- **Issue:** Subjectless fragment; inconsistent with set/unset's "%q is not a valid environment variable name".
- **Suggest:** `these are not valid environment variable names: %s (nothing was imported)`

#### [cmd_import.go:108](cmd/notenv/cmd_import.go#L108), [:169](cmd/notenv/cmd_import.go#L169), [:171](cmd/notenv/cmd_import.go#L171) — LOW > AGREE
- **Current:** `... %d secrets ...`
- **Issue:** No plural guard, prints "1 secrets". (Verified in source.)
- **Suggest:** Use `%d secret(s)`.

#### [cmd_export.go:119](cmd/notenv/cmd_export.go#L119) — MED > AGREE
- **Current:** `%s requires the vault's primary passphrase; the slot you unlocked is not primary`
- **Issue:** States the constraint, not the fix.
- **Suggest:** `%s requires the vault's primary passphrase; you unlocked a non-primary slot, so re-run and unlock with the primary passphrase`

#### [cmd_inspect.go:197](cmd/notenv/cmd_inspect.go#L197) — MED > AGREE
- **Current:** `no vault found at storage %q`
- **Issue:** No next step.
- **Suggest:** `no vault found at storage %q; create one with `notenv init`` (verify the correct bootstrap command).

#### [cmd_export.go:30](cmd/notenv/cmd_export.go#L30) — LOW > AGREE
- **Current:** `Print secrets as .env to stdout, for leaving notenv (never writes a file)`
- **Issue:** "for leaving notenv" is ambiguous.
- **Suggest:** `Print secrets as .env to stdout for backup or offboarding (never writes a file)`

#### [cmd_export.go:143](cmd/notenv/cmd_export.go#L143) — LOW > AGREE
- **Current:** `stdout is a terminal, so these values are now in your scroll-back; redirect to a file or pipe if that matters` 
- **Issue:** "scroll-back" is usually "scrollback".
- **Suggest:** `...now in your scrollback;...`

#### [cmd_set.go:26](cmd/notenv/cmd_set.go#L26) — LOW > AGREE
- **Current:** `Set a secret value (prompted hidden, encrypted, uploaded; never echoed, never on disk)`
- **Issue:** Dense parenthetical; "prompted hidden" reads awkwardly.
- **Suggest:** `Set a secret value (entered hidden, encrypted, never echoed or written to disk)`

#### [cmd_set.go:34](cmd/notenv/cmd_set.go#L34) (and unset) — LOW > AGREE
- **Current:** `%q is not a valid environment variable name`
- **Issue:** Doesn't state the rule. (Consistent across set/unset, which is good; import diverges, see above.)
- **Suggest:** `%q is not a valid environment variable name (use letters, digits, and underscores; cannot start with a digit)`

#### [cmd_list.go:109](cmd/notenv/cmd_list.go#L109), [cmd_run.go:142](cmd/notenv/cmd_run.go#L142) — MED > AGREE
- **Current:** `fall back to a namespace's one-generation backup when its current blob is missing or corrupt, instead of failing closed (the most recent write may be lost; it is reported)`
- **Issue:** Flag help should be scannable; "one-generation backup", "blob", "failing closed" are jargon.
- **Suggest:** `use the previous backup when the current data is missing or corrupt, instead of stopping (the most recent change may be lost; notenv will tell you if so)`

### Run, handoff, vault, session

#### [cmd_handoff.go:113](cmd/notenv/cmd_handoff.go#L113) — MED > AGREE
- **Current:** `could not take a no-cache lease on the source vault (%v); avoid unlocking it elsewhere during this session`
- **Issue:** "no-cache lease" is opaque; alarming without explaining the real risk.
- **Suggest:** `couldn't fully isolate this session (%v); to be safe, don't unlock your main vault in another terminal while the agent is running`

#### [cmd_handoff_build.go:118](cmd/notenv/cmd_handoff_build.go#L118) — MED > AGREE
- **Current:** `handoff needs a passphrase-gated source, but the %s identity unlocks this vault: the agent runs as you and could replay it to reach your real vault. Unset %s for the handoff, or hand off from a passphrase-gated vault`
- **Issue:** Jargon-stacked and dense; also capitalizes "Unset" mid-error after a colon (inconsistent).
- **Suggest:** `handoff won't use a vault that your %s identity can unlock, because the agent runs as you and could reuse that identity to open your real vault. Either unset %s before handing off, or hand off from a passphrase-protected vault`

#### [cmd_handoff_build.go:87](cmd/notenv/cmd_handoff_build.go#L87) — MED > AGREE
- **Current:** `none of the handed-off namespaces (%s) hold any secrets`
- **Issue:** No fix. (This builder's stderr surfaces to the user.)
- **Suggest:** `the namespace(s) you handed off (%s) hold no secrets, so there's nothing to give the agent; add secrets with `notenv set` first`

#### [cmd_vault.go:299](cmd/notenv/cmd_vault.go#L299) — MED > AGREE
- **Current:** `Gated by the vault's primary passphrase, notenv only ever destroys a vault you can prove you own, plus a type-the-name confirmation.`
- **Issue:** Comma-splice / misplaced modifier; doesn't parse cleanly.
- **Suggest:** `Deletion requires the vault's primary passphrase plus typing the name to confirm, so notenv only destroys a vault you can prove you own.`

#### [cmd_vault.go:338](cmd/notenv/cmd_vault.go#L338) — MED > AGREE
- **Current:** `permanently deleting vault %s on storage %q (%d objects). notenv removes the live vault; a versioned remote's history and your backups are the provider's to purge`
- **Issue:** Two sentences crammed into one warning; "%d objects" jargon.
- **Suggest:** `about to permanently delete vault %s on storage %q. This removes the live vault only; a versioned remote's history and your own backups are yours to purge separately`

#### [cmd_vault.go:294](cmd/notenv/cmd_vault.go#L294) — LOW > AGREE
- **Current:** `Permanently delete a vault: its objects, this machine's trust state, and its config entry`
- **Issue:** "objects"/"trust state" jargon in a Short help line.
- **Suggest:** `Permanently delete a vault, its data, and this machine's record of it`

#### [cmd_vault.go:50](cmd/notenv/cmd_vault.go#L50) — MED > AGREE
- **Current:** `NOTENV_READONLY is set; refusing to copy: a vault copy writes a full vault to the destination`
- **Issue:** Slightly circular; doesn't say to unset the var.
- **Suggest:** `NOTENV_READONLY is set, which blocks all writes; copy writes a full vault to the destination, so unset NOTENV_READONLY to proceed`

#### [cmd_vault.go:34](cmd/notenv/cmd_vault.go#L34) — LOW > AGREE
- **Current:** `Replicate this vault to new storage (the local→cloud ramp) and register it`
- **Issue:** "(the local→cloud ramp)" is insider shorthand; arrow reads oddly in help columns.
- **Suggest:** `Copy this vault to new storage (e.g. local to cloud) and register it`

#### [session.go:41](cmd/notenv/session.go#L41) — MED > AGREE
- **Current:** `this is a notenv handoff session scoped to one ephemeral vault; refusing to unlock a different vault (point NOTENV_STORAGE at the handed-off vault, or run this outside the session)`
- **Issue:** Actionable (good) but dense; lead clause is the least useful part.
- **Suggest:** `you're inside a notenv handoff session, which can only open the vault it was handed; refusing to unlock a different one (point NOTENV_STORAGE at the handed-off vault, or run this command outside the handoff)`

#### [cmd_run.go:27](cmd/notenv/cmd_run.go#L27) (Long) — LOW > AGREE
- **Current:** Long block opening with "the contract's secrets" then a dense ~14-line paragraph.
- **Issue:** "contract" is undefined jargon here (the Short line says "secrets"); the masking caveats are buried in one paragraph.
- **Suggest:** Use "this project's secrets", and split masking / `--mask` / `--no-mask` / short-value notes into a separate paragraph.

#### [cmd_run.go:131](cmd/notenv/cmd_run.go#L131) — LOW > AGREE
- **Current:** `flush masked output: %v`
- **Issue:** Reads like an internal op name, not what went wrong.
- **Suggest:** `could not finish writing masked output: %v`

### Doctor, cache, version, root

#### [cmd_doctor.go:98](cmd/notenv/cmd_doctor.go#L98) — MED > AGREE
- **Current:** `no key header, but this machine pinned vault %s at this storage: the vault may have been wiped or replaced. Restore it (` + "`notenv key restore-backup`" + `, or the remote's version history), or, ONLY if you deliberately reset this storage, ` + "`notenv key forget`"
- **Issue:** Run-on with a comma pile-up ("or, ONLY ..., `notenv key forget`").
- **Suggest:** Split the deliberate-reset case into its own sentence: `...Restore it with `notenv key restore-backup` (or the remote's version history). If you reset this storage on purpose, run `notenv key forget``

#### [cmd_doctor.go:128](cmd/notenv/cmd_doctor.go#L128) / [:133](cmd/notenv/cmd_doctor.go#L133) — MED > AGREE
- **Current:** `...; the object checks below check presence against the unverified manifest, not content`
- **Issue:** "checks below check" repetition; :133 also offers no next step for an unreadable cached key.
- **Suggest:** `...The object checks below confirm presence only, against the unverified manifest, not content` (for :133 add `try `notenv cache clear` then unlock again`).

#### [cmd_doctor.go:42](cmd/notenv/cmd_doctor.go#L42) — MED > AGREE
- **Current:** `%d finding(s); the lines above say how to proceed`
- **Issue:** Wordy/stilted.
- **Suggest:** `%d finding(s) above; each says how to fix it`

#### [cmd_doctor.go:137](cmd/notenv/cmd_doctor.go#L137) — LOW > AGREE
- **Current:** `header FAILED authentication under the session key: %v. ...`
- **Issue:** All-caps "FAILED" is shouty; the `ui.Warnf` styling already signals severity.
- **Suggest:** lowercase "failed".

#### [cmd_doctor.go:20](cmd/notenv/cmd_doctor.go#L20) — LOW > AGREE
- **Current:** `Check a storage for known problem states and say how to fix them`
- **Issue:** "a storage" reads awkwardly; slightly wordy.
- **Suggest:** `Check storage for known problems and how to fix them`

#### [root.go:14](cmd/notenv/root.go#L14) — LOW > DISAGREE
- **Current:** `...secrets are encrypted on your machine with age, stored on storage you already own (any rclone remote)...`
- **Issue:** "stored on storage" repetition.
- **Suggest:** `...stored on a backend you already own (any rclone remote)...`

#### [root.go:64](cmd/notenv/root.go#L64) — LOW > AGREE
- **Current:** `address this vault namespace directly, ignoring any project contract (works from anywhere)`
- **Issue:** "project contract" jargon in flag help.
- **Suggest:** `address a vault namespace directly, ignoring the project binding (works from any directory)`

### Internal packages (user-visible errors)

#### [header.go:367](internal/crypto/header.go#L367) — HIGH > AGREE
- **Current:** `%w: a slot's passphrase matched but its key does not open the vault master (a tampered or half-rotated header)` wrapping `ErrWrongPassphrase` ("wrong passphrase")
- **Issue:** Composed message is self-contradictory: "wrong passphrase: a slot's passphrase matched...". Heavy jargon.
- **Suggest:** `the passphrase was accepted but cannot unlock the vault key (the header may be tampered with or only partly rotated); recover with `notenv key restore-backup`` (and don't wrap `ErrWrongPassphrase` here).

#### [header.go:495](internal/crypto/header.go#L495) — HIGH > AGREE
- **Current:** `%w. Was this storage re-initialized or re-keyed? Re-create the value with `notenv set`` wrapping `ErrNotRecipient` ("blob was not encrypted under the current master key")
- **Issue:** Composed message leads with jargon ("blob ... master key") then a capitalized question; reads disjointed.
- **Suggest:** Soften the sentinel to e.g. "this secret was encrypted under a different key" so the whole reads: `this secret was encrypted under a different key. Was the storage re-initialized or re-keyed? Re-create the value with notenv set`

#### [config.go:287](internal/config/config.go#L287) — HIGH (factual staleness) > AGREE
- **Current:** `# cache_ttl = "1h"   # master-key cache lifetime (Linux kernel keyring); "0" disables`
- **Issue:** Cache now works on macOS/Windows too; this ships in every generated config and misleads non-Linux users.
- **Suggest:** `# master-key cache lifetime (OS keystore: kernel keyring / Keychain / DPAPI); "0" disables`

#### [auth.go:54](internal/crypto/auth.go#L54) — MED > AGREE
- **Current:** `header authentication failed (tampered, or wrong master key)`
- **Issue:** "header authentication failed" is internal; no recovery hint for a scary, hittable error.
- **Suggest:** `vault header failed verification: it was tampered with, or unlocked with the wrong key` (consider a restore-backup hint).

#### [manifest.go:92](internal/crypto/manifest.go#L92) — MED > AGREE
- **Current:** `blob does not match the vault manifest (reverted or substituted?)`
- **Issue:** "blob" jargon; trailing "?" reads tentative for a security alarm.
- **Suggest:** `stored secret does not match the vault manifest: it may have been reverted or substituted`

#### [config.go:619](internal/config/config.go#L619) — LOW > AGREE
- **Current:** `unsupported crypto mode %q (MVP supports %q)`
- **Issue:** "MVP" leaks project-phase vocabulary.
- **Suggest:** `unsupported crypto mode %q (only %q is supported)`

#### [secrets.go:515](internal/secrets/secrets.go#L515) — LOW > AGREE
- **Current:** `blob %s read back corrupted; write not recorded`
- **Issue:** "blob" jargon (reassuring tone otherwise good).
- **Suggest:** `value %s read back corrupted after write; the change was not recorded`

#### [secrets.go:247](internal/secrets/secrets.go#L247) — LOW > AGREE
- **Current:** `...format v%d, this build understands v%d); upgrade notenv`
- **Issue:** "this build" vs "this version of notenv" elsewhere (drift).
- **Suggest:** `...this version of notenv understands v%d); upgrade notenv`

#### [keyring.go:52](internal/keyring/keyring.go#L52) — LOW > AGREE
- **Current:** `no terminal available for hidden prompt`
- **Issue:** "hidden prompt" jargon; no next step.
- **Suggest:** `no terminal available to read a passphrase (run notenv from an interactive shell, or pipe the value in)`

#### [keyring.go:104](internal/keyring/keyring.go#L104) — LOW > AGREE
- **Current:** `empty passphrase`
- **Issue:** States a fact, not what to do.
- **Suggest:** `passphrase cannot be empty`

#### [prompt.go:25](internal/ui/prompt.go#L25) — LOW > AGREE
- **Current:** `interactive prompt needs a terminal (or pass the value via flags)`
- **Issue:** "via flags" gives no handle (which flag?).
- **Suggest:** `interactive prompt needs a terminal; pass the value with a flag instead`

---

## What's working well (keep as the model)

- **`doctor` problem lines** consistently state problem + consequence ("reads fail closed") + a concrete fix command. This is the standard the other commands should match.
- **`internal/config` and `internal/contract` errors** name the problem, the file, and the exact command to run (`notenv setup --name`, `notenv init`, `--storage`, `--force`).
- **The strongest security warnings** (rotate-master partial-revocation at cmd_key.go:762, master.go:96/120/152) are accurate, actionable, and not gratuitously scary.
- **The `(never values)` parenthetical** on `list`/`inspect` is a clean, consistent convention worth copying.
- **Destructive flows** (vault delete, key forget/trust/evict) all gate on confirmation with clear `--yes`/`--force` escape hatches and show what is being traded.
