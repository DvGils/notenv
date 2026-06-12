package main

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check a storage for known problem states and say how to fix them",
	Long: `Inspect a storage read-only and report anything in a known problem state,
with the way out for each: a vanished or unreadable header, a pending
rollback alarm, unfinished onboarding, objects a crashed write left
unrecorded, recorded objects that are missing.

doctor never fixes, writes, or prompts. With a session key cached it also
verifies the header's authentication tag; without one it says so and reads
the header unverified. Exit code 0 means no findings, 1 means look above.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		c := &checkup{}
		runDoctor(cmd, store, c)
		if c.problems == 0 {
			ui.Successf("no findings")
			return nil
		}
		ui.Warnf("%d finding(s); the lines above say how to proceed", c.problems)
		return &exitCodeError{code: 1}
	},
}

// checkup counts findings; output goes straight to ui so each check reports
// in place.
type checkup struct{ problems int }

func (c *checkup) ok(format string, a ...any)      { ui.Successf(format, a...) }
func (c *checkup) note(format string, a ...any)    { ui.Notef(format, a...) }
func (c *checkup) problem(format string, a ...any) { c.problems++; ui.Warnf(format, a...) }

func runDoctor(cmd *cobra.Command, store *headerTarget, c *checkup) {
	ctx := cmd.Context()
	if store.readOnly != "" {
		c.note("writes are refused here: %s", store.readOnly)
	}
	if err := store.Preflight(ctx); err != nil {
		c.problem("storage unreachable: %v", err)
		return
	}

	raw, err := store.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		if vaultID, bound, _ := config.ScopeVault(store.scope); bound {
			c.problem("no key header, but this machine pinned vault %s at this storage: the vault may have been wiped or replaced. Restore it (`notenv key restore-backup`, or the remote's version history), or, ONLY if you deliberately reset this storage, `notenv key forget`", vaultID)
		} else {
			c.note("no vault on this storage yet; `notenv setup` creates one")
		}
		return
	}
	if err != nil {
		c.problem("read key header: %v", err)
		return
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		c.problem("%v", err)
		return
	}
	c.ok("header present and well-formed (vault %s, revision %d)", header.VaultID, header.Revision)

	verified := verifyWithSessionKey(c, store.scope, header)
	checkPin(c, store.scope, header)
	checkSlots(c, header)
	checkObjects(cmd, store, c, header, verified)
}

// verifyWithSessionKey authenticates the header when (and only when) a
// session key is already cached: doctor never prompts, so a cold cache just
// reports the limitation.
func verifyWithSessionKey(c *checkup, scope string, header *crypto.Header) bool {
	cached, hit := keyring.DefaultCache().Get(scope)
	if !hit {
		c.note("header not verified: no session key cached (any unlock verifies it); the object checks below trust the unverified manifest")
		return false
	}
	mk, err := crypto.ParseMasterKey(cached)
	if err != nil {
		c.note("header not verified: the cached session key is unreadable; the object checks below trust the unverified manifest")
		return false
	}
	if err := header.Verify(mk); err != nil {
		c.problem("header FAILED authentication under the session key: %v. If the vault was re-keyed elsewhere this is a stale cache (`notenv cache clear`, then unlock again); otherwise treat the storage as tampered", err)
		return false
	}
	c.ok("header authenticates under the cached session key")
	return true
}

// checkPin compares the local trust state against the served header: a bound
// scope must present the same vault, and the revision must not have moved
// backward past what this machine already saw.
func checkPin(c *checkup, scope string, header *crypto.Header) {
	boundVault, bound, err := config.ScopeVault(scope)
	if err != nil {
		c.problem("read local trust state: %v", err)
		return
	}
	if !bound {
		c.note("no vault bound at this storage yet; the first unlock records the trust anchor")
		return
	}
	if boundVault != header.VaultID {
		c.problem("this storage previously held vault %s but now presents vault %s: a wholesale replacement. If deliberate, `notenv key forget` and connect again; otherwise treat the storage as compromised", boundVault, header.VaultID)
		return
	}
	pin, have, err := config.ReadPin(header.VaultID)
	if err != nil {
		c.problem("read rollback pin: %v", err)
		return
	}
	if !have {
		c.note("no rollback pin recorded yet; the first unlock records one")
		return
	}
	if header.Revision < pin.Revision {
		c.problem("the header is at revision %d but this machine already saw revision %d: a rollback. The next unlock will refuse; `notenv key trust` accepts it ONLY after out-of-band verification", header.Revision, pin.Revision)
		return
	}
	c.ok("revision %d is at or past this machine's pin (%d)", header.Revision, pin.Revision)
}

// checkSlots reports unfinished onboarding: provisional slots whose holders
// never replaced the temporary passphrase.
func checkSlots(c *checkup, header *crypto.Header) {
	humans, machines := 0, 0
	for _, slot := range header.Slots {
		if slot.Type == crypto.SlotRecipient {
			machines++
			continue
		}
		humans++
		if !slot.Provisional {
			continue
		}
		age := 0
		if slot.TS > 0 {
			age = int(time.Since(time.Unix(slot.TS, 0)).Hours() / 24)
		}
		if age >= 7 {
			c.problem("slot %q has been provisional for %d days: the holder never replaced the onboarding passphrase, so its issuer still knows their credential. Resend the onboarding string, or `notenv key rm` the slot", dashIfEmpty(slot.Name), age)
		} else {
			c.note("slot %q is provisional: onboarding is not finished until its holder runs a notenv command and sets their own passphrase", dashIfEmpty(slot.Name))
		}
	}
	c.ok("%d slot(s): %d human, %d machine", len(header.Slots), humans, machines)
}

// checkObjects diffs the storage listing against the header manifest in both
// directions: an unrecorded object is a crashed write (or something put
// back); a recorded-but-missing object will fail the next fold closed.
func checkObjects(cmd *cobra.Command, store *headerTarget, c *checkup, header *crypto.Header, verified bool) {
	keys, err := store.List(cmd.Context(), "")
	if err != nil {
		c.problem("list storage objects: %v", err)
		return
	}
	present := make(map[string]bool, len(keys))
	for _, k := range keys {
		present[k] = true
	}
	unrecorded, missing := 0, 0
	for _, k := range keys {
		if _, ok := header.Manifest[k]; !ok {
			unrecorded++
			c.problem("object %s is not recorded in the vault manifest: a write that crashed mid-protocol, or something put back after deletion. Folds include it with a warning and the next compaction records it; if a master rotation happened since it was written, the fold fails closed naming it, and the fix is to delete it and re-set that key", k)
		}
	}
	for k := range header.Manifest {
		if !present[k] {
			missing++
			c.problem("object %s is recorded in the vault manifest but missing from storage: reads will fail closed naming it. Recover it from the remote's version history, or compact to rebuild from what survives", k)
		}
	}
	if unrecorded == 0 && missing == 0 {
		suffix := ""
		if !verified {
			suffix = " (manifest unverified; see above)"
		}
		c.ok("%d object(s), every one recorded in the manifest, none missing%s", len(keys), suffix)
	}
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
