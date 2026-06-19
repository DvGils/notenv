package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check storage for known problems and how to fix them",
	Long: `Inspect a storage read-only and report anything in a known problem state,
with the way out for each: a vanished or unreadable header, a pending
rollback alarm, unfinished onboarding, a namespace blob that is missing or
corrupt, and orphan blobs a crashed write left behind (the next write to that
namespace reclaims them).

doctor never fixes, writes, or prompts. With a session key cached it also
verifies the header's authentication tag; without one it says so and reads
the header unverified. Exit code 0 means no findings, 1 means look above.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		c := &checkup{print: true}
		runDoctor(cmd, store, c)
		if c.problems == 0 {
			ui.Successf("no findings")
			return nil
		}
		ui.Warnf("%d finding(s) above; each says how to fix it", c.problems)
		return &exitCodeError{code: 1}
	},
}

// finding is one checkup line: level "ok", "note", or "problem", and the
// text that says what and, for problems, the way out.
type finding struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// checkup collects findings; with print set, each check also reports in
// place through ui (the CLI experience), otherwise it only accumulates them.
type checkup struct {
	print    bool
	problems int
	findings []finding
}

func (c *checkup) emit(level, format string, a ...any) {
	text := fmt.Sprintf(format, a...)
	c.findings = append(c.findings, finding{Level: level, Text: text})
	if !c.print {
		return
	}
	switch level {
	case "ok":
		ui.Successf("%s", text)
	case "note":
		ui.Notef("%s", text)
	default:
		ui.Warnf("%s", text)
	}
}

func (c *checkup) ok(format string, a ...any)   { c.emit("ok", format, a...) }
func (c *checkup) note(format string, a ...any) { c.emit("note", format, a...) }
func (c *checkup) problem(format string, a ...any) {
	c.problems++
	c.emit("problem", format, a...)
}

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
			c.problem("no key header, but this machine pinned vault %s at this storage: the vault may have been wiped or replaced. Restore it with `notenv key restore-backup` (or the remote's version history). If you reset this storage on purpose, run `notenv key forget`", vaultID)
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

	mk, _ := verifyWithSessionKey(c, store.cache, store.scope, header)
	checkPin(c, store.scope, header)
	checkSlots(c, header)
	checkBlobs(cmd, store, c, header, mk)
}

// verifyWithSessionKey authenticates the header when (and only when) a session
// key is already cached: doctor never prompts, so a cold cache just reports the
// limitation. It returns the master only when the header authenticates under it,
// so callers can use it to verify object content too.
func verifyWithSessionKey(c *checkup, cache keyring.Cache, scope string, header *crypto.Header) (*crypto.MasterKey, bool) {
	// Inside a handoff session, never read the warm master of a vault other than the
	// handed-off one: doing so would verify and decrypt a foreign vault's blobs from
	// cache, the warm-path bypass the session guard exists to stop. doctor never
	// prompts, so this degrades to the same unverified-header report as a cold cache.
	if err := sessionGuard(scope); err != nil {
		c.note("header not verified: inside a notenv handoff session, doctor won't touch another vault's cached key. The object checks below confirm presence only, against the unverified manifest, not content")
		return nil, false
	}
	cached, hit := cache.Get(scope)
	if !hit {
		c.note("header not verified: no session key cached (any unlock verifies it). The object checks below confirm presence only, against the unverified manifest, not content")
		return nil, false
	}
	mk, err := crypto.ParseMasterKey(cached)
	if err != nil {
		c.note("header not verified: the cached session key is unreadable (try `notenv cache clear` then unlock again). The object checks below confirm presence only, against the unverified manifest, not content")
		return nil, false
	}
	if err := header.Verify(mk); err != nil {
		c.problem("header failed authentication under the session key: %v. If the vault was re-keyed elsewhere this is a stale cache (`notenv cache clear`, then unlock again); otherwise treat the storage as tampered", err)
		return nil, false
	}
	c.ok("header authenticates under the cached session key")
	return mk, true
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

// checkBlobs diffs the storage listing against the header manifest and, when a
// session master is available, verifies each namespace's current blob the way a
// read would: a recorded blob that is missing, that does not decrypt, or that
// fails its manifest MAC is exactly what fails a read closed. The
// one-generation backup is checked too, but a bad backup is a degraded-recovery
// note, not a fail-closed problem (it is never served on the happy path). A
// stored object no manifest entry references is an orphan from a crashed write:
// harmless to reads, offered for cleanup. With a master this reads and decrypts
// every current blob, the same cost as a read; without one it can only check
// presence.
func checkBlobs(cmd *cobra.Command, store *headerTarget, c *checkup, header *crypto.Header, mk *crypto.MasterKey) {
	ctx := cmd.Context()
	keys, err := store.List(ctx, "")
	if err != nil {
		c.problem("list storage objects: %v", err)
		return
	}
	present := make(map[string]bool, len(keys))
	for _, k := range keys {
		present[k] = true
	}
	referenced := referencedBlobs(header)
	orphans := 0
	for _, k := range keys {
		if !referenced[k] {
			orphans++
			c.note("object %s is not referenced by the vault manifest: an orphan from a write that crashed before recording it. It is never read, and the next write to its namespace reclaims it", k)
		}
	}
	missing, corrupt := checkNamespaceBlobs(ctx, store, c, header, mk, present)
	if orphans == 0 && missing == 0 && corrupt == 0 {
		if mk != nil {
			c.ok("%d namespace blob(s), all present and matching their manifest MAC", len(header.Manifest))
		} else {
			c.ok("%d namespace blob(s), all present (content unverified: no session key)", len(header.Manifest))
		}
	}
}

// checkNamespaceBlobs verifies each namespace's current blob (and notes a
// missing or corrupt backup), returning how many were missing or corrupt.
func checkNamespaceBlobs(ctx context.Context, store *headerTarget, c *checkup, header *crypto.Header, mk *crypto.MasterKey, present map[string]bool) (missing, corrupt int) {
	for _, ns := range vaultNamespaces(header) {
		e := header.Manifest[ns]
		switch {
		case !present[e.Blob]:
			missing++
			c.problem("namespace %q blob %s is recorded in the vault manifest but missing from storage: reads fail closed. Read what survives (its one-generation backup) with `notenv run --skip-corrupt`, or `notenv key evict %s` to rewrite the namespace from what survives", ns, e.Blob, ns)
		case mk == nil:
			// no session master: cannot check content; the header note already says so
		case verifyNamespaceBlob(ctx, store, c, ns, e.Blob, e.MAC, mk):
			corrupt++
		default:
			// Present, verified under the master, not corrupt: the only remaining
			// thing worth surfacing is an empty namespace (persistence keeps these
			// around, so they can accumulate).
			noteEmptyNamespace(ctx, store, c, ns, e, mk)
		}
		if e.Prev != "" && mk != nil {
			checkNamespaceBackup(ctx, store, c, ns, e, present, mk)
		}
	}
	return missing, corrupt
}

// verifyNamespaceBlob checks one namespace's current blob the way a read would:
// it must decrypt under the master and match its manifest MAC. It reports true
// only when the blob is genuinely corrupt (a read will fail closed on it); a
// transient read error is surfaced but not counted as corruption.
func verifyNamespaceBlob(ctx context.Context, store *headerTarget, c *checkup, ns, key, mac string, mk *crypto.MasterKey) bool {
	blob, err := store.Get(ctx, key)
	if err != nil {
		c.problem("namespace %q blob %s could not be read for verification: %v", ns, key, err)
		return false
	}
	plain, err := mk.Decrypt(blob)
	if err != nil {
		c.problem("namespace %q blob %s does not decrypt under the master (bit-rot or tampering): reads fail closed. Read its one-generation backup with `notenv run --skip-corrupt`, or `notenv key evict %s` to rewrite the namespace from what survives", ns, key, ns)
		return true
	}
	if err := mk.CheckBlobMAC(plain, mac); err != nil {
		c.problem("namespace %q blob %s does not match its manifest MAC (reverted or substituted): reads fail closed. Read its one-generation backup with `notenv run --skip-corrupt`, or `notenv key evict %s` to rewrite the namespace", ns, key, ns)
		return true
	}
	return false
}

// noteEmptyNamespace flags a namespace that verifies cleanly but holds no
// secrets. A persistent namespace (kept after its last secret is removed, or
// stood up empty with `namespace create`) is the one cost of persistence: these
// can accumulate, so doctor surfaces them with the way to remove one. It needs
// the master to decode the blob, so it runs only on the verified path; without a
// session key an empty namespace is indistinguishable from a populated one.
func noteEmptyNamespace(ctx context.Context, store *headerTarget, c *checkup, ns string, e crypto.ManifestEntry, mk *crypto.MasterKey) {
	state, err := secrets.For(store, ns, mk).Read(ctx, e)
	if err != nil {
		// verifyNamespaceBlob already checked decrypt + MAC (and surfaced those
		// failures), so the only error reaching here is one it does not cover: a
		// payload that does not parse (e.g. a stranded older-format blob, which a v3
		// vault should not hold). A real read fails loudly on it; this is only the
		// empty-namespace note helper, so skip rather than double-report.
		return
	}
	if len(state.Secrets) == 0 {
		c.note("namespace %q holds no secrets (it persists empty). Remove it with `notenv namespace delete %s` if it is no longer needed", ns, ns)
	}
}

// checkNamespaceBackup verifies a namespace's one-generation backup blob. A
// missing or corrupt backup only narrows recovery (it is never served on the
// happy path), so it is a note, not a fail-closed problem.
func checkNamespaceBackup(ctx context.Context, store *headerTarget, c *checkup, ns string, e crypto.ManifestEntry, present map[string]bool, mk *crypto.MasterKey) {
	if !present[e.Prev] {
		c.note("namespace %q backup blob %s is missing: recovery from a corrupt current blob is no longer possible until the next write re-establishes a backup", ns, e.Prev)
		return
	}
	blob, err := store.Get(ctx, e.Prev)
	if err != nil {
		return // transient read error: not the backup's fault
	}
	plain, err := mk.Decrypt(blob)
	if err != nil || mk.CheckBlobMAC(plain, e.PrevMAC) != nil {
		c.note("namespace %q backup blob %s is corrupt: recovery from a corrupt current blob is no longer possible until the next write re-establishes a backup", ns, e.Prev)
	}
}

// referencedBlobs is the set of object keys the header manifest points at: each
// namespace's current blob and its one-generation backup. An object outside this
// set is an orphan from a crashed write; doctor notes it, and the next write to
// its namespace reclaims it (internal/secrets reclaim), so there is no separate
// collect step.
func referencedBlobs(header *crypto.Header) map[string]bool {
	ref := make(map[string]bool, len(header.Manifest)*2)
	for _, e := range header.Manifest {
		ref[e.Blob] = true
		if e.Prev != "" {
			ref[e.Prev] = true
		}
	}
	return ref
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
