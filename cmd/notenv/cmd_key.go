package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Inspect and manage the key slots in your storage header",
	Long: `Manage the key-slot header that wraps your master key.

The header lives next to your secrets and stores the master key wrapped under
one or more slots: a person's passphrase, or a machine's age public key. These
commands operate on the storage as a whole, independent of any single project.`,
}

// headerTarget is a storage opened for header operations together with its
// local-state scope (key cache, rollback pins) and, when writes are refused,
// the reason (readOnlyReason).
type headerTarget struct {
	vaultStorage
	scope    string
	readOnly string
}

// loadHeaderStore builds the storage backend for header operations. The header
// sits alongside every namespace, so these commands need only the storage
// target, not a project contract. Storage selection honors --storage, else the
// machine default / sole storage.
func loadHeaderStore() (*headerTarget, error) {
	// --storage wins, then NOTENV_STORAGE (the env an agent / CI / handoff is
	// pointed at), then the project's local binding if we are inside one, then the
	// machine default / sole storage. This must match the rest of the CLI's
	// selection (storageSelector); resolving headers by a different rule is how
	// `key`, `export --all`, and `vault copy` ended up ignoring NOTENV_STORAGE and
	// silently targeting the default vault. A corrupt binding is a hard error only
	// when we fall through to it (no flag, no env): these commands are destructive,
	// so we must never silently retarget the default vault.
	storageName := storageSelector("")
	if storageName == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		if _, dir, err := contract.Find(cwd); err == nil {
			binding, err := config.ReadLocalBinding(dir)
			if err != nil {
				return nil, err
			}
			storageName = binding.Storage
		}
	}
	return headerTargetFor(storageName)
}

// headerTargetFor opens a named storage (or the machine default) for header
// operations, with no checkout in the loop.
func headerTargetFor(storageName string) (*headerTarget, error) {
	user, err := config.LoadUser()
	if err != nil {
		return nil, err
	}
	eff, err := config.ResolveStorage(user, storageName)
	if err != nil {
		return nil, err
	}
	return &headerTarget{vaultStorage: openStorage(eff), scope: eff.Scope(), readOnly: readOnlyReason(eff.StorageName, eff.ReadOnly)}, nil
}

// trustHeader is the read-side integrity check run after every unlock: it
// verifies the header's authentication tag, confirms this storage still holds
// the vault it held before, then checks the local rollback pin and advances
// it. A master change is accepted silently when a chain of signed transitions
// proves the pinned master authorized it; otherwise (and for a rollback or a
// wholesale vault replacement) it is refused, recoverable with
// `notenv key trust` after out-of-band verification.
func trustHeader(scope string, h *crypto.Header, mk *crypto.MasterKey) error {
	if err := h.Verify(mk); err != nil {
		return fmt.Errorf("%w; refusing to use this vault. If a teammate changed it legitimately, run `notenv key trust`; otherwise treat the storage as compromised", err)
	}
	boundVault, bound, err := config.ScopeVault(scope)
	if err != nil {
		return err
	}
	if bound && boundVault != h.VaultID {
		return fmt.Errorf("this storage previously held vault %s but now presents vault %s: the vault was replaced wholesale. If you deliberately re-initialized it, run `notenv key forget` and set up again; otherwise treat the storage as compromised", boundVault, h.VaultID)
	}
	stored, have, err := config.ReadPin(h.VaultID)
	if err != nil {
		return err
	}
	advance, err := config.CheckPin(stored, have, h.Revision, mk.PublicKey())
	if errors.Is(err, config.ErrMasterChanged) {
		if keymgmt.FollowRotations(h, stored.SignPub, stored.Revision, mk) == nil {
			ui.Notef("the master key was rotated on another machine; verified the signed rotation chain and moved this machine's pin forward")
			advance, err = true, nil
		}
	}
	if err != nil {
		return err
	}
	if advance {
		return writePin(scope, h, mk)
	}
	return nil
}

// writePin records the observed header as this machine's trust anchor for the
// vault, and binds the storage scope to the vault's identity.
func writePin(scope string, h *crypto.Header, mk *crypto.MasterKey) error {
	signPub, err := mk.SignPub()
	if err != nil {
		return err
	}
	return config.WritePin(scope, h.VaultID, config.Pin{
		Revision:  h.Revision,
		MasterPub: mk.PublicKey(),
		SignPub:   signPub,
	})
}

// pinCurrent force-advances the local pin to a header this machine just wrote
// (the writer is authoritative for its own writes, including a legitimate master
// change). Best-effort: a failure only risks a false rollback alarm next read.
func pinCurrent(scope string, h *crypto.Header, mk *crypto.MasterKey) {
	if err := writePin(scope, h, mk); err != nil {
		ui.Warnf("could not update the local rollback pin: %v", err)
	}
}

// recacheMaster refreshes the session master-key cache after the master changed
// (rotate-master / rm), so the operator's next command neither fails to decrypt
// with a stale master nor re-prompts. Drops any stale entry first; honors the
// configured cache TTL ("0" disables, so this no-ops). Best-effort.
func recacheMaster(store *headerTarget, mk *crypto.MasterKey) {
	cache := keyring.DefaultCache()
	scope := store.scope
	cache.Drop(scope)
	user, err := config.LoadUser()
	if err != nil {
		return
	}
	ttl, err := user.MasterCacheTTL()
	if err != nil {
		return
	}
	cacheMaster(cache, scope, mk, ttl)
}

var keyListJSON bool

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the key slots in the storage header",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		var raw []byte
		if err := ui.Spin("Reading key header", func() error {
			var getErr error
			raw, getErr = store.GetHeader(cmd.Context())
			return getErr
		}); err != nil {
			if errors.Is(err, backend.ErrNotFound) {
				return errors.New("no key header found in storage; run `notenv setup` first")
			}
			return err
		}
		header, err := crypto.ParseHeader(raw)
		if err != nil {
			return err
		}
		if keyListJSON {
			return printJSON(keyListOutput(header))
		}
		printSlots(header)
		return nil
	},
}

// keyListJSONOutput is the frozen shape of `key list --json`. Slots carry
// their index because the rm/set-primary selectors accept one; public_key
// appears only on recipient slots (a passphrase slot's key is internal).
// Extensions are additive fields only.
type keyListJSONOutput struct {
	VaultID  string       `json:"vault_id"`
	Revision int          `json:"revision"`
	Slots    []slotOutput `json:"slots"`
}

type slotOutput struct {
	Index       int    `json:"index"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type"`
	Primary     bool   `json:"primary,omitempty"`
	Provisional bool   `json:"provisional,omitempty"`
	Added       string `json:"added,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
}

func keyListOutput(h *crypto.Header) keyListJSONOutput {
	out := keyListJSONOutput{VaultID: h.VaultID, Revision: h.Revision, Slots: make([]slotOutput, 0, len(h.Slots))}
	for i, slot := range h.Slots {
		s := slotOutput{Index: i, Name: slot.Name, Type: slot.Type, Primary: slot.Primary, Provisional: slot.Provisional}
		if s.Type == "" {
			s.Type = crypto.SlotPassphrase
		}
		if slot.TS > 0 {
			s.Added = time.Unix(slot.TS, 0).UTC().Format(time.RFC3339)
		}
		if slot.Type == crypto.SlotRecipient {
			s.PublicKey = slot.PublicKey
		}
		out.Slots = append(out.Slots, s)
	}
	return out
}

// slotPrincipal renders a slot's principal for humans: passphrases are for
// people, identities are for machines. A provisional slot is still a human
// slot, but the holder has not replaced the onboarding passphrase yet, which
// is the more important fact to show.
func slotPrincipal(slot crypto.Slot) string {
	if slot.Type == crypto.SlotRecipient {
		return "machine (identity)"
	}
	if slot.Provisional {
		return "human (provisional)"
	}
	return "human (passphrase)"
}

// printSlots renders the slots as a table. The fingerprint column shows a
// recipient slot's public key; passphrase slots have no public value, so they
// show a dash.
func printSlots(h *crypto.Header) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPRINCIPAL\tPRIMARY\tADDED\tFINGERPRINT")
	for _, slot := range h.Slots {
		primary := ""
		if slot.Primary {
			primary = "yes"
		}
		added := "-"
		if slot.TS > 0 {
			added = time.Unix(slot.TS, 0).UTC().Format("2006-01-02")
		}
		name := dashIfEmpty(slot.Name)
		// The public key is a user-facing fingerprint only for recipient slots;
		// a passphrase slot's key is internal.
		fingerprint := "-"
		if slot.Type == crypto.SlotRecipient {
			fingerprint = dashIfEmpty(slot.PublicKey)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, slotPrincipal(slot), primary, added, fingerprint)
	}
	_ = w.Flush()
	warnStaleProvisional(h)
}

// warnStaleProvisional flags provisional slots older than a week: the holder
// never replaced the onboarding passphrase, so the issuer still knows their
// credential and the onboarding is not done.
func warnStaleProvisional(h *crypto.Header) {
	const staleAfter = 7 * 24 * time.Hour
	for _, slot := range h.Slots {
		if !slot.Provisional || slot.TS <= 0 {
			continue
		}
		age := time.Since(time.Unix(slot.TS, 0))
		if age >= staleAfter {
			ui.Warnf("slot %q has been provisional for %d days; its holder never replaced the onboarding passphrase (resend it, or remove the slot)", dashIfEmpty(slot.Name), int(age.Hours()/24))
		}
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var keyRestoreBackupCmd = &cobra.Command{
	Use:   "restore-backup",
	Short: "Restore the key header from its backup after a failed write",
	Long: `Restore the header from the backup taken before the last write.

If a key operation reported that the header could not be verified after writing,
this recovers the prior header. notenv keeps this backup on every backend, so it
works the same whether your storage is local or a cloud remote. It reports an
error only when no backup exists yet (a vault gets its first on its second header
write).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		if store.readOnly != "" {
			return fmt.Errorf("%s; refusing to restore the header (a recovery is still a storage write)", store.readOnly)
		}
		if err := ui.Spin("Restoring header from backup", func() error {
			return keymgmt.RestoreBackup(cmd.Context(), store)
		}); err != nil {
			return err
		}
		ui.Successf("header restored from backup")
		repinAfterRestore(cmd.Context(), store)
		return nil
	},
}

// repinAfterRestore advances the local rollback pin to the just-restored header
// so the operator's next command does not raise a rollback alarm against their
// own deliberate recovery: the restored header is a revision behind whatever was
// last committed, so it would otherwise trip the rollback check. The re-pin is
// prompt-free and gated on the cached master verifying the restored header, so
// it can only ever move the pin back to a header this machine's master vouches
// for, never to a planted one. With no usable cached master (a cold session, or
// a restore across a master rotation) it explains the pin-ahead state instead.
func repinAfterRestore(ctx context.Context, store *headerTarget) {
	raw, err := store.GetHeader(ctx)
	if err != nil {
		return
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return
	}
	var mk *crypto.MasterKey
	if cached, ok := keyring.DefaultCache().Get(store.scope); ok {
		mk, _ = crypto.ParseMasterKey(cached)
	}
	if repinRestored(store.scope, header, mk) {
		ui.Notef("rollback pin moved to the restored revision %d", header.Revision)
		return
	}
	ui.Warnf("the restored header is at revision %d; if this machine pinned a higher one, the next unlock raises a rollback alarm. After confirming this restore is what you intended, run `notenv key trust` to accept it", header.Revision)
}

// repinRestored pins header for scope when mk verifies it, the safety gate that
// keeps the re-pin from trusting anything the master does not vouch for. Returns
// whether it pinned.
func repinRestored(scope string, header *crypto.Header, mk *crypto.MasterKey) bool {
	if mk == nil || header.Verify(mk) != nil {
		return false
	}
	pinCurrent(scope, header, mk)
	return true
}

// unlocked carries everything a mutating key operation needs after it has
// unlocked the header: the parsed header to mutate, the exact raw bytes it
// started from (the freshness baseline for SafePut), the master key, the index
// of the slot that opened, a reverify closure that re-unlocks a rewritten header
// with the same credential, and (for a passphrase unlock) the slot private key.
type unlocked struct {
	header   *crypto.Header
	raw      []byte
	mk       *crypto.MasterKey
	slot     int
	reverify func(*crypto.Header) (*crypto.MasterKey, error)
	slotKey  *age.X25519Identity
}

// unlockHeader reads and unlocks the header for a mutating operation. Unlike
// most commands it does not use the master-key cache: a key operation needs to
// know which slot the caller holds and to hold the credential itself for the
// post-write verification, so it always prompts. Every mutating key command
// funnels through here, so this is also where read-only policy refuses them.
// gateProvisional runs the onboarding gate; `key rotate` skips it because the
// rotation it is about to perform is exactly what the gate would force.
func unlockHeader(ctx context.Context, store *headerTarget, gateProvisional bool) (*unlocked, error) {
	if store.readOnly != "" {
		return nil, fmt.Errorf("%s; refusing to modify the vault header", store.readOnly)
	}
	if err := store.Preflight(ctx); err != nil {
		return nil, err
	}
	var raw []byte
	if err := ui.Spin("Reading key header", func() error {
		var getErr error
		raw, getErr = store.GetHeader(ctx)
		return getErr
	}); err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return nil, errors.New("no key header found in storage; run `notenv setup` first")
		}
		return nil, err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return nil, err
	}
	res, err := resolveUnlock(header, false) // admin path: the operator manages the vault
	if err != nil {
		return nil, err
	}
	// The fingerprint check precedes the trust check: it exists to refuse
	// a substituted vault before anything pins it on first use.
	if res.fingerprint != "" {
		if err := verifyOnboardingFingerprint(header, res.mk, res.fingerprint); err != nil {
			return nil, err
		}
	}
	if err := trustHeader(store.scope, header, res.mk); err != nil {
		return nil, err
	}
	if gateProvisional {
		// Read-only was refused above, so the gate's write cannot hit it.
		rotated, err := enforceProvisional(ctx, store, store.scope, "", header, raw, res)
		if err != nil {
			return nil, err
		}
		if rotated {
			// The gate rewrote the header; re-marshal the sealed result so the
			// next SafePut's freshness baseline matches what storage now holds.
			raw, err = header.Marshal()
			if err != nil {
				return nil, err
			}
		}
	}
	return &unlocked{header: header, raw: raw, mk: res.mk, slot: res.slot, reverify: res.reverify, slotKey: res.slotKey}, nil
}

// writeHeader marshals the mutated header and writes it through the safe-write
// protocol. verify re-unlocks the written header with the operator's credential;
// it defaults to the original unlock when nil (the credential is unchanged).
func writeHeader(ctx context.Context, store *headerTarget, u *unlocked, verify func(*crypto.Header) (*crypto.MasterKey, error)) error {
	if verify == nil {
		verify = u.reverify
	}
	if err := ui.Spin("Writing header", func() error {
		return keymgmt.SafePut(ctx, store, u.header, u.raw, u.mk, verify)
	}); err != nil {
		return err
	}
	pinCurrent(store.scope, u.header, u.mk) // revision was bumped by SafePut
	return nil
}

var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Re-wrap the master key under a new passphrase for your slot",
	Long: `Change the passphrase on the slot you unlock with.

This rewrites only the header: the master key and every encrypted secret are
untouched, so other slots keep working. Escrow the new passphrase.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(cmd.Context(), store, false)
		if err != nil {
			return err
		}
		if u.slotKey == nil {
			return errors.New("`key rotate` changes a passphrase; unlock with a passphrase slot, not an identity")
		}
		newPass, err := keyring.PromptNewPassphrase("Choose a new passphrase for your slot: ")
		if err != nil {
			return err
		}
		warnShortPassphrase(newPass)
		if err := u.header.RotateSlot(u.slot, newPass, u.slotKey); err != nil {
			return err
		}
		// The credential changed, so verify the write with the NEW passphrase.
		verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, _, e := h.Unlock(newPass); return m, e }
		if err := writeHeader(cmd.Context(), store, u, verify); err != nil {
			return err
		}
		ui.Warnf("escrow this new passphrase in your password manager NOW; the old one no longer opens this slot")
		ui.Successf("rotated passphrase for slot %q", u.header.Slots[u.slot].Name)
		return nil
	},
}

var keyRotateMasterCmd = &cobra.Command{
	Use:   "rotate-master",
	Short: "Re-key the vault: fresh master key, re-encrypt every secret",
	Long: `Generate a new master key and re-encrypt every secret under it, keeping all
slots.

Use this as a precaution, for example if a device that held the key may have been
compromised. Every current credential keeps working (the new master is re-wrapped
under all existing slots). This rewrites every secret, so it does more work than
the header-only operations.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(cmd.Context(), store, true)
		if err != nil {
			return err
		}
		// Pin and re-cache the new master at flip time, so an interrupted narrow
		// pass leaves the pin consistent with the header (a re-run isn't a false
		// rollback) and the operator's next command stays warm.
		onFlip := func(newMK *crypto.MasterKey) {
			pinCurrent(store.scope, u.header, newMK)
			recacheMaster(store, newMK)
		}
		if err := ui.Spin("Re-keying the vault (re-encrypting every secret)", func() error {
			_, rErr := keymgmt.RotateMaster(cmd.Context(), store, u.header, u.raw, u.mk, u.reverify, onFlip)
			return rErr
		}); err != nil {
			return err
		}
		ui.Successf("re-keyed the vault under a fresh master key; all slots still work")
		return nil
	},
}

var keyAddMachine bool
var keyAddRecipient string

var keyAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a key slot: onboard a teammate or enroll a machine",
	Long: `Add a key slot to the header.

  notenv key add alice          onboard a teammate: prints a one-time
                                onboarding passphrase to send them; their
                                first notenv command replaces it with a
                                passphrase only they know
  notenv key add --machine ci   enroll a machine (CI, an agent): prints a
                                new identity exactly once, for the platform's
                                secret store; nothing is written to disk

Passphrases are for people, identities are for machines. A machine slot wraps
the master key to an age public key; the machine presents the private key via
NOTENV_IDENTITY. Where the machine only reads, pair it with a read-only
storage credential and NOTENV_READONLY. With --machine --recipient age1...,
an existing public key is enrolled instead of generating a new identity (the
private key stays wherever it was made).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if keyAddRecipient != "" && !keyAddMachine {
			return errors.New("--recipient enrolls a machine key; use it together with --machine")
		}
		name := args[0]
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(cmd.Context(), store, true)
		if err != nil {
			return err
		}
		for _, slot := range u.header.Slots {
			if slot.Name == name {
				return fmt.Errorf("a slot named %q already exists; pick another name", name)
			}
		}

		if keyAddMachine {
			return addMachineSlot(cmd.Context(), store, u, name)
		}

		temp, err := keyring.GeneratePassphrase()
		if err != nil {
			return err
		}
		if err := u.header.AddPassphraseSlot(temp, name, u.mk); err != nil {
			return err
		}
		slot := &u.header.Slots[len(u.header.Slots)-1]
		slot.Provisional = true
		slot.TS = time.Now().Unix()
		// We only appended a slot, so the credential we unlocked with still
		// opens the new header and verifies the write.
		if err := writeHeader(cmd.Context(), store, u, nil); err != nil {
			return err
		}
		ui.Successf("added slot %q with a one-time onboarding string", name)
		ui.Infof("send this string to them over a private channel:")
		fmt.Println(temp + "/" + crypto.Fingerprint(u.header.VaultID, u.header.SignPub))
		ui.Infof("it bundles their first passphrase with a code proving they reached the real vault. Their first notenv command replaces the passphrase with one only they know; until then `notenv key list` shows the slot as provisional")
		return nil
	},
}

// addMachineSlot enrolls a machine principal: a recipient slot for a supplied
// public key, or for a freshly generated identity whose secret half is printed
// exactly once and never stored. The identity belongs in the machine's secret
// store, presented at runtime via NOTENV_IDENTITY.
func addMachineSlot(ctx context.Context, store *headerTarget, u *unlocked, name string) error {
	var recipient *age.X25519Recipient
	var generated *age.X25519Identity
	if keyAddRecipient != "" {
		var err error
		recipient, err = age.ParseX25519Recipient(keyAddRecipient)
		if err != nil {
			return fmt.Errorf("invalid recipient %q: %w", keyAddRecipient, err)
		}
	} else {
		var err error
		generated, err = age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		recipient = generated.Recipient()
	}
	if err := u.header.AddRecipientSlot(recipient, name, u.mk); err != nil {
		return err
	}
	u.header.Slots[len(u.header.Slots)-1].TS = time.Now().Unix()
	if err := writeHeader(ctx, store, u, nil); err != nil {
		return err
	}
	ui.Successf("enrolled machine slot %q for %s", name, recipient.String())
	if generated != nil {
		ui.Infof("store this identity in the machine's secret store and present it via NOTENV_IDENTITY; it is shown only once and saved nowhere:")
		fmt.Println(generated.String())
	}
	ui.Infof("if this machine only reads, give it a read-only storage credential and set NOTENV_READONLY=1")
	return nil
}

// refuseRecipientPrimary blocks transferring primary to a machine identity.
// Primary is the human governance anchor: a recipient slot's private key lives
// only on the machine it was enrolled for, so making it primary would leave
// nobody able to transfer primary away or remove it once that machine is lost.
func refuseRecipientPrimary(h *crypto.Header, target int) error {
	if h.Slots[target].Type == crypto.SlotRecipient {
		return errors.New("primary must be a human (passphrase) slot, not a machine identity: its key lives only on that machine, so making it primary could strand primary if the machine is lost")
	}
	return nil
}

var keySetPrimaryCmd = &cobra.Command{
	Use:   "set-primary <name | index>",
	Short: "Transfer the primary slot to another slot",
	Long: `Make another slot the primary slot.

Requires unlocking with the current primary slot's credential. Primary is
advisory governance (tooling-enforced, not cryptographic): the primary slot
cannot be removed, and only its holder may transfer primary.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(cmd.Context(), store, true)
		if err != nil {
			return err
		}
		if u.slot != u.header.PrimarySlot() {
			return errors.New("you must unlock with the current primary slot's credential to transfer primary")
		}
		target, err := resolveSlot(u.header, args[0])
		if err != nil {
			return err
		}
		if target == u.slot {
			return errors.New("that slot is already primary")
		}
		if err := refuseRecipientPrimary(u.header, target); err != nil {
			return err
		}
		if err := u.header.SetPrimary(target); err != nil {
			return err
		}
		if err := writeHeader(cmd.Context(), store, u, nil); err != nil {
			return err
		}
		ui.Successf("transferred primary to slot %q", slotLabel(u.header.Slots[target]))
		return nil
	},
}

// slotLabel is a human label for a slot: its name, else (for recipient slots)
// its public key.
func slotLabel(s crypto.Slot) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Type == crypto.SlotRecipient {
		return s.PublicKey
	}
	return "(unnamed slot)"
}

var keyRmCmd = &cobra.Command{
	Use:   "rm <name | index>",
	Short: "Remove a key slot and re-key the vault (offboarding)",
	Long: `Remove a key slot by name or by its zero-based index in 'key list', then
re-key the vault so the removed credential can no longer decrypt anything.

This re-encrypts every secret under a fresh master key (see 'rotate-master'),
which is what makes removal real revocation rather than just deleting a
credential. The primary slot and the last remaining slot cannot be removed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(cmd.Context(), store, true)
		if err != nil {
			return err
		}
		target, err := resolveSlot(u.header, args[0])
		if err != nil {
			return fmt.Errorf("%w (if a previous `key rm` was interrupted, the slot may already be gone; run `notenv key rotate-master` to finish re-keying)", err)
		}
		if u.header.Slots[target].Primary {
			return errors.New("refusing to remove the primary slot")
		}
		if target == u.slot {
			return errors.New("that is the slot you just unlocked with; remove it using a different credential")
		}
		name := u.header.Slots[target].Name
		if err := u.header.RemoveSlot(target, u.mk); err != nil {
			return err
		}
		// Re-key under the surviving slots so the removed credential, and any
		// retained copy of the old master, can no longer decrypt.
		onFlip := func(newMK *crypto.MasterKey) {
			pinCurrent(store.scope, u.header, newMK)
			recacheMaster(store, newMK)
		}
		if err := ui.Spin("Removing slot and re-keying the vault", func() error {
			_, rErr := keymgmt.RotateMaster(cmd.Context(), store, u.header, u.raw, u.mk, u.reverify, onFlip)
			return rErr
		}); err != nil {
			if errors.Is(err, keymgmt.ErrNarrowIncomplete) {
				// The slot is removed and the master rotated, but re-encryption did
				// not finish, so the removed credential can still read the
				// not-yet-re-keyed namespaces. This is incomplete revocation: say so
				// plainly rather than let the operator read "error" as "nothing
				// happened, the slot is still there".
				return fmt.Errorf("slot %q is removed and the vault re-keyed, but re-encryption did not finish: that credential can STILL read the namespaces not yet re-keyed. Treat it as NOT revoked and re-run `notenv key rotate-master` until it succeeds: %w", name, err)
			}
			return err
		}
		ui.Successf("removed slot %q and re-keyed the vault; that credential can no longer decrypt", name)
		ui.Warnf("for complete offboarding, also rotate this vault's storage credential at the provider so the removed holder can't read or write the bucket")
		return nil
	},
}

// resolveSlot maps a user-supplied selector to a slot index. A bare integer is
// a zero-based index; otherwise it matches a slot's name, then a recipient
// slot's public key. It errors on no match or an ambiguous name.
func resolveSlot(h *crypto.Header, sel string) (int, error) {
	if i, err := strconv.Atoi(sel); err == nil {
		if i < 0 || i >= len(h.Slots) {
			return -1, fmt.Errorf("slot index %d out of range (have %d slots)", i, len(h.Slots))
		}
		return i, nil
	}
	match := -1
	for i, slot := range h.Slots {
		recipientMatch := slot.Type == crypto.SlotRecipient && slot.PublicKey == sel
		if slot.Name == sel || recipientMatch {
			if match != -1 {
				return -1, fmt.Errorf("more than one slot matches %q; select it by index instead", sel)
			}
			match = i
		}
	}
	if match == -1 {
		return -1, fmt.Errorf("no slot matches %q", sel)
	}
	return match, nil
}

var (
	keyTrustYes    bool
	keyForgetForce bool
	keyEvictYes    bool
)

var keyForgetCmd = &cobra.Command{
	Use:   "forget",
	Short: "Forget this machine's local trust state for a storage (pin + cached key)",
	Long: `Remove this machine's rollback pin and cached master key for a storage.

Use it ONLY after you have deliberately deleted or re-initialized the vault on
that storage, so the next setup starts from a clean trust-on-first-use state.
If the header vanished and you did NOT delete it, do not run this: that absence
is the alarm. Restore the header instead ('notenv key restore-backup' or the
remote's version history).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		scope := store.scope
		vaultID, bound, err := config.ScopeVault(scope)
		if err != nil {
			return err
		}
		if !bound {
			keyring.DefaultCache().Drop(scope)
			ui.Notef("no vault pinned at this storage; dropped any cached key")
			return nil
		}
		pin, _, _ := config.ReadPin(vaultID)
		ui.Warnf("this forgets vault %s (pinned revision %d, master %s); a substituted vault would then be trusted on next contact", vaultID, pin.Revision, pin.MasterPub)
		if !keyForgetForce {
			if !ui.Interactive() {
				return errors.New("refusing to forget non-interactively without --force")
			}
			ok, err := ui.Confirm("Forget this storage's trust state?", false)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted; trust state kept")
			}
		}
		if err := config.ForgetScope(scope); err != nil {
			return err
		}
		keyring.DefaultCache().Drop(scope)
		ui.Successf("forgot the pin and cached key for this storage; the next unlock is trust-on-first-use")
		return nil
	},
}

var keyTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Trust the vault's current header (clear a rollback / master-change alarm)",
	Long: `Pin this machine to the vault's current header revision and master key,
clearing a rollback or unexpected-master-change alarm.

Only do this after confirming out of band that the change is legitimate (for
example, a teammate rotated the master on another machine). Trusting a malicious
rollback re-exposes you to it. A tampered header is never trusted: its
authentication tag must still verify.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		var raw []byte
		if err := ui.Spin("Reading key header", func() error {
			var getErr error
			raw, getErr = store.GetHeader(cmd.Context())
			return getErr
		}); err != nil {
			if errors.Is(err, backend.ErrNotFound) {
				return errors.New("no key header found in storage; run `notenv setup` first")
			}
			return err
		}
		header, err := crypto.ParseHeader(raw)
		if err != nil {
			return err
		}
		// Unlock to recover the master, then require the tag to verify (trust
		// clears the pin alarm, never an authentication failure).
		res, err := resolveUnlock(header, false)
		if err != nil {
			return err
		}
		if err := header.Verify(res.mk); err != nil {
			return fmt.Errorf("%w; refusing to trust an unauthenticated header", err)
		}
		// Show exactly what is being traded before the alarm is cleared: this
		// command exists to override a security check, so the decision must be
		// visible, deliberate, and never the path of least resistance.
		scope := store.scope
		boundVault, bound, err := config.ScopeVault(scope)
		if err != nil {
			return err
		}
		if bound && boundVault != header.VaultID {
			ui.Warnf("this storage previously held vault %s; trusting REPLACES it with vault %s; every prior trust anchor stops applying", boundVault, header.VaultID)
		}
		stored, have, err := config.ReadPin(header.VaultID)
		if err != nil {
			return err
		}
		if have {
			ui.Notef("pinned now:  revision %d, master %s", stored.Revision, stored.MasterPub)
			ui.Notef("trusting:    revision %d, master %s", header.Revision, res.mk.PublicKey())
			if stored.MasterPub != res.mk.PublicKey() {
				ui.Warnf("this is a MASTER KEY change with no signed rotation path; only proceed if you confirmed the change out of band (e.g. with the teammate who ran it)")
			} else if header.Revision < stored.Revision {
				ui.Warnf("this is a ROLLBACK to an older header; trusting it re-exposes you to whatever it undid")
			}
		} else if !bound {
			ui.Notef("no pin recorded yet; this is this machine's first pin for the vault")
		}
		if !keyTrustYes {
			if !ui.Interactive() {
				return errors.New("refusing to trust non-interactively without --yes")
			}
			ok, err := ui.Confirm("Pin this header as trusted?", false)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted; the existing pin is unchanged")
			}
		}
		pinCurrent(scope, header, res.mk)
		ui.Successf("trusted header revision %d (master %s)", header.Revision, res.mk.PublicKey())
		return nil
	},
}

var keyEvictCmd = &cobra.Command{
	Use:   "evict <namespace>",
	Short: "Repair a namespace with an unreadable blob by rewriting it from what survives (accepts data loss)",
	Long: `Repair a namespace a normal read refuses because its current blob is missing or
corrupt (bit-rot, a truncated upload, an unrecoverable remote). notenv rewrites
the namespace from what survives: its one-generation backup if that is intact
(losing only the most recent write), or, if the backup is gone too, an empty
namespace. The corrupt blobs are then dropped.

This is a last resort for honest media loss. Prefer recovering the blob from your
remote's version history if it keeps one, or 'notenv run --skip-corrupt' to read
what survives without changing anything.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		ns := args[0]
		store, err := loadHeaderStore()
		if err != nil {
			return err
		}
		u, err := unlockHeader(ctx, store, false)
		if err != nil {
			return err
		}
		entry, recorded := u.header.Manifest[ns]
		if !recorded {
			return fmt.Errorf("namespace %q is not in the vault manifest; nothing to evict", ns)
		}
		state, err := secrets.For(store, ns, u.mk).ReadSalvage(ctx, entry)
		if err != nil {
			return err
		}
		if len(state.Corrupt) == 0 {
			return fmt.Errorf("namespace %q reads cleanly; nothing to evict", ns)
		}
		for _, c := range state.Corrupt {
			ui.Warnf("unreadable blob %s: %s", c.Blob, c.Reason)
		}
		survivors := len(state.Secrets)
		if survivors > 0 {
			ui.Warnf("evicting rewrites namespace %q from its last good backup (%d secret(s)); the most recent write(s) are lost", ns, survivors)
		} else {
			ui.Warnf("nothing survives for namespace %q; evicting clears it (it will hold no secrets)", ns)
		}
		if !keyEvictYes {
			if !ui.Interactive() {
				return errors.New("refusing to evict non-interactively without --yes")
			}
			ok, err := ui.Confirm("Evict and rewrite this namespace?", false)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted; nothing was changed")
			}
		}
		if err := evictNamespace(ctx, store, u.mk, ns, state, entry); err != nil {
			if errors.Is(err, keymgmt.ErrEpochChanged) {
				return fmt.Errorf("%w; nothing was changed. Re-unlock under the current key (verify the rotation is legitimate) and re-run", err)
			}
			return err
		}
		if survivors > 0 {
			ui.Successf("recovered namespace %q to its last good state (%d secret(s))", ns, survivors)
		} else {
			ui.Successf("cleared namespace %q; it now holds no secrets", ns)
		}
		return nil
	},
}

// evictNamespace rewrites a namespace from the salvaged state: a fresh blob (no
// backup yet) when anything survives, or the namespace entry dropped when
// nothing does. The corrupt blobs it replaces are dropped as part of the same
// commit (secrets.Rewrite handles the header swap and blob cleanup). expected is
// the manifest entry the state was salvaged under, so a concurrent repair that
// landed since aborts the evict rather than being clobbered.
func evictNamespace(ctx context.Context, store *headerTarget, mk *crypto.MasterKey, ns string, state *secrets.State, expected crypto.ManifestEntry) error {
	_, err := secrets.For(store, ns, mk).Rewrite(ctx, state, expected,
		func(h *crypto.Header) { pinCurrent(store.scope, h, mk) })
	return err
}

func init() {
	keyAddCmd.Flags().BoolVar(&keyAddMachine, "machine", false, "enroll a machine (CI, an agent) instead of onboarding a teammate")
	keyAddCmd.Flags().StringVar(&keyAddRecipient, "recipient", "", "with --machine: enroll an existing age1... public key instead of generating an identity")
	keyListCmd.Flags().BoolVar(&keyListJSON, "json", false, "machine-readable output: vault id, revision, slots")
	keyTrustCmd.Flags().BoolVar(&keyTrustYes, "yes", false, "pin without the interactive confirmation (for scripts; you have verified the change out of band)")
	keyForgetCmd.Flags().BoolVar(&keyForgetForce, "force", false, "forget without the interactive confirmation")
	keyEvictCmd.Flags().BoolVar(&keyEvictYes, "yes", false, "evict without the interactive confirmation (you have accepted the data loss)")
	keyCmd.AddCommand(keyListCmd, keyRotateCmd, keyRotateMasterCmd, keyAddCmd, keyRmCmd, keySetPrimaryCmd, keyTrustCmd, keyForgetCmd, keyRestoreBackupCmd, keyEvictCmd)
}
