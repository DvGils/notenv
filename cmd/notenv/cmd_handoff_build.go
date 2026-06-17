package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/secrets"
)

var (
	buildSource     string
	buildNamespaces string
	buildVault      string
	buildRecipient  string
)

// handoffBuildCmd is the internal builder subprocess `handoff` re-execs (R2 in
// design/ephemeral-scope.md). It unlocks the source vault, mints the ephemeral
// vault E under a fresh recipient, copies the chosen namespaces in, drops the
// source master from the cache, and exits, so that by the time the agent runs no
// live process holds your master. It receives only public inputs (the source
// spec, the namespaces, E's path, and the ephemeral public recipient); the
// private ephemeral key stays with the parent, so the builder returns no secret.
// Hidden: not a user-facing command.
var handoffBuildCmd = &cobra.Command{
	Use:    "__handoff-build",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runHandoffBuild(cmd.Context())
	},
}

// cacheProvider returns the master-key cache the build path uses. It is the real
// platform cache in production; a test seam, because TestRunHandoffBuild* runs the
// builder in-process and so needs no cross-process store, and reaching for the real
// macOS Keychain there imported its headless-CI fragility for no benefit.
var cacheProvider = keyring.DefaultCache

func runHandoffBuild(ctx context.Context) error {
	namespaces := splitNamespaces(buildNamespaces)
	if buildSource == "" || buildVault == "" || buildRecipient == "" || len(namespaces) == 0 {
		return errors.New("internal: handoff build is missing arguments")
	}
	recipient, err := age.ParseX25519Recipient(buildRecipient)
	if err != nil {
		return fmt.Errorf("internal: bad ephemeral recipient: %w", err)
	}

	user, err := config.LoadUser()
	if err != nil {
		return err
	}
	srcEff, err := config.ResolveStorage(user, buildSource)
	if err != nil {
		return err
	}
	srcStore := openStorage(srcEff)
	vault, ok := srcStore.(keymgmt.Vault)
	if !ok {
		return errors.New("source backend does not support client-side crypto")
	}

	mk, header, err := unlockSource(ctx, vault, srcEff)
	if err != nil {
		return err
	}

	// Read the chosen namespaces from the source under the unlocked master.
	states := make(map[string]*secrets.State, len(namespaces))
	total := 0
	for _, ns := range namespaces {
		entry, _ := header.NamespaceEntry(ns)
		st, err := secrets.For(srcStore, ns, mk).Read(ctx, entry)
		if err != nil {
			return fmt.Errorf("read namespace %q from the source vault: %w", ns, err)
		}
		states[ns] = st
		total += len(st.Secrets)
	}
	if total == 0 {
		return fmt.Errorf("the namespace(s) you handed off (%s) hold no secrets, so there's nothing to give the agent; add secrets with `notenv set` first", strings.Join(namespaces, ", "))
	}

	if err := buildEphemeral(ctx, buildVault, recipient, states); err != nil {
		return err
	}

	// Drop the source master from the shared cache. The lease kept it from being
	// re-stored during the build; this removes any entry that predated the handoff,
	// so no agent-readable cache entry for your master survives (R1).
	cacheProvider().Drop(srcEff.Scope())
	return nil
}

// unlockSource opens the source vault's master: a warm cache read if present,
// otherwise the full unlock ceremony (which prompts). It first refuses a source
// any configured identity can unlock, since the agent runs as you and could
// replay that identity to reach your real vault.
func unlockSource(ctx context.Context, vault keymgmt.Vault, eff config.Effective) (*crypto.MasterKey, *crypto.Header, error) {
	raw, err := vault.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, nil, errors.New("no vault found at the source storage; nothing to hand off")
	}
	if err != nil {
		return nil, nil, err
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		return nil, nil, err
	}
	if identityUnlocks(header) {
		return nil, nil, fmt.Errorf("handoff won't use a vault that your %s identity can unlock, because the agent runs as you and could reuse that identity to open your real vault. Either unset %s before handing off, or hand off from a passphrase-protected vault", identityEnv, identityEnv)
	}
	cache := cacheProvider()
	if cached, ok := cache.Get(eff.Scope()); ok {
		if mk, err := crypto.ParseMasterKey(cached); err == nil {
			return mk, header, nil
		}
	}
	// readOnly reason forbids the create-on-missing branch: handoff only reads.
	mk, _, err := ensureMaster(ctx, vault, cache, eff.Scope(), eff.CacheTTL, "handoff only reads the source vault")
	if err != nil {
		return nil, nil, err
	}
	return mk, header, nil
}

// identityUnlocks reports whether any identity in NOTENV_IDENTITY opens the
// source header (the precondition that makes the agent's reach to your real
// vault impossible).
func identityUnlocks(header *crypto.Header) bool {
	ids, err := configuredIdentities()
	if err != nil {
		return false
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			if _, _, err := header.UnlockIdentity(x); err == nil {
				return true
			}
		}
	}
	return false
}

// buildEphemeral mints the ephemeral vault E at dir under recipient (a fresh
// random master wrapped only to that recipient) and copies states in. E is an
// ordinary local vault in the existing format, so the agent's normal notenv
// reads it with no special code.
func buildEphemeral(ctx context.Context, dir string, recipient *age.X25519Recipient, states map[string]*secrets.State) error {
	eStore := openStorage(config.Effective{Path: dir})
	header, mk, err := crypto.NewRecipientHeader(recipient, userAtHost())
	if err != nil {
		return err
	}
	header.Slots[0].TS = time.Now().Unix()
	header.Revision = 0 // SafePut owns the revision; the stored header starts at 1
	// The builder holds the fresh master directly (NewRecipientHeader returns it)
	// and not the private identity, so it confirms the read-back header by its
	// recipient rather than by unlocking it.
	verify := func(hh *crypto.Header) (*crypto.MasterKey, error) {
		if hh.Recipient != mk.PublicKey() {
			return nil, errors.New("ephemeral header read back with the wrong recipient")
		}
		return mk, nil
	}
	if err := keymgmt.SafePut(ctx, eStore, header, nil, mk, verify); err != nil {
		return fmt.Errorf("write ephemeral vault: %w", err)
	}
	now := time.Now().Unix()
	for ns, st := range states {
		if len(st.Secrets) == 0 {
			continue
		}
		writes := writesFromState(st, now)
		_, _, err := secrets.For(eStore, ns, mk).Commit(ctx,
			func(cur *secrets.State) (*secrets.State, error) { return cur.Apply(writes), nil },
			nil)
		if err != nil {
			return fmt.Errorf("copy namespace %q into the ephemeral vault: %w", ns, err)
		}
	}
	return nil
}

// writesFromState turns a read source namespace into the writes that recreate it
// in the ephemeral vault, carrying each key's description and timestamp forward.
func writesFromState(st *secrets.State, fallbackTS int64) []secrets.Write {
	writes := make([]secrets.Write, 0, len(st.Secrets))
	for k, v := range st.Secrets {
		m := st.Meta[k]
		ts := m.TS
		if ts == 0 {
			ts = fallbackTS
		}
		writes = append(writes, secrets.Write{Key: k, Value: v, Description: m.Description, TS: ts})
	}
	return writes
}

// splitNamespaces parses a comma-separated namespace list, trimming blanks.
func splitNamespaces(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func init() {
	handoffBuildCmd.Flags().StringVar(&buildSource, "source", "", "source storage spec")
	handoffBuildCmd.Flags().StringVar(&buildNamespaces, "namespaces", "", "comma-separated namespaces to copy")
	handoffBuildCmd.Flags().StringVar(&buildVault, "vault", "", "ephemeral vault directory to create")
	handoffBuildCmd.Flags().StringVar(&buildRecipient, "recipient", "", "ephemeral public recipient (age1...)")
}
