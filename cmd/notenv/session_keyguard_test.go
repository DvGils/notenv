package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
)

// identityHeaderStore builds a recipient-locked vault and a headerTarget bound to
// it at the given scope, with NOTENV_IDENTITY pointing at the matching key so
// resolveUnlock opens it without a prompt. The master is also pre-cached so the
// warm-path readers (doctor) have something to find.
func identityHeaderStore(t *testing.T, scope string) (*headerTarget, *crypto.MasterKey) {
	t.Helper()
	isolateConfig(t)
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, id.String())
	store := memstore.New()
	header, mk, err := crypto.NewRecipientHeader(id.Recipient(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	header.Revision = 0
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, e := h.UnlockIdentity(id); return m, e }
	if err := keymgmt.SafePut(ctx, store, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	cache := newMapCache()
	_ = cache.Store(scope, mk.String(), time.Hour)
	target := &headerTarget{vaultStorage: doctorStore{store}, scope: scope, cache: cache}
	return target, mk
}

// TestUnlockHeaderRefusesForeignVaultInSession: every mutating key command
// funnels through unlockHeader, which must refuse to unlock any vault but the
// handed-off one while inside a handoff session, before it prompts.
func TestUnlockHeaderRefusesForeignVaultInSession(t *testing.T) {
	ctx := context.Background()
	target, _ := identityHeaderStore(t, "vault-scope")

	// A session bound to a different vault: unlockHeader must fail closed.
	t.Setenv(sessionEnv, "some-other-scope")
	if _, err := unlockHeader(ctx, target, false); err == nil || !strings.Contains(err.Error(), "handoff session") {
		t.Fatalf("foreign session: err = %v, want a handoff-session refusal", err)
	}

	// The session's own vault still unlocks (the guard is scoped, not blanket).
	t.Setenv(sessionEnv, "vault-scope")
	if _, err := unlockHeader(ctx, target, false); err != nil {
		t.Fatalf("the session's own vault must unlock: %v", err)
	}

	// No session at all is unaffected.
	t.Setenv(sessionEnv, "")
	if _, err := unlockHeader(ctx, target, false); err != nil {
		t.Fatalf("no session: %v", err)
	}
}

// TestDoctorSessionGuardSkipsForeignWarmKey: doctor must not read another vault's
// warm master from inside a handoff session (which would verify and decrypt that
// vault's blobs from cache). It degrades to the unverified-header report instead.
func TestDoctorSessionGuardSkipsForeignWarmKey(t *testing.T) {
	target, _ := identityHeaderStore(t, "vault-scope")

	authenticates := func(c *checkup) bool {
		for _, f := range c.findings {
			if f.Level == "ok" && strings.Contains(f.Text, "authenticates under the cached session key") {
				return true
			}
		}
		return false
	}
	handoffNoted := func(c *checkup) bool {
		for _, f := range c.findings {
			if strings.Contains(f.Text, "handoff session") {
				return true
			}
		}
		return false
	}

	// Foreign session: the warm key is present but must not be used; doctor notes
	// the session limitation and reports presence only.
	t.Setenv(sessionEnv, "some-other-scope")
	c := &checkup{}
	runDoctor(doctorCmdCtx(t), target, c)
	if authenticates(c) {
		t.Fatal("doctor verified a foreign vault under a warm session key inside a handoff session")
	}
	if !handoffNoted(c) {
		t.Fatal("doctor must say it skipped verification because of the handoff session")
	}

	// The session's own vault verifies normally.
	t.Setenv(sessionEnv, "vault-scope")
	c = &checkup{}
	runDoctor(doctorCmdCtx(t), target, c)
	if !authenticates(c) {
		t.Fatal("doctor must verify the session's own vault under its warm key")
	}
}
