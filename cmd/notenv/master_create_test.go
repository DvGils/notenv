package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
)

// stubReadSecret pins the passphrase prompt seam to a queue of answers, so the
// creation ceremony runs without a terminal.
func stubReadSecret(t *testing.T, answers ...string) {
	t.Helper()
	prev := readSecretFn
	i := 0
	readSecretFn = func(string) (string, error) {
		if i >= len(answers) {
			return "", errors.New("no more stubbed answers")
		}
		a := answers[i]
		i++
		return a, nil
	}
	t.Cleanup(func() { readSecretFn = prev })
}

func TestWarnShortPassphrase(t *testing.T) {
	cases := []struct {
		pass     string
		wantWarn bool
	}{
		{"short", true},
		{"eleven_char", true},   // 11 chars: still warns
		{"twelve_chars", false}, // 12 chars: at the threshold, silent
		{"a-much-longer-one", false},
	}
	for _, c := range cases {
		out := captureStderr(t, func() { warnShortPassphrase(c.pass) })
		warned := strings.Contains(out, "short")
		if warned != c.wantWarn {
			t.Errorf("warnShortPassphrase(%q): warned=%v, want %v (len %d)", c.pass, warned, c.wantWarn, len(c.pass))
		}
	}
}

func TestChooseCreationPassphrase(t *testing.T) {
	t.Run("generated when empty", func(t *testing.T) {
		stubReadSecret(t, "") // Enter at the first prompt generates one
		got, err := chooseCreationPassphrase()
		if err != nil {
			t.Fatal(err)
		}
		if got == "" {
			t.Fatal("an empty entry must yield a generated passphrase")
		}
	})
	t.Run("typed and confirmed", func(t *testing.T) {
		stubReadSecret(t, "a-typed-passphrase", "a-typed-passphrase")
		got, err := chooseCreationPassphrase()
		if err != nil {
			t.Fatal(err)
		}
		if got != "a-typed-passphrase" {
			t.Fatalf("got %q, want the typed passphrase", got)
		}
	})
	t.Run("mismatch errors", func(t *testing.T) {
		stubReadSecret(t, "one-passphrase", "another-passphrase")
		if _, err := chooseCreationPassphrase(); err == nil || !strings.Contains(err.Error(), "do not match") {
			t.Fatalf("a mismatch must error, got %v", err)
		}
	})
}

// TestCreateWithIdentity: the promptless creation path mints a recipient-only
// vault that opens with that identity and has no passphrase to attack.
func TestCreateWithIdentity(t *testing.T) {
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	mk, header, err := createWithIdentity(ctx, store, id)
	if err != nil {
		t.Fatalf("createWithIdentity: %v", err)
	}
	if header.Recipient != mk.PublicKey() {
		t.Fatal("the header is not wrapped to the fresh master")
	}

	stored := reparseHeader(t, ctx, store)
	if _, _, err := stored.UnlockIdentity(id); err != nil {
		t.Fatalf("the identity could not unlock its own vault: %v", err)
	}
	if _, _, _, err := stored.Unlock("anything"); err == nil {
		t.Fatal("a recipient-only vault must have no passphrase slot to unlock")
	}
}

// TestCreateMasterWithIdentity: createMaster routes to the identity ceremony
// when the environment supplies a creation identity.
func TestCreateMasterWithIdentity(t *testing.T) {
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityEnv, id.String())
	store := memstore.New()
	if _, _, err := createMaster(ctx, store); err != nil {
		t.Fatalf("createMaster (identity): %v", err)
	}
	if _, _, err := reparseHeader(t, ctx, store).UnlockIdentity(id); err != nil {
		t.Fatalf("identity-created vault does not unlock with its identity: %v", err)
	}
}

// TestCreateMasterPassphrase: with no creation identity, createMaster runs the
// passphrase ceremony (via the prompt seam) and the result unlocks with it.
func TestCreateMasterPassphrase(t *testing.T) {
	ctx := context.Background()
	t.Setenv(identityEnv, "")
	stubReadSecret(t, "a-long-creation-passphrase", "a-long-creation-passphrase")
	store := memstore.New()
	mk, _, err := createMaster(ctx, store)
	if err != nil {
		t.Fatalf("createMaster (passphrase): %v", err)
	}
	got, _, _, err := reparseHeader(t, ctx, store).Unlock("a-long-creation-passphrase")
	if err != nil {
		t.Fatalf("passphrase-created vault does not unlock with the passphrase: %v", err)
	}
	if got.PublicKey() != mk.PublicKey() {
		t.Fatal("unlocked a different master than the one returned")
	}
}

// reparseHeader reads the stored header back the way a fresh process would, so a
// test exercises the on-disk bytes rather than the in-memory struct.
func reparseHeader(t *testing.T, ctx context.Context, store *memstore.Store) *crypto.Header {
	t.Helper()
	raw, err := store.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	header, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return header
}
