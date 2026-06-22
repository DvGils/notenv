package secrets_test

import (
	"context"
	"flag"
	"os"
	"sort"
	"testing"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/local"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// The golden vault is a committed, encrypted vault that every later 1.x build must
// still open and read unchanged. It is the regression guard behind the storage
// compatibility promise in COMPATIBILITY.md: the header (v6) and blob (v3) formats
// are frozen, so a vault written once stays readable bit-for-bit. The fixture
// exercises both unlock paths (a passphrase slot and a machine-identity recipient
// slot), namespace and per-secret metadata, a value that only survives a base64
// round-trip, and a namespace that carries a one-generation backup (a Prev manifest
// pointer). A future change that broke any of these decrypts to the wrong bytes and
// fails here.
//
// Regenerate with:
//
//	go test -tags fastkdf -run TestGoldenVault -update-golden ./internal/secrets
//
// The fastkdf tag is required when regenerating: it wraps the passphrase slot at
// the test scrypt work factor, which the same-tagged suite can open. A production
// build wraps it at 2^19, above the fastkdf unlock cap, so the suite would then
// refuse the passphrase. The work factor is a cost parameter, not a format one (the
// bytes are identical at any factor); the production value is guarded by
// TestProductionScryptWorkFactor.
var updateGolden = flag.Bool("update-golden", false, "regenerate the golden vault fixture")

const (
	goldenDir        = "testdata/golden/v1"
	goldenPassphrase = "golden fixture passphrase, not a real credential"
	// A fixed throwaway machine identity so the fixture is deterministic. Test data,
	// not a real key.
	goldenIdentity = "AGE-SECRET-KEY-1259CZ4C3HNZRR7JQCY6Z0LGQUDMZHYRW6ACX52RGPKSPCU50JXUS8CZPWV"
	goldenActor    = "golden@fixture"
	goldenTS1      = int64(1_700_000_000) // namespace creation and first writes
	goldenTS2      = int64(1_700_100_000) // proj's second write: a Prev backup and a later Updated
)

type secretExpect struct {
	value string
	desc  string
	ts    int64 // which write it belongs to (goldenTS1 first, goldenTS2 second)
}

type nsExpect struct {
	desc      string
	hasBackup bool // written twice, so its manifest entry carries a Prev pointer
	secrets   map[string]secretExpect
}

// goldenContent is both the input the fixture is generated from and the contract
// every build must read back. Change it only together with -update-golden, which
// rewrites the committed ciphertext to match.
var goldenContent = map[string]nsExpect{
	"proj": {
		desc:      "Demo project secrets",
		hasBackup: true,
		secrets: map[string]secretExpect{
			"API_KEY":      {"sk-test-0123456789abcdef", "Third-party API token", goldenTS1},
			"DATABASE_URL": {"postgres://app:pw@localhost:5432/app", "Primary database DSN", goldenTS1},
			"GREETING":     {"héllo, wörld 🌍\nsecond line", "Unicode and a newline, to exercise the base64 round-trip", goldenTS2},
		},
	},
	"infra": {
		desc:      "Infrastructure settings",
		hasBackup: false,
		secrets: map[string]secretExpect{
			"REGION": {"eu-west-1", "Deployment region", goldenTS1},
		},
	},
}

func TestGoldenVault(t *testing.T) {
	if *updateGolden {
		generateGolden(t)
		return
	}
	ctx := context.Background()
	st := &local.Storage{Path: goldenDir}

	raw, err := st.GetHeader(ctx)
	if err != nil {
		t.Fatalf("read golden header (regenerate with -update-golden if the fixture is missing): %v", err)
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		t.Fatalf("parse golden header: %v", err)
	}
	if h.Version != 6 {
		t.Fatalf("golden vault header is v%d, want v6: the storage format is frozen for the 1.x line", h.Version)
	}

	// Unlock via the machine-identity recipient slot (no scrypt, opens under any
	// build) and via the passphrase slot (the scrypt-wrapped path). Both must yield
	// the same master.
	id, err := age.ParseX25519Identity(goldenIdentity)
	if err != nil {
		t.Fatal(err)
	}
	mkID, _, err := h.UnlockIdentity(id)
	if err != nil {
		t.Fatalf("machine-identity unlock failed: %v", err)
	}
	mkPass, _, _, err := h.Unlock(goldenPassphrase)
	if err != nil {
		t.Fatalf("passphrase unlock failed: %v", err)
	}
	if mkPass.PublicKey() != mkID.PublicKey() {
		t.Fatal("the passphrase and the machine identity opened different masters")
	}

	for _, ns := range sortedKeys(goldenContent) {
		want := goldenContent[ns]
		entry, ok := h.NamespaceEntry(ns)
		if !ok {
			t.Fatalf("namespace %q is missing from the manifest", ns)
		}
		switch {
		case want.hasBackup && entry.Prev == "":
			t.Errorf("namespace %q should carry a one-generation backup, but its manifest entry has no Prev pointer", ns)
		case !want.hasBackup && entry.Prev != "":
			t.Errorf("namespace %q should have no backup, but its manifest entry carries Prev %q", ns, entry.Prev)
		}

		state, err := secrets.For(st, ns, mkID).Read(ctx, entry)
		if err != nil {
			t.Fatalf("read namespace %q: %v", ns, err)
		}
		if state.Namespace.Description != want.desc {
			t.Errorf("namespace %q description = %q, want %q", ns, state.Namespace.Description, want.desc)
		}
		if len(state.Secrets) != len(want.secrets) {
			t.Errorf("namespace %q holds %d secrets, want %d", ns, len(state.Secrets), len(want.secrets))
		}
		for k, w := range want.secrets {
			if got := state.Secrets[k]; got != w.value {
				t.Errorf("namespace %q secret %q = %q, want %q", ns, k, got, w.value)
			}
			if got := state.Meta[k].Description; got != w.desc {
				t.Errorf("namespace %q secret %q description = %q, want %q", ns, k, got, w.desc)
			}
		}
	}

	// The one-generation backup is itself a valid, readable blob: the write proj
	// superseded. Reading it under its recorded PrevMAC proves the backup pointer
	// and its MAC survived the freeze.
	projEntry, _ := h.NamespaceEntry("proj")
	backup, err := secrets.For(st, "proj", mkID).Read(ctx, crypto.ManifestEntry{Blob: projEntry.Prev, MAC: projEntry.PrevMAC})
	if err != nil {
		t.Fatalf("read proj backup blob: %v", err)
	}
	if _, present := backup.Secrets["GREETING"]; present {
		t.Error("proj backup should predate the GREETING write, but contains it")
	}
	if got := backup.Secrets["API_KEY"]; got != goldenContent["proj"].secrets["API_KEY"].value {
		t.Errorf("proj backup API_KEY = %q, want the first-write value", got)
	}
}

func generateGolden(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := os.RemoveAll(goldenDir); err != nil {
		t.Fatal(err)
	}
	st := &local.Storage{Path: goldenDir}
	if err := st.Preflight(ctx); err != nil {
		t.Fatal(err)
	}

	h, mk, err := crypto.NewHeader(goldenPassphrase, "golden-laptop")
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.ParseX25519Identity(goldenIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddRecipientSlot(id.Recipient(), "golden-agent", mk); err != nil {
		t.Fatal(err)
	}
	verify := func(hh *crypto.Header) (*crypto.MasterKey, error) {
		m, _, e := hh.UnlockIdentity(id)
		return m, e
	}
	if err := keymgmt.SafePut(ctx, st, h, nil, mk, verify); err != nil {
		t.Fatal(err)
	}

	for _, ns := range sortedKeys(goldenContent) {
		c := goldenContent[ns]
		first := writesAt(c.secrets, goldenTS1)
		nsw := secrets.For(st, ns, mk).WithStamp(secrets.Stamp{By: goldenActor, TS: goldenTS1})
		if _, _, err := nsw.Commit(ctx, func(s *secrets.State) (*secrets.State, error) {
			out := s.Apply(first)
			out.Namespace.Description = c.desc
			return out, nil
		}, nil); err != nil {
			t.Fatalf("write namespace %q: %v", ns, err)
		}
		if c.hasBackup {
			second := writesAt(c.secrets, goldenTS2)
			nsw2 := secrets.For(st, ns, mk).WithStamp(secrets.Stamp{By: goldenActor, TS: goldenTS2})
			if _, _, err := nsw2.Commit(ctx, func(s *secrets.State) (*secrets.State, error) {
				return s.Apply(second), nil
			}, nil); err != nil {
				t.Fatalf("second write to namespace %q: %v", ns, err)
			}
		}
	}
	t.Logf("regenerated golden vault at %s", goldenDir)
}

func writesAt(secs map[string]secretExpect, ts int64) []secrets.Write {
	var ws []secrets.Write
	for _, k := range sortedKeys(secs) {
		if secs[k].ts != ts {
			continue
		}
		ws = append(ws, secrets.Write{Key: k, Value: secs[k].value, Description: secs[k].desc, TS: ts, By: goldenActor})
	}
	return ws
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
