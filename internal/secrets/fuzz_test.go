package secrets_test

import (
	"context"
	"fmt"
	"testing"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/secrets"
)

// seededFast is seeded() without scrypt: a header sealed under the master via an
// X25519 recipient instead of a passphrase slot. Commit only needs a header it
// can verify and re-seal under the master (it never unlocks a passphrase), so
// this is equivalent for the write path and orders of magnitude cheaper, which
// matters when it runs once per fuzz exec.
func seededFast(t *testing.T) (*memstore.Store, *crypto.MasterKey) {
	t.Helper()
	ctx := context.Background()
	mem := memstore.New()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	header, mk, err := crypto.NewRecipientHeader(id.Recipient(), "fuzz")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(h *crypto.Header) (*crypto.MasterKey, error) { m, _, e := h.UnlockIdentity(id); return m, e }
	if err := keymgmt.SafePut(ctx, mem, header, nil, mk, verify); err != nil {
		t.Fatal(err)
	}
	return mem, mk
}

// FuzzWriteReadRoundTrip: any storable value written through Apply + WriteBlob
// reads back byte-for-byte. The value must satisfy the storage contract
// (secrets.ValidateValue: valid UTF-8, no control bytes beyond the newline
// family), so a value outside it is skipped, not a failure (WriteBlob rejects it
// by design). The key is skipped only when it is not valid UTF-8, since it becomes
// a JSON map key and encoding/json coerces invalid UTF-8 there to U+FFFD. The
// description is unconstrained: it is stored base64-encoded (blob v2), so any byte
// sequence round-trips, which is exactly what this also checks.
func FuzzWriteReadRoundTrip(f *testing.F) {
	f.Add("KEY", "value", "what it is for")
	f.Add("A", "", "")
	f.Add("MULTILINE", "line1\nline2\tend", "")
	f.Add("DESC_RAW_BYTES", "ok", "desc with \x00 and \xff bytes")
	f.Fuzz(func(t *testing.T, key, value, desc string) {
		if !utf8.ValidString(key) || secrets.ValidateValue(value) != nil {
			t.Skip()
		}
		ctx := context.Background()
		v := newVault(t)
		empty, err := v.ns().Read(ctx, crypto.ManifestEntry{})
		if err != nil {
			t.Fatal(err)
		}
		state := empty.Apply([]secrets.Write{{Key: key, Value: value, Description: desc}})
		_, entry, err := v.ns().WriteBlob(ctx, state, crypto.ManifestEntry{})
		if err != nil {
			t.Fatalf("write blob: %v", err)
		}
		got, err := v.ns().Read(ctx, entry)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if got.Secrets[key] != value {
			t.Fatalf("round-trip value for key %q: got %q want %q", key, got.Secrets[key], value)
		}
		if got.Meta[key].Description != desc {
			t.Fatalf("round-trip desc for key %q: got %q want %q", key, got.Meta[key].Description, desc)
		}
	})
}

// FuzzReadDecodeNeverPanics feeds arbitrary plaintext (sealed under the real
// master, with the matching MAC, so the read gets all the way into JSON decode
// and the version/namespace checks) and requires the read to resolve to either a
// clean error or a non-nil state, never a panic and never nil-state-with-nil-err.
func FuzzReadDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(`{"v":2,"ns":"proj","entries":{}}`))
	f.Add([]byte(`{"v":2,"ns":"proj","entries":{"K":{"value":"dg==","desc":"ZA==","ts":1}}}`)) // base64("v"), base64("d")
	f.Add([]byte(`{"v":2,"ns":"proj","entries":{"K":{"value":"!notbase64","ts":1}}}`))         // invalid base64: clean corrupt error, no panic
	f.Add([]byte(`{"v":1,"ns":"proj","entries":{}}`))                                          // older format: clean version error
	f.Add([]byte(`{"v":999,"ns":"proj","entries":{}}`))
	f.Add([]byte(`{"v":2,"ns":"elsewhere","entries":{}}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, plain []byte) {
		ctx := context.Background()
		v := newVault(t)
		mac, err := v.mk.BlobMAC(plain)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := v.mk.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		const key = "proj/data-fuzz.age"
		if err := v.store.Put(ctx, key, sealed); err != nil {
			t.Fatal(err)
		}
		state, err := v.ns().Read(ctx, crypto.ManifestEntry{Blob: key, MAC: mac})
		if err == nil && state == nil {
			t.Fatal("Read returned nil state with a nil error")
		}
	})
}

// FuzzCommitSequence drives a fuzzed sequence of sets and deletes through the
// real Commit path (the header compare-and-swap, read-modify-write, last-write-
// wins merge, orphan reclaim, and one-generation backup) and checks two
// invariants against a plain in-memory model: the namespace reads back exactly
// the model's last-write-wins state, and no blob is left in storage that the
// manifest does not reference. Keys are drawn from a small set so the same key is
// overwritten and deleted repeatedly, which is what exercises the merge and the
// reclaim. Arbitrary key/value/description content is FuzzWriteReadRoundTrip's
// axis; this target fuzzes the order of operations instead.
func FuzzCommitSequence(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x11, 0x02, 0x00, 0x00}) // two sets, then delete k0
	f.Add([]byte{0x01, 0x00, 0x05, 0x00})             // overwrite the same key
	f.Add([]byte{})                                   // no ops: namespace stays empty
	f.Fuzz(func(t *testing.T, script []byte) {
		ctx := context.Background()
		mem, mk := seededFast(t)
		ns := secrets.For(mem, "proj", mk)

		const numKeys = 4
		model := map[string]string{}
		var header *crypto.Header

		// Each op is two bytes: the operation (a delete one time in four) and the
		// key index. The same key recurs, so overwrites and deletes pile up.
		for i := 0; i+1 < len(script); i += 2 {
			op, arg := script[i], script[i+1]
			key := fmt.Sprintf("k%d", int(arg)%numKeys)
			w := secrets.Write{Key: key, Value: fmt.Sprintf("v%d", op)}
			if op%4 == 0 {
				w = secrets.Write{Key: key, Deleted: true}
				delete(model, key)
			} else {
				model[key] = w.Value
			}
			_, h, err := ns.Commit(ctx, func(cur *secrets.State) (*secrets.State, error) {
				return cur.Apply([]secrets.Write{w}), nil
			}, nil)
			if err != nil {
				t.Fatalf("commit %+v: %v", w, err)
			}
			header = h
		}

		// Invariant 1: the namespace reads back exactly the model's LWW state.
		var entry crypto.ManifestEntry
		if header != nil {
			entry, _ = header.NamespaceEntry("proj")
		}
		got, err := ns.Read(ctx, entry)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if len(got.Secrets) != len(model) {
			t.Fatalf("read %d secrets, model has %d: %v vs %v", len(got.Secrets), len(model), got.Secrets, model)
		}
		for k, v := range model {
			if got.Secrets[k] != v {
				t.Fatalf("key %q: read %q, model %q", k, got.Secrets[k], v)
			}
		}

		// Invariant 2: every blob in storage is referenced by the manifest entry
		// (the current blob or its one-generation backup); reclaim leaks nothing.
		blobs, err := mem.List(ctx, "proj/")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		referenced := map[string]bool{}
		if entry.Blob != "" {
			referenced[entry.Blob] = true
		}
		if entry.Prev != "" {
			referenced[entry.Prev] = true
		}
		for _, b := range blobs {
			if !referenced[b] {
				t.Fatalf("orphan blob %q in storage but not referenced by the manifest (entry %+v)", b, entry)
			}
		}
	})
}
