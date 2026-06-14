package secrets_test

import (
	"context"
	"testing"
	"unicode/utf8"

	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/secrets"
)

// FuzzWriteReadRoundTrip: anything written through Apply + WriteBlob reads back
// byte-for-byte. Inputs with invalid UTF-8 are skipped because encoding/json
// coerces them to U+FFFD on the way out, and the secrets layer is only ever fed
// valid env names and values (the command layer validates names), so that
// coercion is not a layer this package is responsible for.
func FuzzWriteReadRoundTrip(f *testing.F) {
	f.Add("KEY", "value", "what it is for")
	f.Add("A", "", "")
	f.Add("MULTILINE", "line1\nline2\tend", "")
	f.Fuzz(func(t *testing.T, key, value, desc string) {
		if !utf8.ValidString(key) || !utf8.ValidString(value) || !utf8.ValidString(desc) {
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
	f.Add([]byte(`{"v":1,"ns":"proj","entries":{}}`))
	f.Add([]byte(`{"v":1,"ns":"proj","entries":{"K":{"value":"v","desc":"d","ts":1}}}`))
	f.Add([]byte(`{"v":999,"ns":"proj","entries":{}}`))
	f.Add([]byte(`{"v":1,"ns":"elsewhere","entries":{}}`))
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
