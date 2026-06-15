package secrets_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/secrets"
)

func TestValidateValue(t *testing.T) {
	valid := []string{
		"",
		"token123",
		"with spaces and a\ttab",
		"-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----", // multiline PEM
		"crlf\r\nline",                                     // CRLF cert
		"unicode: køde 世界 🎉",
	}
	for _, v := range valid {
		if err := secrets.ValidateValue(v); err != nil {
			t.Errorf("ValidateValue(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"nul\x00byte",
		"esc\x1b[31m",
		"bell\x07",
		"del\x7f",
		"vtab\x0b",
		"formfeed\x0c",
		"\xff\xfe not valid utf8",
	}
	for _, v := range invalid {
		if err := secrets.ValidateValue(v); err == nil {
			t.Errorf("ValidateValue(%q) = nil, want error", v)
		}
	}
}

// TestBlobPreservesBytesExactly: a value carrying the allowed newline family, and
// a description carrying arbitrary bytes (descriptions are not gated), both
// survive the blob round-trip byte-for-byte. This is the base64 backstop: storage
// never coerces a stored byte to U+FFFD.
func TestBlobPreservesBytesExactly(t *testing.T) {
	v := newVault(t)
	value := "line1\nline2\twith tab\rand cr"
	desc := "desc with \x00 nul, \xff invalid utf8, \x1b esc, and a\nnewline"
	v.write(t, secrets.Write{Key: "K", Value: value, Description: desc, TS: 1})
	st := v.read(t)
	if st.Secrets["K"] != value {
		t.Errorf("value not preserved:\n got %q\nwant %q", st.Secrets["K"], value)
	}
	if st.Meta["K"].Description != desc {
		t.Errorf("description not preserved:\n got %q\nwant %q", st.Meta["K"].Description, desc)
	}
}

// TestWriteBlobRejectsBadValue: the storage chokepoint refuses a value that
// slipped past the command layer (here a NUL), naming the key, so nothing
// un-injectable is ever persisted.
func TestWriteBlobRejectsBadValue(t *testing.T) {
	v := newVault(t)
	ctx := context.Background()
	cur, err := v.ns().Read(ctx, v.entry)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	next := cur.Apply([]secrets.Write{{Key: "TOKEN", Value: "bad\x00value"}})
	if _, _, err := v.ns().WriteBlob(ctx, next, v.entry); err == nil {
		t.Fatal("WriteBlob accepted a value containing NUL; want rejection")
	} else if !strings.Contains(err.Error(), "TOKEN") {
		t.Errorf("rejection should name the offending key, got: %v", err)
	}
}
