package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
)

// TestMaskerCatchesBase64: a value base64'd (the common single transform, an
// auth header or a token blob) is masked, in all four base64 variants.
func TestMaskerCatchesBase64(t *testing.T) {
	secret := "supersecretvalue"
	for name, enc := range map[string]string{
		"std":     base64.StdEncoding.EncodeToString([]byte(secret)),
		"std-raw": base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"url":     base64.URLEncoding.EncodeToString([]byte(secret)),
		"url-raw": base64.RawURLEncoding.EncodeToString([]byte(secret)),
	} {
		got := write(t, []Secret{{Name: "K", Value: secret}}, "header "+enc+" end\n")
		if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
			t.Fatalf("%s base64 of the secret leaked: %q", name, got)
		}
	}
}

// TestMaskerCatchesHex: a value hex-encoded, in both cases.
func TestMaskerCatchesHex(t *testing.T) {
	secret := "supersecretvalue"
	lower := hex.EncodeToString([]byte(secret))
	for _, enc := range []string{lower, strings.ToUpper(lower)} {
		got := write(t, []Secret{{Name: "K", Value: secret}}, "key="+enc+"\n")
		if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
			t.Fatalf("hex of the secret leaked: %q", got)
		}
	}
}

// TestMaskerCatchesPercentEncoding: a value with special characters
// percent-encoded into a URL (the common connection-string-in-a-log case).
func TestMaskerCatchesPercentEncoding(t *testing.T) {
	secret := "p@ss w0rd/with+special"
	for _, enc := range []string{url.QueryEscape(secret), url.PathEscape(secret)} {
		got := write(t, []Secret{{Name: "K", Value: secret}}, "postgres://u:"+enc+"@host/db\n")
		if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
			t.Fatalf("percent-encoded secret leaked: %q", got)
		}
	}
}

// TestMaskerSkipsShortValueAndItsEncodings: a value below the floor passes
// through, and so do its encodings (we never start masking a short secret via
// the back door of an encoding).
func TestMaskerSkipsShortValueAndItsEncodings(t *testing.T) {
	secret := "abc" // below MinMaskLen
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	got := write(t, []Secret{{Name: "K", Value: secret}}, "v="+secret+" enc="+b64+"\n")
	if !strings.Contains(got, secret) || !strings.Contains(got, b64) {
		t.Fatalf("a sub-floor value and its encodings must pass through unmasked: %q", got)
	}
}

// TestMaskerLiteralStillCaught: the encoding expansion must not regress the
// literal-value match.
func TestMaskerLiteralStillCaught(t *testing.T) {
	got := write(t, []Secret{{Name: "K", Value: "s3cretvalue"}}, "raw s3cretvalue here\n")
	if strings.Contains(got, "s3cretvalue") || !strings.Contains(got, "<notenv-masked:K>") {
		t.Fatalf("literal value leaked: %q", got)
	}
}

// BenchmarkMaskerManySecrets exercises the first-byte index: 100 secrets, each
// expanding into several encodings (~hundreds of patterns), over output that
// matches none of them. The index keeps per-byte cost off the pattern count.
func BenchmarkMaskerManySecrets(b *testing.B) {
	secrets := make([]Secret, 100)
	for i := range secrets {
		secrets[i] = Secret{Name: fmt.Sprintf("S%d", i), Value: fmt.Sprintf("secretvalue-%020d", i)}
	}
	data := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 1000)
	for b.Loop() {
		m := NewMasker(io.Discard, secrets)
		_, _ = m.Write(data)
		_ = m.Flush()
	}
}
