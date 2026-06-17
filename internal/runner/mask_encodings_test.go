package runner

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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

// TestMaskerCatchesBase32: a value base32'd, both padded and not (TOTP seeds and
// recovery tokens are commonly base32).
func TestMaskerCatchesBase32(t *testing.T) {
	secret := "supersecretvalue"
	for _, enc := range []string{
		base32.StdEncoding.EncodeToString([]byte(secret)),
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret)),
	} {
		got := write(t, []Secret{{Name: "K", Value: secret}}, "otpauth seed="+enc+"\n")
		if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
			t.Fatalf("base32 of the secret leaked: %q", got)
		}
	}
}

// TestMaskerCatchesJSONEscaped: a secret containing characters JSON escapes
// (quote, backslash) is masked when logged inside a JSON string, where it appears
// as its escaped bytes, not its literal ones.
func TestMaskerCatchesJSONEscaped(t *testing.T) {
	secret := `pa"ss\word`
	quoted, _ := json.Marshal(secret)
	enc := string(quoted[1 : len(quoted)-1]) // pa\"ss\\word
	if enc == secret {
		t.Fatal("test value must actually need JSON escaping")
	}
	got := write(t, []Secret{{Name: "K", Value: secret}}, `{"token":"`+enc+`"}`+"\n")
	if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
		t.Fatalf("JSON-escaped secret leaked: %q", got)
	}
}

// TestMaskerCatchesHTMLEscaped: a secret with HTML metacharacters is masked when
// rendered into HTML/XML as its escaped entities.
func TestMaskerCatchesHTMLEscaped(t *testing.T) {
	secret := `secret<&>"x`
	enc := html.EscapeString(secret) // secret&lt;&amp;&gt;&#34;x
	if enc == secret {
		t.Fatal("test value must actually need HTML escaping")
	}
	got := write(t, []Secret{{Name: "K", Value: secret}}, "<input value=\""+enc+"\">\n")
	if strings.Contains(got, enc) || !strings.Contains(got, "<notenv-masked:K>") {
		t.Fatalf("HTML-escaped secret leaked: %q", got)
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

// longSecret is a PEM-shaped value of about n bytes: notenv accepts
// arbitrary-length secrets, and a full private key or cert bundle is kilobytes.
func longSecret(n int) string {
	var b strings.Builder
	b.WriteString("-----BEGIN PRIVATE KEY-----\n")
	for b.Len() < n {
		b.WriteString("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh\n")
	}
	return b.String()
}

// BenchmarkMaskerLongSecret shows how cost scales with secret length, for a long
// secret printed in one Write versus small chunks. The small-writes case is the
// streaming-hold worst case: each chunk extends a partial match, so the matcher
// holds the growing buffer and re-scans it from offset 0 every Write, making cost
// quadratic in the secret length (the PEM concern). Compare the small-writes row's
// growth across sizes against one-write's to read the quadratic off the numbers.
func BenchmarkMaskerLongSecret(b *testing.B) {
	for _, kb := range []int{1, 8, 64} {
		secret := longSecret(kb * 1024)
		secrets := []Secret{{Name: "KEY", Value: secret}}
		data := []byte(secret)
		var chunks [][]byte
		for s := data; len(s) > 0; {
			c := min(16, len(s))
			chunks = append(chunks, s[:c])
			s = s[c:]
		}
		b.Run(fmt.Sprintf("%dKB/one-write", kb), func(b *testing.B) {
			for b.Loop() {
				m := NewMasker(io.Discard, secrets)
				_, _ = m.Write(data)
				_ = m.Flush()
			}
		})
		b.Run(fmt.Sprintf("%dKB/small-writes", kb), func(b *testing.B) {
			for b.Loop() {
				m := NewMasker(io.Discard, secrets)
				for _, c := range chunks {
					_, _ = m.Write(c)
				}
				_ = m.Flush()
			}
		})
	}
}
