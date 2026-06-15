package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// Masker is a Writer that rewrites occurrences of injected secret values in a
// byte stream with placeholders before forwarding to dst. It exists for
// captured output: anything a child process prints can end up in an agent's
// context window, a CI log, or a shell pipeline, and a server that echoes its
// connection string on boot would otherwise hand the secret to whatever is
// reading. Masking is accident-proofing, not a boundary: code that already
// holds the secret can always move it some other way.
//
// Matching is exact byte matching, streamed: a value split across two writes
// is still caught (the longest tail that could open a secret is held back
// until later bytes decide). Flush emits whatever is still held at
// end-of-stream; callers must call it after the child exits or trailing
// output is lost.
type Masker struct {
	dst io.Writer
	// index groups patterns by their first byte, each bucket longest-first. Most
	// output positions start no secret, so the bucket is empty and matching is
	// O(1) there: the cost does not scale with the number of patterns, which is
	// what keeps masking snappy once each secret expands into several encodings.
	index map[byte][]pattern
	carry []byte
}

// Secret is one injected env var for masking purposes.
type Secret struct {
	Name  string
	Value string
}

// MinMaskLen is the shortest value the masker will rewrite. Below it, values
// are too likely to collide with ordinary output ("true", "8080") and would
// shred it; such secrets pass through unmasked by design.
const MinMaskLen = 6

type pattern struct {
	value       []byte
	placeholder []byte
}

// NewMasker builds a masker over dst for the given secrets. Values shorter
// than MinMaskLen are skipped; duplicate values collapse into one pattern
// (named after the first env var alphabetically). With no usable patterns the
// masker degrades to a plain passthrough.
func NewMasker(dst io.Writer, secrets []Secret) *Masker {
	return NewMaskerFloor(dst, secrets, MinMaskLen)
}

// NewMaskerFloor is NewMasker with an explicit minimum value length. A floor of
// 1 masks every non-empty value, for a consumer where keeping secrets out of the
// output outweighs occasionally shredding a short common string; the default
// floor trades that off the other way (it does not mangle ordinary short
// output). An empty value is always skipped, whatever the floor, since it would
// match at every position.
func NewMaskerFloor(dst io.Writer, secrets []Secret, minLen int) *Masker {
	sorted := append([]Secret(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	// Each secret expands into its literal value plus the common encodings a
	// program might apply before printing it (see encodedForms); all forms of one
	// secret share its placeholder. The floor is applied to the original value, so
	// a short secret and its encodings are all skipped together. seen dedups
	// forms across secrets (an alphanumeric token's percent-encoding equals its
	// literal, and two secrets may collide), first name alphabetically winning.
	seen := map[string]bool{}
	var patterns []pattern
	for _, s := range sorted {
		if s.Value == "" || len(s.Value) < minLen {
			continue
		}
		placeholder := fmt.Appendf(nil, "<notenv-masked:%s>", s.Name)
		for _, form := range encodedForms(s.Value) {
			if len(form) == 0 || seen[string(form)] {
				continue
			}
			seen[string(form)] = true
			patterns = append(patterns, pattern{value: form, placeholder: placeholder})
		}
	}
	sort.SliceStable(patterns, func(i, j int) bool { return len(patterns[i].value) > len(patterns[j].value) })
	index := map[byte][]pattern{}
	for _, p := range patterns { // patterns are non-empty, so value[0] is safe
		index[p.value[0]] = append(index[p.value[0]], p)
	}
	return &Masker{dst: dst, index: index}
}

// encodedForms returns the distinct byte forms of a secret value worth masking:
// the literal plus the common single-transform encodings a program is likely to
// apply before it reaches stdout (base64 into an auth header, hex, percent into a
// logged URL). notenv knows the exact value, so masking its encodings carries
// none of the false-positive risk a guessing scanner would. It deliberately does
// NOT catch a value concatenated into a larger blob and then encoded, chained
// transforms, or any egress notenv does not wrap (network, files); masking stays
// accident-proofing, not containment. Duplicates (common for alphanumeric tokens,
// whose percent-encoding equals the literal) are collapsed by the caller's seen.
func encodedForms(value string) [][]byte {
	v := []byte(value)
	hexLower := hex.EncodeToString(v)
	return [][]byte{
		v,
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawStdEncoding.EncodeToString(v)),
		[]byte(base64.URLEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
		[]byte(hexLower),
		[]byte(strings.ToUpper(hexLower)),
		[]byte(url.QueryEscape(value)),
		[]byte(url.PathEscape(value)),
	}
}

// Write rewrites complete matches and holds back a tail that might still
// become one. It always reports len(p) consumed: held bytes are not an error,
// they are emitted by a later Write or by Flush.
func (m *Masker) Write(p []byte) (int, error) {
	buf := p
	if len(m.carry) > 0 {
		buf = append(m.carry, p...)
		m.carry = nil
	}
	out := make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		rest := buf[i:]
		if m.partialAt(rest) {
			break // rest could still grow into a secret; hold it
		}
		if n, ph := m.completeAt(rest); n > 0 {
			out = append(out, ph...)
			i += n
			continue
		}
		out = append(out, rest[0])
		i++
	}
	m.carry = append(m.carry, buf[i:]...)
	if len(out) > 0 {
		if _, err := m.dst.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush emits the held tail. No more bytes are coming, so a partial prefix
// can no longer complete, but a shorter secret inside the tail still can,
// so the tail is re-scanned for complete matches rather than emitted raw.
func (m *Masker) Flush() error {
	buf := m.carry
	m.carry = nil
	out := make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		rest := buf[i:]
		if n, ph := m.completeAt(rest); n > 0 {
			out = append(out, ph...)
			i += n
			continue
		}
		out = append(out, rest[0])
		i++
	}
	if len(out) == 0 {
		return nil
	}
	_, err := m.dst.Write(out)
	return err
}

// partialAt reports whether rest, in its entirety, is a proper prefix of some
// secret, i.e. bytes still to come could complete a match. This deliberately
// outranks a shorter complete match at the same position: holding is always
// safe (the next Write or Flush resolves it), while emitting early could split
// a longer secret in two and leak its tail.
// rest is always non-empty here (the Write/Flush loops only call it with
// buf[i:] for i < len(buf)), so rest[0] selects the only bucket that can match.
func (m *Masker) partialAt(rest []byte) bool {
	for _, p := range m.index[rest[0]] {
		if len(rest) < len(p.value) && bytes.HasPrefix(p.value, rest) {
			return true
		}
	}
	return false
}

// completeAt reports the longest secret starting exactly at rest's head.
func (m *Masker) completeAt(rest []byte) (int, []byte) {
	for _, p := range m.index[rest[0]] { // longest first within the bucket
		if len(rest) >= len(p.value) && bytes.HasPrefix(rest, p.value) {
			return len(p.value), p.placeholder
		}
	}
	return 0, nil
}
