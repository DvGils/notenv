package runner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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
// Matching is exact-byte, streamed, by maximal munch: from the leftmost
// unresolved byte it extends a held window as far as some pattern's prefix allows,
// then replaces the longest pattern that started there. A value split across writes
// is still caught (the window is held until later bytes decide), and Flush emits
// whatever is still held at end-of-stream, so callers must call it after the child
// exits or trailing output is lost. It is tuned for few but possibly long patterns
// (a handful of secrets, each expanded into encodings, any of which can be
// kilobytes, like a PEM): patterns are kept flat (cheap to build, small) and grouped
// by first byte, and while a window is held a small candidate list (the patterns it
// is still a prefix of) is narrowed byte by byte. The window and candidates persist
// across Writes, so a value split over many small writes is matched once, not
// re-scanned each Write: cost stays linear in the stream, not quadratic in the value.
type Masker struct {
	dst       io.Writer
	patterns  []pattern
	firstByte map[byte][]int // pattern indices keyed by value[0]; empty => passthrough

	// Held-window state, persisted across Writes. buf is the bytes held from the
	// current anchor; cand (owned, never aliasing a firstByte bucket) is the indices
	// of patterns that have buf as a prefix; bestLen/bestPh are the longest pattern
	// that has fully matched at the anchor so far (0 if none).
	buf     []byte
	cand    []int
	bestLen int
	bestPh  []byte
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
	patterns := buildPatterns(secrets, minLen)
	firstByte := map[byte][]int{}
	for i, p := range patterns { // values are non-empty, so value[0] is safe
		firstByte[p.value[0]] = append(firstByte[p.value[0]], i)
	}
	return &Masker{dst: dst, patterns: patterns, firstByte: firstByte}
}

// buildPatterns expands secrets into the byte patterns to match: each secret's
// literal plus its encodings (see encodedForms), all sharing one placeholder.
// Values below the floor (and their encodings) are skipped, and forms that collide
// (an alphanumeric token whose encoding equals its literal, or two secrets with the
// same value) are deduped, the first name alphabetically winning.
func buildPatterns(secrets []Secret, minLen int) []pattern {
	sorted := append([]Secret(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

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
	return patterns
}

// encodedForms returns the distinct byte forms of a secret value worth masking:
// the literal plus the common single-transform encodings a program is likely to
// apply before it reaches stdout. Each is one transform a value plausibly passes
// through on the way to a log or response: base64 (an auth header or token blob),
// base32 (a TOTP seed or recovery token), hex, percent-encoding (a logged URL),
// JSON string-escaping (a value inside a JSON body), and HTML escaping (a value
// rendered into a page). notenv knows the exact value, so masking its encodings
// carries none of the false-positive risk a guessing scanner would. It deliberately
// does NOT catch a value concatenated into a larger blob and then encoded, chained
// transforms, escaping variants a different library would emit (a non-HTML-safe JSON
// encoder, &quot; instead of &#34;), or any egress notenv does not wrap (network,
// files); masking stays accident-proofing, not containment. Forms that coincide
// (an alphanumeric token escapes to itself) are collapsed by the caller's seen set.
func encodedForms(value string) [][]byte {
	v := []byte(value)
	hexLower := hex.EncodeToString(v)
	// json.Marshal of a string never errors; it wraps the value in quotes and
	// escapes it the way a program logging the secret inside JSON would (Go's
	// default also escapes < > & as <…, the HTML-safe form). The surrounding
	// quotes are JSON structure, not part of the value, so they are trimmed: the
	// masker matches the escaped bytes wherever they appear. For an alphanumeric
	// token this equals the literal and is dropped by the caller's dedup.
	jsonQuoted, _ := json.Marshal(value)
	jsonInner := jsonQuoted[1 : len(jsonQuoted)-1]
	return [][]byte{
		v,
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawStdEncoding.EncodeToString(v)),
		[]byte(base64.URLEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
		[]byte(base32.StdEncoding.EncodeToString(v)),
		[]byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(v)),
		[]byte(hexLower),
		[]byte(strings.ToUpper(hexLower)),
		[]byte(url.QueryEscape(value)),
		[]byte(url.PathEscape(value)),
		jsonInner,
		[]byte(html.EscapeString(value)),
	}
}

// Write feeds p through the matcher and forwards settled output. A value that may
// still be completing is held (in m.buf) for a later Write or Flush, so it always
// reports len(p) consumed: held bytes are not an error. With no patterns it is a
// plain passthrough.
func (m *Masker) Write(p []byte) (int, error) {
	if len(m.firstByte) == 0 {
		if _, err := m.dst.Write(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// Size out by p, not by the held window: a Write emits at most the bytes it
	// settles (a held value contributes a single placeholder when it completes, or
	// is flushed out only once if it never matches), so it must not allocate in
	// proportion to a growing hold, or a long value in many small writes is
	// quadratic in allocation. append grows out on the rare large settle.
	out := make([]byte, 0, len(p))
	m.process(p, &out)
	if len(out) > 0 {
		if _, err := m.dst.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// process feeds in through the matcher, appending settled bytes (and placeholders
// for matches) to out and leaving any unresolved window in m.buf. The window and
// its candidate set persist across calls: an incoming byte that extends the window
// narrows the candidates in O(len(cand)) with no re-scan of what is already held.
// Only when a byte cannot extend the window does it resolve the front (the longest
// pattern that started at the anchor, else one byte) and re-process the small
// leftover.
func (m *Masker) process(in []byte, out *[]byte) {
	// Bytes are pulled from refeed first (leftover re-queued after a resolve), then
	// from in by index: in itself is never copied, so a divergence costs only the
	// bounded held window, not the rest of the stream.
	var refeed []byte
	ri, ii := 0, 0
	for {
		var c byte
		switch {
		case ri < len(refeed):
			c, ri = refeed[ri], ri+1
		case ii < len(in):
			c, ii = in[ii], ii+1
		default:
			return
		}

		if len(m.buf) == 0 {
			// Not holding: does c begin any pattern?
			bucket := m.firstByte[c]
			if len(bucket) == 0 {
				*out = append(*out, c)
				continue
			}
			m.cand = append(m.cand[:0], bucket...) // owned copy; never mutate the bucket
			m.buf = append(m.buf, c)
			m.bestLen, m.bestPh = 0, nil
			for _, pi := range bucket { // a length-1 pattern completes immediately
				if len(m.patterns[pi].value) == 1 {
					m.bestLen, m.bestPh = 1, m.patterns[pi].placeholder
				}
			}
			continue
		}

		// Holding: narrow candidates to those that c extends (still matching at the
		// next position), recording any that complete exactly here.
		off := len(m.buf)
		w := 0
		var doneLen int
		var donePh []byte
		for _, pi := range m.cand {
			v := m.patterns[pi].value
			if len(v) > off && v[off] == c {
				m.cand[w] = pi
				w++
				if len(v) == off+1 {
					doneLen, donePh = off+1, m.patterns[pi].placeholder
				}
			}
		}
		if w > 0 {
			m.cand = m.cand[:w]
			m.buf = append(m.buf, c)
			if doneLen > 0 {
				m.bestLen, m.bestPh = doneLen, donePh
			}
			continue
		}

		// c cannot extend the held window: resolve its front (longest pattern from
		// the anchor, else one byte), then re-queue the leftover and c ahead of any
		// remaining refeed. leftover and c are copied into a fresh slice first, since
		// leftover aliases m.buf's storage which is about to be reset.
		var leftover []byte
		if m.bestLen > 0 {
			*out = append(*out, m.bestPh...)
			leftover = m.buf[m.bestLen:]
		} else {
			*out = append(*out, m.buf[0])
			leftover = m.buf[1:]
		}
		nr := make([]byte, 0, len(leftover)+1+len(refeed)-ri)
		nr = append(nr, leftover...)
		nr = append(nr, c)
		nr = append(nr, refeed[ri:]...)
		refeed, ri = nr, 0
		m.buf = m.buf[:0]
		m.cand = m.cand[:0]
		m.bestLen, m.bestPh = 0, nil
	}
}

// Flush drains the held window at end of stream. No more bytes can extend it, so a
// held prefix can no longer complete: resolve its front (the longest pattern that
// started at the anchor, else one byte) and re-walk the leftover, which exposes a
// shorter or later match the hold was deferring, until nothing is held. Callers
// must Flush after the child exits or trailing output is lost.
func (m *Masker) Flush() error {
	out := make([]byte, 0, len(m.buf))
	for len(m.buf) > 0 {
		var leftover []byte
		if m.bestLen > 0 {
			out = append(out, m.bestPh...)
			leftover = append([]byte(nil), m.buf[m.bestLen:]...)
		} else {
			out = append(out, m.buf[0])
			leftover = append([]byte(nil), m.buf[1:]...)
		}
		m.buf = m.buf[:0]
		m.cand = m.cand[:0]
		m.bestLen, m.bestPh = 0, nil
		m.process(leftover, &out)
	}
	if len(out) == 0 {
		return nil
	}
	_, err := m.dst.Write(out)
	return err
}
