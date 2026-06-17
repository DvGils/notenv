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
// Matching is exact-byte, streamed, leftmost-longest, and non-overlapping: each
// output position is replaced by the longest pattern that starts there, then
// scanning resumes after it. A value split across writes is still caught (the
// decision for a position is deferred until later bytes settle it), and Flush emits
// whatever is still pending at end-of-stream, so callers must call it after the
// child exits or trailing output is lost.
//
// Each pattern runs as its own KMP automaton (a flat failure table per pattern),
// all advanced one step per input byte. KMP's failure links mean a byte is never
// re-scanned, so the cost is linear in the stream and a fixed factor of the pattern
// count, never quadratic in the pattern length: this matters because patterns can
// be kilobytes (a handful of secrets, each expanded into encodings, any of which
// may be a PEM). A byte that starts no pattern and extends no live match is emitted
// at once (plain passthrough); a byte is held only while some automaton is mid-match
// and could still complete a match covering it, so the hold is bounded by the
// longest live partial match (at most one pattern length), and is zero for output
// that touches no secret.
type Masker struct {
	dst       io.Writer
	patterns  []pattern
	fail      [][]int32      // KMP failure table per pattern (the partial-match function)
	firstByte map[byte][]int // pattern indices keyed by value[0]; empty => passthrough

	// Matcher state, persisted across Writes so a value split over many writes is
	// matched once. q[i] is pattern i's KMP state (length of the prefix matched
	// ending at the last byte); active lists the patterns with q>0, the only ones a
	// byte can advance besides those a byte freshly starts.
	q      []int32
	active []int

	// Pending emit queue. buf[bh:] are bytes read but not yet settled; mlen/midx[j]
	// record the longest match that starts at buf[j] (mlen 0, midx -1 if none). A
	// front byte is settled, and emitted, once no live automaton could still begin a
	// match at it, so the queue holds at most the longest live partial match.
	buf  []byte
	mlen []int32
	midx []int32
	bh   int
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
	fail := make([][]int32, len(patterns))
	firstByte := map[byte][]int{}
	for i, p := range patterns { // values are non-empty, so value[0] is safe
		fail[i] = buildFail(p.value)
		firstByte[p.value[0]] = append(firstByte[p.value[0]], i)
	}
	return &Masker{dst: dst, patterns: patterns, fail: fail, firstByte: firstByte, q: make([]int32, len(patterns))}
}

// buildFail returns the KMP failure table for v: fail[i] is the length of the
// longest proper prefix of v[:i+1] that is also a suffix of it, the jump that lets
// the matcher resume after a mismatch without re-reading any byte.
func buildFail(v []byte) []int32 {
	fail := make([]int32, len(v))
	var k int32
	for i := 1; i < len(v); i++ {
		for k > 0 && v[i] != v[k] {
			k = fail[k-1]
		}
		if v[i] == v[k] {
			k++
		}
		fail[i] = k
	}
	return fail
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

// process feeds in through the matcher one byte at a time, appending settled bytes
// (and placeholders for matches) to out and leaving the unsettled tail pending in
// m.buf. Each byte advances every live automaton plus any the byte starts (O(1)
// amortized each, no re-scan), records the longest match that completes, then emits
// every front byte no live automaton could still begin a match at.
func (m *Masker) process(in []byte, out *[]byte) {
	for _, b := range in {
		// Enqueue the byte with an empty match record; matches completing here fill it
		// in at the position where they start.
		m.buf = append(m.buf, b)
		m.mlen = append(m.mlen, 0)
		m.midx = append(m.midx, -1)
		pos := len(m.buf) - 1

		// Advance the in-progress automata, recording any completed match and the
		// largest surviving state (maxQ: the longest live partial match, which is also
		// how many trailing bytes must stay pending).
		var maxQ int32
		w := 0
		for _, pi := range m.active {
			nq, matched := m.step(pi, b)
			m.q[pi] = nq
			if matched {
				m.record(pi, pos)
			}
			if nq > 0 {
				m.active[w] = pi
				w++
				if nq > maxQ {
					maxQ = nq
				}
			}
		}
		m.active = m.active[:w]

		// Start the automata this byte begins (q was 0; ones already advanced above
		// kept q>0 and are skipped). A length-1 pattern completes here and stays at 0.
		for _, pi := range m.firstByte[b] {
			if m.q[pi] != 0 {
				continue
			}
			nq, matched := m.step(pi, b)
			m.q[pi] = nq
			if matched {
				m.record(pi, pos)
			}
			if nq > 0 {
				m.active = append(m.active, pi)
				if nq > maxQ {
					maxQ = nq
				}
			}
		}

		// A front byte is settled once it sits before the earliest position any live
		// automaton is still building from (pending length > maxQ). Emit settled
		// bytes, taking the longest match recorded at each, else one literal byte.
		for len(m.buf)-m.bh > int(maxQ) {
			if m.mlen[m.bh] > 0 {
				*out = append(*out, m.patterns[m.midx[m.bh]].placeholder...)
				m.bh += int(m.mlen[m.bh])
			} else {
				*out = append(*out, m.buf[m.bh])
				m.bh++
			}
		}
		if m.bh > 0 && m.bh >= len(m.buf)-m.bh {
			m.compact() // dead prefix has overtaken the live tail; reclaim it
		}
	}
}

// step advances pattern pi's KMP automaton by one byte, following failure links on
// a mismatch. It returns the new state and whether a full match just completed; on
// a match the state is rolled back along the failure link so overlapping matches
// still fire.
func (m *Masker) step(pi int, b byte) (int32, bool) {
	v := m.patterns[pi].value
	f := m.fail[pi]
	k := m.q[pi]
	for k > 0 && v[k] != b {
		k = f[k-1]
	}
	if v[k] == b {
		k++
	}
	if int(k) == len(v) {
		return f[k-1], true
	}
	return k, false
}

// record notes that pattern pi completed a match ending at buf position pos, at the
// position it started; the longest match starting there wins (leftmost-longest). A
// match starting before the pending front (start < bh) begins inside output already
// emitted, so it overlaps a match (or literal run) already committed; the resume is
// non-overlapping, so it is dropped. Any start at or after the front is real: a
// position is emitted only once no automaton can still be building from it, so a
// match that completes later cannot start in already-emitted, non-consumed output.
func (m *Masker) record(pi, pos int) {
	ml := len(m.patterns[pi].value)
	start := pos - ml + 1
	if start < m.bh {
		return
	}
	if int32(ml) > m.mlen[start] {
		m.mlen[start] = int32(ml)
		m.midx[start] = int32(pi)
	}
}

// compact slides the live pending region to the front of the buffers, reclaiming
// the emitted prefix. Triggered only when the dead prefix has grown past the live
// tail, so it is amortized O(1) per byte.
func (m *Masker) compact() {
	n := copy(m.buf, m.buf[m.bh:])
	m.buf = m.buf[:n]
	copy(m.mlen, m.mlen[m.bh:])
	m.mlen = m.mlen[:n]
	copy(m.midx, m.midx[m.bh:])
	m.midx = m.midx[:n]
	m.bh = 0
}

// Flush drains the pending queue at end of stream: no more bytes can arrive, so
// every pending byte is settled. It emits the longest recorded match at each front
// position, else one literal byte, then resets the matcher so a later Write starts
// clean. Callers must Flush after the child exits or trailing output is lost.
func (m *Masker) Flush() error {
	out := make([]byte, 0, len(m.buf)-m.bh)
	for len(m.buf)-m.bh > 0 {
		if m.mlen[m.bh] > 0 {
			out = append(out, m.patterns[m.midx[m.bh]].placeholder...)
			m.bh += int(m.mlen[m.bh])
		} else {
			out = append(out, m.buf[m.bh])
			m.bh++
		}
	}
	m.buf, m.mlen, m.midx, m.bh = m.buf[:0], m.mlen[:0], m.midx[:0], 0
	for _, pi := range m.active {
		m.q[pi] = 0
	}
	m.active = m.active[:0]
	if len(out) == 0 {
		return nil
	}
	_, err := m.dst.Write(out)
	return err
}
