package runner

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// referenceMask is the obviously-correct oracle the streaming matcher is graded
// against: whole-buffer, leftmost-longest, non-overlapping. At each cursor it
// replaces the longest pattern that starts there, else emits one byte. O(n*L), so
// only fit for tests, but its simplicity is the point: if the Masker's output
// matches it for every input and chunking, the streaming/maximal-munch machinery is
// correct, and in particular no secret byte escapes (a leak would be a divergence).
func referenceMask(patterns []pattern, input []byte) []byte {
	var out []byte
	for i := 0; i < len(input); {
		bestLen := 0
		var bestPh []byte
		for _, p := range patterns {
			// Strictly-longer wins, so the placeholder for equal-length patterns is
			// resolved differently here (first in slice) than in the Masker (last
			// candidate). That can only diverge if two distinct patterns share both
			// length and bytes, which buildPatterns dedups away, so the two agree.
			if len(p.value) > bestLen && bytes.HasPrefix(input[i:], p.value) {
				bestLen, bestPh = len(p.value), p.placeholder
			}
		}
		if bestLen > 0 {
			out = append(out, bestPh...)
			i += bestLen
		} else {
			out = append(out, input[i])
			i++
		}
	}
	return out
}

// maskChunked runs input through a fresh Masker, split at the given offsets, and
// returns the result. A correct masker's output is independent of where the writes
// are split.
func maskChunked(t *testing.T, secrets []Secret, floor int, input []byte, splits []int) []byte {
	t.Helper()
	var buf bytes.Buffer
	m := NewMaskerFloor(&buf, secrets, floor)
	prev := 0
	for _, s := range append(splits, len(input)) {
		if s < prev || s > len(input) {
			continue
		}
		if _, err := m.Write(input[prev:s]); err != nil {
			t.Fatalf("write: %v", err)
		}
		prev = s
	}
	if prev < len(input) {
		if _, err := m.Write(input[prev:]); err != nil {
			t.Fatalf("write tail: %v", err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return buf.Bytes()
}

// TestMaskerMatchesReference is the differential property test: for random secrets,
// inputs, and write splits, the streaming Masker must produce exactly what the
// reference oracle produces. A small alphabet with the secret bytes in it makes
// matches, nested patterns, overlaps, and split-mid-match common, so the tricky
// hold/resolve paths are exercised hard.
func TestMaskerMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("abc<>&\"\\/=+0\n ")
	randBytes := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return b
	}
	for iter := 0; iter < 20000; iter++ {
		var secrets []Secret
		for i, ns := 0, rng.Intn(4); i < ns; i++ {
			secrets = append(secrets, Secret{Name: fmt.Sprintf("S%d", i), Value: string(randBytes(1 + rng.Intn(7)))})
		}
		floor := 1 + rng.Intn(4)

		// Input is random bytes with secret values occasionally spliced in, so real
		// matches occur instead of being vanishingly unlikely.
		var input []byte
		for parts := rng.Intn(6); parts >= 0; parts-- {
			if len(secrets) > 0 && rng.Intn(2) == 0 {
				input = append(input, secrets[rng.Intn(len(secrets))].Value...)
			} else {
				input = append(input, randBytes(rng.Intn(6))...)
			}
		}

		var splits []int
		for s := rng.Intn(4); s >= 0; s-- {
			splits = append(splits, rng.Intn(len(input)+1))
		}

		want := referenceMask(buildPatterns(secrets, floor), input)
		got := maskChunked(t, secrets, floor, input, splits)
		if !bytes.Equal(got, want) {
			t.Fatalf("iter %d diverged:\n secrets=%v floor=%d\n input=%q\n splits=%v\n got  =%q\n want =%q",
				iter, secrets, floor, input, splits, got, want)
		}
	}
}

// FuzzMaskerMatchesReference is the same contract under the fuzzer: any byte string
// is carved into secrets, a floor, write splits, and input, then the streaming
// Masker is required to match the reference oracle. Wired with -tags fastkdf in CI.
func FuzzMaskerMatchesReference(f *testing.F) {
	f.Add([]byte("abcabc\x02\x01abcXabc"))
	f.Add([]byte("\x03\x02secret\x01value\x00leak secret value here"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		ns := int(data[0]) % 4
		floor := 1 + int(data[1])%4
		data = data[2:]

		var secrets []Secret
		for i := 0; i < ns && len(data) > 0; i++ {
			n := 1 + int(data[0])%8
			data = data[1:]
			if n > len(data) {
				n = len(data)
			}
			secrets = append(secrets, Secret{Name: fmt.Sprintf("S%d", i), Value: string(data[:n])})
			data = data[n:]
		}
		input := data

		// Derive a few split points deterministically from the input itself.
		var splits []int
		for i := 0; i < len(input); i += 7 {
			splits = append(splits, int(input[i])%(len(input)+1))
		}

		want := referenceMask(buildPatterns(secrets, floor), input)
		got := maskChunked(t, secrets, floor, input, splits)
		if !bytes.Equal(got, want) {
			t.Fatalf("diverged: secrets=%v floor=%d input=%q splits=%v\n got=%q\nwant=%q",
				secrets, floor, input, splits, got, want)
		}
	})
}
