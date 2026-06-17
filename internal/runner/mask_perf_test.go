package runner

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMaskerStreamingIsSubQuadratic guards against the masker regressing to the
// O(N*L) re-scan. A secret whose value is a long run of one byte makes the held
// window grow toward L and break on (almost) every input byte, so a matcher that
// re-scans the held window on each break does O(N*L) work. A linear matcher
// processes this pathological stream in milliseconds; the quadratic one takes many
// seconds. The gap is enormous, so the ceiling is generous on purpose: it stays
// robust under -race and CI jitter while still catching any return to quadratic.
func TestMaskerStreamingIsSubQuadratic(t *testing.T) {
	const L = 4000                         // pattern length
	const N = 400000                       // stream length
	secret := strings.Repeat("a", L) + "X" // long repetitive prefix a pure-'a' stream never completes
	stream := []byte(strings.Repeat("a", N))

	m := NewMasker(io.Discard, []Secret{{Name: "S", Value: secret}})
	start := time.Now()
	if _, err := m.Write(stream); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("masking %d bytes against a length-%d pattern took %v; the matcher has regressed to quadratic (re-scanning the held window)", N, L, elapsed)
	}
}

// TestMaskerLargeSecretBoundedMemory guards the memory side: building the matcher
// over a long secret (which expands into several long encoded forms) must cost
// memory proportional to the pattern bytes, not a per-byte automaton node. A trie
// once cost ~315MB for a 64KB secret; the flat per-pattern failure tables cost a
// few MB. The ceiling is generous so it stays robust under -race and GC noise while
// still failing loudly on a return to the node-per-byte representation. It also
// checks the masker still works on a secret far longer than the held window.
func TestMaskerLargeSecretBoundedMemory(t *testing.T) {
	secret := strings.Repeat("S3cr3t-", 10000) // ~70KB, high enough to dwarf a few-MB matcher
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m := NewMasker(io.Discard, []Secret{{Name: "BIG", Value: secret}})
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Signed: a flat matcher may net negative (GC reclaims more than it allocates),
	// which would underflow unsigned subtraction.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 100<<20 {
		t.Fatalf("building a masker over a %d-byte secret grew the heap by %d bytes; the matcher is not flat (a per-byte trie regressed back in)", len(secret), grew)
	}

	var buf bytes.Buffer
	m = NewMasker(&buf, []Secret{{Name: "BIG", Value: secret}})
	if _, err := m.Write([]byte("prefix " + secret + " suffix")); err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "<notenv-masked:BIG>") || strings.Contains(got, secret) {
		t.Fatalf("a secret longer than the held window was not masked cleanly: %.80q...", got)
	}
}
