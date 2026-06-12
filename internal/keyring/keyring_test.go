package keyring

import (
	"slices"
	"strings"
	"testing"
)

func TestGeneratePassphrase(t *testing.T) {
	seen := map[string]bool{}
	for range 8 {
		p, err := GeneratePassphrase()
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Split(p, "-")
		if len(words) != 6 {
			t.Fatalf("want 6 words, got %q", p)
		}
		for _, w := range words {
			if !slices.Contains(tempWords, w) {
				t.Fatalf("word %q is not from the wordlist", w)
			}
		}
		if seen[p] {
			t.Fatalf("generated the same passphrase twice: %q", p)
		}
		seen[p] = true
	}
}

func TestWordlistIntegrity(t *testing.T) {
	if len(tempWords) != 1296 {
		t.Fatalf("wordlist must hold 1296 words, has %d", len(tempWords))
	}
	uniq := map[string]bool{}
	for _, w := range tempWords {
		if w == "" || uniq[w] {
			t.Fatalf("empty or duplicate word %q", w)
		}
		uniq[w] = true
	}
}
