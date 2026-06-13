package config_test

import (
	"testing"

	"github.com/DvGils/notenv/internal/config"
)

// TestNextSeqFloor: a lost or reset counter catches up to the floor (the remote
// high-water) before incrementing, so it never reissues a number below it, and a
// counter already ahead of the floor is not pulled back.
func TestNextSeqFloor(t *testing.T) {
	isolateConfig(t)

	n, err := config.NextSeq("scope", "ns", 50)
	if err != nil {
		t.Fatal(err)
	}
	if n != 51 {
		t.Fatalf("NextSeq floored at 50 = %d, want 51", n)
	}

	// The counter is now at 51; a lower floor must not pull it back.
	n2, err := config.NextSeq("scope", "ns", 10)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 52 {
		t.Fatalf("NextSeq with a lower floor = %d, want 52 (counter stays ahead)", n2)
	}
}
