package crypto

import "testing"

// The key header is frozen at v6 for the 1.x line (the published compatibility
// contract, COMPATIBILITY.md). ParseHeader refuses any other version, in either
// direction, so bumping this would break the promise that any 1.x build reads any
// 1.x vault: it is a 2.0 change, not a 1.x one.
func TestHeaderVersionFrozen(t *testing.T) {
	if headerVersion != 6 {
		t.Fatalf("headerVersion = %d, want 6: the storage format is frozen for the 1.x line", headerVersion)
	}
}
