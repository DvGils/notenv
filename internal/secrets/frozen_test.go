package secrets

import "testing"

// The blob format is frozen at v3 for the 1.x line (the published compatibility
// contract, COMPATIBILITY.md). A reader refuses any other version outright, in
// either direction, so bumping this would break the promise that any 1.x build
// reads any 1.x vault: it is a 2.0 change, not a 1.x one. The golden vault proves
// the current code still reads a committed v3 blob; this guards the writer.
func TestBlobVersionFrozen(t *testing.T) {
	if blobVersion != 3 {
		t.Fatalf("blobVersion = %d, want 3: the storage format is frozen for the 1.x line", blobVersion)
	}
}
