//go:build !fastkdf

package crypto

import "testing"

// TestProductionScryptWorkFactor guards the production scrypt cost. It compiles
// only without `-tags fastkdf`, so running the crypto tests in a normal (untagged)
// build asserts that a release binary wraps passphrase slots at 2^19. CI runs this
// in an untagged step before the fast-tagged suite.
func TestProductionScryptWorkFactor(t *testing.T) {
	if scryptWorkFactor != 19 {
		t.Fatalf("production scryptWorkFactor = %d, want 19 (is a release build accidentally using -tags fastkdf?)", scryptWorkFactor)
	}
}
