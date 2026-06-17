//go:build !linux

package runtimedir

// IsRAMBacked is always false off Linux: notenv makes the "RAM-only" guarantee
// only on Linux (tmpfs at XDG_RUNTIME_DIR). macOS and Windows have no verified
// equivalent, so callers fall back to the OS temp dir, the documented at-rest
// caveat on those platforms.
func IsRAMBacked(string) bool { return false }
