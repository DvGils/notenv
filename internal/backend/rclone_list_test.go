package backend

import (
	"slices"
	"testing"
)

// TestKeysFromLsfExcludesReserved is the default-CI guard for the rclone List
// filter (the real conformance run needs rclone installed). rclone lists the
// header artifacts as ordinary files; List must drop them, or whole-vault and
// orphan-cleanup callers mistake the header for a stray object and delete it.
func TestKeysFromLsfExcludesReserved(t *testing.T) {
	// Exactly what `rclone lsf -R --files-only` prints at the vault root: the
	// header and its backup sit alongside the namespace blobs.
	out := []byte(HeaderName + "\n" +
		HeaderBackupName + "\n" +
		ProbeName + "\n" +
		"app/data-a.age\n" +
		"app/data-b.age\n")

	got := keysFromLsf(out, "")
	slices.Sort(got)
	want := []string{"app/data-a.age", "app/data-b.age"}
	if !slices.Equal(got, want) {
		t.Fatalf("keysFromLsf at root: got %v, want only the blobs %v (reserved plumbing must be excluded)", got, want)
	}
}

// TestKeysFromLsfReprefixesScopedListing covers the scoped path: lsf prints keys
// relative to the listed root, so List re-prefixes them to stay base-relative.
func TestKeysFromLsfReprefixesScopedListing(t *testing.T) {
	out := []byte("data-a.age\ndata-b.age\n")
	got := keysFromLsf(out, "app")
	slices.Sort(got)
	want := []string{"app/data-a.age", "app/data-b.age"}
	if !slices.Equal(got, want) {
		t.Fatalf("keysFromLsf scoped to app: got %v, want %v", got, want)
	}
}
