//go:build linux

package runtimedir

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func isTmpfs(t *testing.T, dir string) bool {
	t.Helper()
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return false
	}
	m := uint32(fs.Type)
	return m == uint32(unix.TMPFS_MAGIC) || m == uint32(unix.RAMFS_MAGIC)
}

func TestIsRAMBackedRejects(t *testing.T) {
	if IsRAMBacked("") {
		t.Error("empty path must be false")
	}
	if IsRAMBacked("/nonexistent/notenv-no-such-dir") {
		t.Error("missing dir must be false")
	}
	// A regular on-disk dir is not RAM-backed. Only assert when the test's temp
	// dir is genuinely not tmpfs (it can be on some systems), so this never flakes.
	disk := t.TempDir()
	if !isTmpfs(t, disk) && IsRAMBacked(disk) {
		t.Error("a non-tmpfs dir must be false")
	}
}

func TestIsRAMBackedAcceptsTmpfs(t *testing.T) {
	const shm = "/dev/shm"
	if !isTmpfs(t, shm) {
		t.Skip("/dev/shm is not tmpfs here")
	}
	dir, err := os.MkdirTemp(shm, "notenv-rd-*") // 0700 by MkdirTemp
	if err != nil {
		t.Skipf("cannot create under %s: %v", shm, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if !IsRAMBacked(dir) {
		t.Fatal("a private 0700 tmpfs dir must be RAM-backed")
	}

	// Group/other access disqualifies it (another local user could read secrets).
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if IsRAMBacked(dir) {
		t.Error("a group/other-accessible tmpfs dir must be rejected")
	}

	// A non-existent path under tmpfs is still false (stat fails).
	if IsRAMBacked(filepath.Join(dir, "missing")) {
		t.Error("a missing path must be false")
	}
}
