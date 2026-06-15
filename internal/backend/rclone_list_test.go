package backend

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"
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

// rcloneErrExit runs a throwaway command that exits with code and writes stderr,
// then wraps it exactly as runRclone does, so the not-found classifier sees a real
// *exec.ExitError (its exit code is unexported and cannot be fabricated otherwise).
func rcloneErrExit(t *testing.T, code int, stderr string) error {
	t.Helper()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo %q 1>&2; exit %d", stderr, code))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	if err == nil {
		t.Fatal("helper command unexpectedly succeeded")
	}
	return &rcloneError{args: []string{"deletefile"}, err: err, stderr: strings.TrimSpace(errb.String())}
}

// TestNotFoundTrustsExitCodeNotStderr locks the v0.19.1 hardening: not-found is
// classified purely by rclone's dedicated exit codes (3: directory, 4: file),
// never by stderr text. A real failure whose message merely contains "not found"
// must NOT be read as not-found, or Delete would report a delete that never
// happened and RestoreHeaderBackup would disguise a failed restore as "no backup".
// rclone returns 3/4 for a genuinely missing source on deletefile and copyto
// (verified on v1.74.3), so dropping the stderr fallback loses no real not-found.
func TestNotFoundTrustsExitCodeNotStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell to produce controlled exit codes")
	}
	if !isNotFoundExit(rcloneErrExit(t, rcloneExitFileNotFound, "object not found")) {
		t.Error("exit 4 (file not found) must be classified as not-found")
	}
	if !isNotFoundExit(rcloneErrExit(t, rcloneExitDirNotFound, "directory not found")) {
		t.Error("exit 3 (directory not found) must be classified as not-found")
	}
	if isNotFoundExit(rcloneErrExit(t, 1, "Failed to copyto: backend not found in config")) {
		t.Error("a generic exit-1 failure must not be read as not-found from its stderr text")
	}
	if isNotFoundExit(rcloneErrExit(t, 5, "couldn't connect: remote doesn't exist upstream")) {
		t.Error("a transient exit-5 failure must not be read as not-found from its stderr text")
	}
}
