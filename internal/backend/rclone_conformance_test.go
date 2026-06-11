package backend_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/backendtest"
)

// TestRcloneConformance runs the shared conformance contracts against a real
// rclone remote, proving the in-memory fake models the real backend. It is
// skipped unless a remote is provided, so the default `go test` stays
// offline:
//
//	NOTENV_TEST_REMOTE=local NOTENV_TEST_BASE=/tmp/notenv-conformance go test ./internal/backend/...
//
// The base path is wiped of all objects before each subtest's store so runs
// don't bleed into each other.
func TestRcloneConformance(t *testing.T) {
	remote := os.Getenv("NOTENV_TEST_REMOTE")
	base := os.Getenv("NOTENV_TEST_BASE")
	if remote == "" || base == "" {
		t.Skip("set NOTENV_TEST_REMOTE and NOTENV_TEST_BASE to run rclone conformance")
	}
	if !backend.RcloneInstalled() {
		t.Skip("rclone not installed")
	}

	basePath := remote + ":" + strings.Trim(base, "/")
	clean := func() {
		_ = exec.Command("rclone", "delete", basePath).Run() // wipe every object under the base
	}

	backendtest.HeaderStoreContract(t, func(t *testing.T) backend.HeaderStore {
		clean()
		t.Cleanup(clean)
		return &backend.RcloneStorage{Remote: remote, Base: base}
	}, false)

	backendtest.BackendContract(t, func(t *testing.T) backend.Backend {
		clean()
		t.Cleanup(clean)
		return &backend.RcloneStorage{Remote: remote, Base: base}
	})
}
