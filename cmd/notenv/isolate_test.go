package main

import (
	"runtime"
	"testing"
)

// isolateConfig points the platform config directory at a fresh temp dir, so
// a test's trust state (pins, bindings, namespace acceptances) cannot leak
// into its neighbors. XDG_CONFIG_HOME only steers os.UserConfigDir on Linux:
// macOS resolves it through HOME and Windows through AppData, so a test that
// sets only the XDG variable shares the real config dir on those platforms.
func isolateConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", dir)
	case "windows":
		t.Setenv("AppData", dir)
	}
}
