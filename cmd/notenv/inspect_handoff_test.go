package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DvGils/notenv/internal/config"
)

// liveHandoffVault builds an ephemeral-vault directory the way `handoff` names
// it ("notenv-handoff-<pid>-..."), and returns the matching NOTENV_STORAGE spec
// and NOTENV_SESSION scope so a test can drive evalHandoff with consistent env.
func liveHandoffVault(t *testing.T, pid int) (storage, session string) {
	t.Helper()
	vault := filepath.Join(t.TempDir(), fmt.Sprintf("%s%d-abc123", handoffDirPrefix, pid))
	if err := os.Mkdir(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	return "local:" + vault, (config.Effective{Path: vault}).Scope()
}

func TestEvalHandoff(t *testing.T) {
	alive := func(int) bool { return true }
	dead := func(int) bool { return false }

	t.Run("live session is a handoff", func(t *testing.T) {
		storage, session := liveHandoffVault(t, 4242)
		got := evalHandoff(session, storage, "api", alive)
		if got.Version != 1 {
			t.Errorf("version = %d, want 1", got.Version)
		}
		if !got.Handoff {
			t.Fatalf("a live handoff vault should report handoff: %+v", got)
		}
		if got.Namespace != "api" {
			t.Errorf("namespace = %q, want %q", got.Namespace, "api")
		}
	})

	t.Run("nested run inside a handoff is still a handoff", func(t *testing.T) {
		// A `notenv run` inside the agent inherits NOTENV_SESSION/NOTENV_STORAGE
		// unchanged, so its child must read as scoped too.
		storage, session := liveHandoffVault(t, 4242)
		if got := evalHandoff(session, storage, "api", alive); !got.Handoff {
			t.Fatalf("nested run should stay scoped: %+v", got)
		}
	})

	t.Run("no session marker", func(t *testing.T) {
		storage, _ := liveHandoffVault(t, 4242)
		if got := evalHandoff("", storage, "api", alive); got.Handoff {
			t.Fatalf("an empty NOTENV_SESSION is not a handoff: %+v", got)
		}
	})

	t.Run("dead supervisor", func(t *testing.T) {
		storage, session := liveHandoffVault(t, 4242)
		if got := evalHandoff(session, storage, "api", dead); got.Handoff {
			t.Fatalf("a dead supervisor is stale, not a live session: %+v", got)
		}
	})

	t.Run("ephemeral vault already torn down", func(t *testing.T) {
		storage, session := liveHandoffVault(t, 4242)
		path, _ := localSpecPath(storage)
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		if got := evalHandoff(session, storage, "api", alive); got.Handoff {
			t.Fatalf("a missing vault means the session is over: %+v", got)
		}
	})

	t.Run("storage is not local", func(t *testing.T) {
		_, session := liveHandoffVault(t, 4242)
		if got := evalHandoff(session, "rclone:b2:notenv", "api", alive); got.Handoff {
			t.Fatalf("a remote storage is never a handoff vault: %+v", got)
		}
	})

	t.Run("local vault but not handoff-named", func(t *testing.T) {
		vault := filepath.Join(t.TempDir(), "ordinary-vault")
		if err := os.Mkdir(vault, 0o700); err != nil {
			t.Fatal(err)
		}
		storage := "local:" + vault
		session := (config.Effective{Path: vault}).Scope()
		if got := evalHandoff(session, storage, "api", alive); got.Handoff {
			t.Fatalf("a plain local vault is not a handoff: %+v", got)
		}
	})

	t.Run("session names a different vault", func(t *testing.T) {
		// NOTENV_SESSION present but pointing at another scope: a partial clobber.
		storage, _ := liveHandoffVault(t, 4242)
		if got := evalHandoff("0::/some/other/scope", storage, "api", alive); got.Handoff {
			t.Fatalf("a mismatched session scope must not be trusted: %+v", got)
		}
	})
}

func TestLocalSpecPath(t *testing.T) {
	// A platform-native absolute path: "/.../vaults/e" on Unix, "C:\...\vaults\e"
	// on Windows. A hardcoded "/srv/..." is not absolute on Windows (filepath.IsAbs
	// wants a drive letter), so localSpecPath would correctly reject it there.
	abs := filepath.Join(t.TempDir(), "vaults", "e")
	cases := []struct {
		storage  string
		wantOK   bool
		wantPath string
	}{
		{"local:" + abs, true, abs},
		{"local:" + abs + string(filepath.Separator), true, abs}, // trailing separator cleaned
		{"local:relative/path", false, ""},                       // env paths must be absolute
		{"local:", false, ""},
		{"rclone:b2:notenv", false, ""},
		{"prod", false, ""}, // a configured storage name
		{"", false, ""},
	}
	for _, c := range cases {
		path, ok := localSpecPath(c.storage)
		if ok != c.wantOK || path != c.wantPath {
			t.Errorf("localSpecPath(%q) = (%q, %v), want (%q, %v)", c.storage, path, ok, c.wantPath, c.wantOK)
		}
	}
}

func TestFirstNamespace(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"api":         "api",
		"api,db":      "api",
		" api , db ":  "api",
		",leadingsep": "",
	}
	for in, want := range cases {
		if got := firstNamespace(in); got != want {
			t.Errorf("firstNamespace(%q) = %q, want %q", in, got, want)
		}
	}
}
