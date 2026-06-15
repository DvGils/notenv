package config

import (
	"path/filepath"
	"testing"
)

func TestParseStorageSpec(t *testing.T) {
	// A real OS-absolute path, so the local: cases are valid on Windows too (where
	// a driveless path like /srv/vault is not absolute).
	abs := filepath.Join(t.TempDir(), "vault")
	want := filepath.Clean(abs)

	for _, spec := range []string{"local:" + abs, "local:" + abs + string(filepath.Separator)} {
		eff, err := parseStorageSpec(spec)
		if err != nil {
			t.Fatalf("parseStorageSpec(%q): %v", spec, err)
		}
		if eff.Path != want {
			t.Errorf("parseStorageSpec(%q) Path = %q, want %q", spec, eff.Path, want)
		}
		if !eff.Local() {
			t.Errorf("parseStorageSpec(%q) should be a local vault", spec)
		}
		if eff.StorageName != spec {
			t.Errorf("StorageName = %q, want the spec %q", eff.StorageName, spec)
		}
	}

	// The remaining cases do not depend on the platform's notion of "absolute".
	cases := []struct {
		spec       string
		wantRemote string
		wantBase   string
		wantErr    bool
	}{
		{spec: "local:relative/path", wantErr: true}, // must be absolute
		{spec: "local:", wantErr: true},              // needs a path
		{spec: "rclone:b2:notenv", wantRemote: "b2", wantBase: "notenv"},
		{spec: "rclone:b2:", wantRemote: "b2", wantBase: DefaultBase}, // empty base defaults
		{spec: "rclone:b2:team/secrets", wantRemote: "b2", wantBase: "team/secrets"},
		{spec: "rclone:b2", wantErr: true},    // needs rclone's own remote:base colon
		{spec: "rclone:", wantErr: true},      // needs <remote>:<base>
		{spec: "rclone:b2:..", wantErr: true}, // base traversal rejected
		{spec: "ftp:host", wantErr: true},     // unknown scheme
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			eff, err := parseStorageSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseStorageSpec(%q) = %+v, want error", tc.spec, eff)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStorageSpec(%q): %v", tc.spec, err)
			}
			if eff.Remote != tc.wantRemote || eff.Base != tc.wantBase {
				t.Fatalf("parseStorageSpec(%q) = {Remote:%q Base:%q}, want {Remote:%q Base:%q}",
					tc.spec, eff.Remote, eff.Base, tc.wantRemote, tc.wantBase)
			}
			if eff.StorageName != tc.spec {
				t.Errorf("StorageName = %q, want the spec %q", eff.StorageName, tc.spec)
			}
		})
	}
}

// TestStorageHalfDiscriminatesByColon is the load-bearing freeze guard: the
// grammar relies on a configured name never containing a colon, so a colon must
// always select the spec path and never be a valid storage name.
func TestStorageHalfDiscriminatesByColon(t *testing.T) {
	if ValidStorageName("a:b") {
		t.Fatal("a colon must never be a valid storage name; the NOTENV_STORAGE grammar freezes on it")
	}
	if !ValidStorageName("prod-1") {
		t.Fatal("a plain name should be valid")
	}

	prodPath := filepath.Join(t.TempDir(), "prod")
	u := &User{Storage: map[string]StorageEntry{"prod": {Path: prodPath}}, Default: "prod"}

	// A colon-bearing selector is a spec, resolved with no config entry.
	ephemeral := filepath.Join(t.TempDir(), "ephemeral")
	eff, st, err := storageHalf(u, "local:"+ephemeral)
	if err != nil {
		t.Fatalf("storageHalf(spec): %v", err)
	}
	if eff.Path != filepath.Clean(ephemeral) || !eff.Local() {
		t.Fatalf("spec resolved to %+v, want local %q", eff, ephemeral)
	}
	if st != (StorageEntry{}) {
		t.Errorf("spec should yield a zero StorageEntry, got %+v", st)
	}

	// A colon-free selector is a configured name.
	eff, _, err = storageHalf(u, "prod")
	if err != nil {
		t.Fatalf("storageHalf(name): %v", err)
	}
	if eff.StorageName != "prod" || eff.Path != filepath.Clean(prodPath) {
		t.Fatalf("name resolved to %+v, want configured prod at %q", eff, prodPath)
	}
}

// TestSpecScopesAreDistinct confirms two local specs get distinct local-state
// scopes, so an ephemeral vault never shares a key cache with another.
func TestSpecScopesAreDistinct(t *testing.T) {
	dir := t.TempDir()
	a, err := parseStorageSpec("local:" + filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseStorageSpec("local:" + filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Scope() == b.Scope() {
		t.Fatalf("distinct local specs share a scope %q", a.Scope())
	}
}
