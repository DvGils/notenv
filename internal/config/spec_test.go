package config

import "testing"

func TestParseStorageSpec(t *testing.T) {
	cases := []struct {
		spec       string
		wantPath   string
		wantRemote string
		wantBase   string
		wantErr    bool
	}{
		{spec: "local:/srv/vault", wantPath: "/srv/vault"},
		{spec: "local:/srv/vault/", wantPath: "/srv/vault"}, // cleaned
		{spec: "local:relative/path", wantErr: true},        // must be absolute
		{spec: "local:", wantErr: true},                     // needs a path
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
			if eff.Path != tc.wantPath || eff.Remote != tc.wantRemote || eff.Base != tc.wantBase {
				t.Fatalf("parseStorageSpec(%q) = {Path:%q Remote:%q Base:%q}, want {Path:%q Remote:%q Base:%q}",
					tc.spec, eff.Path, eff.Remote, eff.Base, tc.wantPath, tc.wantRemote, tc.wantBase)
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

	u := &User{Storage: map[string]StorageEntry{"prod": {Path: "/srv/prod"}}, Default: "prod"}

	// A colon-bearing selector is a spec, resolved with no config entry.
	eff, st, err := storageHalf(u, "local:/tmp/ephemeral")
	if err != nil {
		t.Fatalf("storageHalf(spec): %v", err)
	}
	if eff.Path != "/tmp/ephemeral" || !eff.Local() {
		t.Fatalf("spec resolved to %+v, want local /tmp/ephemeral", eff)
	}
	if st != (StorageEntry{}) {
		t.Errorf("spec should yield a zero StorageEntry, got %+v", st)
	}

	// A colon-free selector is a configured name.
	eff, _, err = storageHalf(u, "prod")
	if err != nil {
		t.Fatalf("storageHalf(name): %v", err)
	}
	if eff.StorageName != "prod" || eff.Path != "/srv/prod" {
		t.Fatalf("name resolved to %+v, want configured prod", eff)
	}
}

// TestSpecScopesAreDistinct confirms two local specs get distinct local-state
// scopes, so an ephemeral vault never shares a key cache with another.
func TestSpecScopesAreDistinct(t *testing.T) {
	a, _ := parseStorageSpec("local:/tmp/a")
	b, _ := parseStorageSpec("local:/tmp/b")
	if a.Scope() == b.Scope() {
		t.Fatalf("distinct local specs share a scope %q", a.Scope())
	}
}
