package config_test

import (
	"testing"

	"github.com/DvGils/notenv/internal/config"
)

// TestRemoveStorage: removing a storage drops its entry; removing the default
// reassigns the default to the sole survivor; removing an absent one is a no-op.
func TestRemoveStorage(t *testing.T) {
	isolateConfig(t)
	if _, err := config.UpsertStorage("a", config.StorageEntry{Path: "/tmp/a"}, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := config.UpsertStorage("b", config.StorageEntry{Path: "/tmp/b"}, false, false); err != nil {
		t.Fatal(err)
	}

	existed, err := config.RemoveStorage("a") // the default
	if err != nil || !existed {
		t.Fatalf("RemoveStorage(a): existed=%v err=%v", existed, err)
	}
	u, err := config.LoadUser()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Storage["a"]; ok {
		t.Fatal("a must be gone")
	}
	if _, ok := u.Storage["b"]; !ok {
		t.Fatal("b must remain")
	}
	if u.Default != "b" {
		t.Fatalf("default must move to the sole survivor, got %q", u.Default)
	}

	if existed, err := config.RemoveStorage("nope"); err != nil || existed {
		t.Fatalf("removing an absent storage must be a no-op: existed=%v err=%v", existed, err)
	}
}
