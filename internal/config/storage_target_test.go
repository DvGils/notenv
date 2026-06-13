package config_test

import (
	"testing"

	"github.com/DvGils/notenv/internal/config"
)

// TestUpsertStorageRejectsBadRemoteTarget: a remote name or base path that could
// smuggle a flag, break the remote:path split, traverse out of its prefix, or
// carry a control character is refused on write.
func TestUpsertStorageRejectsBadRemoteTarget(t *testing.T) {
	isolateConfig(t)
	bad := map[string]config.StorageEntry{
		"dashremote":    {Remote: "-x", Base: "notenv"},
		"colonremote":   {Remote: "a:b", Base: "notenv"},
		"traversalbase": {Remote: "b2", Base: "a/../b"},
		"controlbase":   {Remote: "b2", Base: "a\nb"},
		"dashbase":      {Remote: "b2", Base: "-x"},
	}
	for name, e := range bad {
		if _, err := config.UpsertStorage(name, e, false); err == nil {
			t.Errorf("%s: UpsertStorage accepted a bad target %+v", name, e)
		}
	}
	if _, err := config.UpsertStorage("good", config.StorageEntry{Remote: "b2", Base: "bucket/sub"}, false); err != nil {
		t.Errorf("clean remote/base rejected: %v", err)
	}
}
