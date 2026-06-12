package secrets_test

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/memstore"
	"github.com/DvGils/notenv/internal/secrets"
)

// lagOnceStore makes the first Get return not-found, simulating read-after-write
// lag on an eventually-consistent backend.
type lagOnceStore struct {
	*memstore.Store
	lagged bool
}

func (s *lagOnceStore) Get(ctx context.Context, key string) ([]byte, error) {
	if !s.lagged {
		s.lagged = true
		return nil, backend.ErrNotFound
	}
	return s.Store.Get(ctx, key)
}

// TestAppendKeepsLaggedWrite: when the verify read-back lags (the write may
// actually have landed), the write must not be deleted. The operation fails so
// the caller can retry, but the object stays.
func TestAppendKeepsLaggedWrite(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	store := &lagOnceStore{Store: v.store}
	ns := secrets.For(store, "proj", v.mk, "m1", v.manifest)

	prev, err := ns.Fold(ctx) // empty namespace: no reads happen, the first Get is the verify read-back
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ns.Append(ctx, prev, 1, "K", "v", false); err == nil {
		t.Fatal("append should surface the lagged read-back as an error")
	}
	keys, err := v.store.List(ctx, "proj/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("a lagged write must survive (not be deleted), got %d objects", len(keys))
	}
}
