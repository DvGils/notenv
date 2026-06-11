package memstore_test

import (
	"context"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/backendtest"
	"github.com/DvGils/notenv/internal/backend/memstore"
)

func TestConformanceNonVersioned(t *testing.T) {
	backendtest.HeaderStoreContract(t, func(t *testing.T) backend.HeaderStore {
		return memstore.New()
	}, false)
}

func TestConformanceVersioned(t *testing.T) {
	backendtest.HeaderStoreContract(t, func(t *testing.T) backend.HeaderStore {
		return memstore.New(memstore.Versioned())
	}, true)
}

func TestBackendConformance(t *testing.T) {
	backendtest.BackendContract(t, func(t *testing.T) backend.Backend {
		return memstore.New()
	})
}

// TestCorruptNextPut covers the fault-injection hook the conformance suite
// can't reach through the interface: it must change only the next write.
func TestCorruptNextPut(t *testing.T) {
	ctx := context.Background()
	s := memstore.New()
	s.CorruptNextPut(func([]byte) []byte { return []byte("mangled") })

	if err := s.PutHeader(ctx, []byte("good-1")); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	got, err := s.GetHeader(ctx)
	if err != nil {
		t.Fatalf("GetHeader: %v", err)
	}
	if string(got) != "mangled" {
		t.Fatalf("corruption hook not applied: got %q", got)
	}

	// Hook is one-shot: the following write is stored intact.
	if err := s.PutHeader(ctx, []byte("good-2")); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	got, _ = s.GetHeader(ctx)
	if string(got) != "good-2" {
		t.Fatalf("corruption hook was not one-shot: got %q", got)
	}
}
