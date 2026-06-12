package local_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/backendtest"
	"github.com/DvGils/notenv/internal/backend/local"
)

func newStore(t *testing.T) *local.Storage {
	t.Helper()
	return &local.Storage{Path: t.TempDir()}
}

func TestBackendConformance(t *testing.T) {
	backendtest.BackendContract(t, func(t *testing.T) backend.Backend { return newStore(t) })
}

func TestHeaderStoreConformance(t *testing.T) {
	backendtest.HeaderStoreContract(t, func(t *testing.T) backend.HeaderStore { return newStore(t) }, false)
}

// TestSwapHeaderConcurrentNoLostUpdates is the guarantee that distinguishes
// this backend: racing swaps serialize completely. Workers read the header as
// a counter and swap in its increment; with a true compare-and-swap, exactly
// the successful swaps are reflected — the final value equals the success
// count, with no lost update ever.
func TestSwapHeaderConcurrentNoLostUpdates(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	const workers, rounds = 8, 25

	var successes atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range rounds {
				base, err := s.GetHeader(ctx)
				if err != nil && err != backend.ErrNotFound {
					t.Errorf("GetHeader: %v", err)
					return
				}
				n := 0
				if base != nil {
					if n, err = strconv.Atoi(string(base)); err != nil {
						t.Errorf("non-counter header %q", base)
						return
					}
				}
				err = s.SwapHeader(ctx, base, []byte(strconv.Itoa(n+1)))
				switch err {
				case nil:
					successes.Add(1)
				case backend.ErrHeaderChanged:
					// lost the race cleanly; retry next round
				default:
					t.Errorf("SwapHeader: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()

	final, err := s.GetHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := strconv.Atoi(string(final))
	if err != nil {
		t.Fatal(err)
	}
	if int64(got) != successes.Load() {
		t.Fatalf("lost update: header counter %d != %d successful swaps", got, successes.Load())
	}
	if successes.Load() == 0 {
		t.Fatal("no swap ever succeeded")
	}
}

// TestListSkipsArtifacts: header files, the lock, and abandoned temp files
// are plumbing, not objects.
func TestListSkipsArtifacts(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.PutHeader(ctx, []byte("h1")); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupHeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapHeader(ctx, []byte("h1"), []byte("h2")); err != nil { // creates the lock file
		t.Fatal(err)
	}
	for _, key := range []string{"proj/seg-m1-aa.age", ".transitions.json"} {
		if err := s.Put(ctx, key, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	// An abandoned temp file from a crashed atomic write.
	if err := os.WriteFile(filepath.Join(s.Path, "proj", ".tmp-crashed"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := s.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".transitions.json", "proj/seg-m1-aa.age"}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("List = %v, want %v", keys, want)
	}
}

// TestProbeAndPreflight: a fresh directory probes clean and leaves nothing.
func TestProbeAndPreflight(t *testing.T) {
	ctx := context.Background()
	s := &local.Storage{Path: filepath.Join(t.TempDir(), "not", "yet", "created")}
	if err := s.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	keys, err := s.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("probe left objects behind: %v", keys)
	}
}

// TestObjectPathGuard: keys that could escape the vault directory are refused.
func TestObjectPathGuard(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, key := range []string{"", "/etc/passwd", "../outside", "ns/../../outside"} {
		if err := s.Put(ctx, key, []byte("x")); err == nil {
			t.Errorf("Put(%q) must be refused", key)
		}
	}
}
