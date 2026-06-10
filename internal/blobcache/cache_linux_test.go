//go:build linux

package blobcache

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Point XDG_RUNTIME_DIR at a temp dir so the test never touches the real
// runtime cache.
func withRuntimeDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

func TestBlobCacheRoundTrip(t *testing.T) {
	withRuntimeDir(t)
	c := New(time.Minute)
	const scope, ns = "9:b2-notenv:base", "myproject"

	if _, ok := c.Get(scope, ns); ok {
		t.Fatal("unexpected hit before Put")
	}
	blob := []byte("age-ciphertext-bytes")
	if err := c.Put(scope, ns, blob); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := c.Get(scope, ns)
	if !ok || !bytes.Equal(got, blob) {
		t.Fatalf("Get = %q, %v; want %q, true", got, ok, blob)
	}
	c.Drop(scope, ns)
	if _, ok := c.Get(scope, ns); ok {
		t.Fatal("hit after Drop")
	}
}

func TestBlobCacheExpiryAndSweep(t *testing.T) {
	withRuntimeDir(t)
	c := New(20 * time.Millisecond)
	const scope, ns = "1:r:b", "ns"
	if err := c.Put(scope, ns, []byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)

	// Expired entry is a miss and is removed on access.
	if _, ok := c.Get(scope, ns); ok {
		t.Fatal("expired entry should miss")
	}

	// A fresh cache construction sweeps expired files left behind.
	if err := c.Put(scope, ns, []byte("y")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "notenv", "blobs")
	time.Sleep(40 * time.Millisecond)
	_ = New(20 * time.Millisecond) // triggers sweep()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("sweep left %d expired entries", len(entries))
	}
}

func TestClear(t *testing.T) {
	withRuntimeDir(t)
	c := New(time.Hour)
	if err := c.Put("1:r:b", "ns1", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("1:r:b", "ns2", []byte("b")); err != nil {
		t.Fatal(err)
	}
	n, err := Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n != 2 {
		t.Fatalf("cleared %d, want 2", n)
	}
	if _, ok := c.Get("1:r:b", "ns1"); ok {
		t.Fatal("blob survived Clear")
	}
}

func TestClearNoRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	if n, err := Clear(); err != nil || n != 0 {
		t.Fatalf("Clear without runtime dir = %d, %v; want 0, nil", n, err)
	}
}

func TestBlobCacheDisabled(t *testing.T) {
	withRuntimeDir(t)
	// ttl <= 0 disables caching entirely.
	c := New(0)
	if err := c.Put("s", "n", []byte("x")); err != nil {
		t.Fatalf("disabled Put should be a no-op: %v", err)
	}
	if _, ok := c.Get("s", "n"); ok {
		t.Fatal("disabled cache must always miss")
	}
}

func TestBlobCacheNoRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	// No RAM-backed dir, so refuse to cache (no persistent-disk fallback).
	c := New(time.Minute)
	if err := c.Put("s", "n", []byte("x")); err != nil {
		t.Fatalf("no-runtime-dir Put should be a no-op: %v", err)
	}
	if _, ok := c.Get("s", "n"); ok {
		t.Fatal("without XDG_RUNTIME_DIR the cache must not store anything")
	}
}
