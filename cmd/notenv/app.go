package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/ui"
)

// app wires contract, config, and backend together for one command invocation.
type app struct {
	contract     *contract.File
	contractPath string
	namespace    string
	store        backend.Backend
	cache        keyring.Cache
	blobs        blobcache.Cache
	cacheScope   string // length-prefixed remote+base (config.CacheScope): one key per storage base
	cacheTTL     time.Duration
}

func loadApp() (*app, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cf, dir, err := contract.Find(cwd)
	if err != nil {
		return nil, err
	}
	user, err := config.LoadUser()
	if err != nil {
		return nil, err
	}
	// Storage selection: --storage flag wins, else the project's local binding,
	// else the machine default / sole storage. The committed contract never
	// influences this.
	storageName := storageFlag
	if storageName == "" {
		bound, err := config.ReadLocalBinding(dir)
		if err != nil {
			return nil, err
		}
		storageName = bound
	}
	eff, err := config.Resolve(user, cf, dir, storageName)
	if err != nil {
		return nil, err
	}
	return &app{
		contract:     cf,
		contractPath: filepath.Join(dir, contract.FileName),
		namespace:    eff.Namespace,
		store:        &backend.RcloneStorage{Remote: eff.Remote, Base: eff.Base, Versioned: eff.Versioned},
		cache:        keyring.DefaultCache(),
		blobs:        blobcache.New(eff.BlobCacheTTL),
		cacheScope:   config.CacheScope(eff.Remote, eff.Base),
		cacheTTL:     eff.CacheTTL,
	}, nil
}

// getBlob fetches the namespace blob. found=false means no blob exists yet
// (not an error here; callers decide what that means).
//   - readCache: serve a fresh-enough local copy with no network. Reads
//     (run/list) pass true unless --refresh; writes (set) pass false so the
//     read-modify-write always sees current storage state.
//   - writeCache: repopulate the cache after a network fetch. Reads pass
//     true (incl. --refresh, so the next run is warm); set passes false and
//     caches the new sealed blob itself after writing.
func (a *app) getBlob(ctx context.Context, readCache, writeCache bool) (ciphertext []byte, found bool, err error) {
	if readCache {
		if cached, ok := a.blobs.Get(a.cacheScope, a.namespace); ok {
			return cached, true, nil
		}
	}
	spinErr := ui.Spin(fmt.Sprintf("Fetching namespace %q", a.namespace), func() error {
		var getErr error
		ciphertext, getErr = a.store.Get(ctx, a.namespace)
		if errors.Is(getErr, backend.ErrNotFound) {
			return nil
		}
		return getErr
	})
	if spinErr != nil {
		return nil, false, spinErr
	}
	if writeCache && ciphertext != nil {
		_ = a.blobs.Put(a.cacheScope, a.namespace, ciphertext) // best-effort
	}
	return ciphertext, ciphertext != nil, nil
}

// fetchSecrets pulls the namespace blob and decrypts it in memory with the
// master key. Plaintext never touches disk. refresh bypasses the read cache
// (and repopulates it) to pull another machine's change.
//
// After a remote re-key (rotate-master / key rm elsewhere), a cached blob and/or
// a cached master can be stale and fail to decrypt. fetchSecrets recovers once,
// cheapest first: re-fetch a fresh blob (a stale blob, no master re-unlock),
// then drop and re-unlock the master (a stale master). Only a genuine
// master/blob mismatch surfaces an error.
func (a *app) fetchSecrets(ctx context.Context, refresh bool) (map[string]string, error) {
	readCache := !refresh
	ciphertext, found, err := a.getBlob(ctx, readCache, true)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no secrets stored yet for namespace %q; use `notenv set KEY` first", a.namespace)
	}
	_, wasCached := a.cache.Get(a.cacheScope) // before master(), to know if it was already cached
	mk, err := a.master(ctx)
	if err != nil {
		return nil, err
	}
	plaintext, err := mk.Decrypt(ciphertext)
	if err != nil && readCache {
		// Maybe a stale cached blob: re-fetch fresh and retry with the same master.
		if fresh, ok, ferr := a.getBlob(ctx, false, true); ferr == nil && ok {
			ciphertext = fresh
			plaintext, err = mk.Decrypt(ciphertext)
		}
	}
	if err != nil && wasCached {
		// Maybe a stale cached master: drop it, re-unlock from the fresh header.
		a.cache.Drop(a.cacheScope)
		if mk, err = a.master(ctx); err == nil {
			plaintext, err = mk.Decrypt(ciphertext)
		}
	}
	if err != nil {
		return nil, err
	}
	return decodePayload(plaintext)
}

// decrypt opens an already-fresh ciphertext with the master, recovering once
// from a stale cached master (another machine re-keyed) by dropping the cache
// and re-unlocking. Returns the plaintext and the master that worked. Used by
// `set`, which always fetches the blob uncached.
func (a *app) decrypt(ctx context.Context, ciphertext []byte) ([]byte, *crypto.MasterKey, error) {
	_, wasCached := a.cache.Get(a.cacheScope) // before master(), to know if it was already cached
	mk, err := a.master(ctx)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := mk.Decrypt(ciphertext)
	if err != nil && wasCached {
		a.cache.Drop(a.cacheScope)
		if mk, err = a.master(ctx); err == nil {
			plaintext, err = mk.Decrypt(ciphertext)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return plaintext, mk, nil
}

// master returns the unwrapped master key: session cache first, then the
// header ceremony (unlock with the escrowed passphrase, or, on virgin
// storage, generate the key and write the header).
func (a *app) master(ctx context.Context) (*crypto.MasterKey, error) {
	if cached, ok := a.cache.Get(a.cacheScope); ok {
		if mk, err := crypto.ParseMasterKey(cached); err == nil {
			return mk, nil
		}
		a.cache.Drop(a.cacheScope) // unparseable cached value, treat as stale and drop it
	}
	hs, ok := a.store.(backend.HeaderStore)
	if !ok {
		return nil, errors.New("backend does not support client-side crypto")
	}
	mk, _, err := ensureMaster(ctx, hs, a.cache, a.cacheScope, a.cacheTTL)
	return mk, err
}

// The blob payload is a flat map[string]string, JSON-serialized, encrypted
// as one age message.
func decodePayload(plaintext []byte) (map[string]string, error) {
	secrets := map[string]string{}
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("corrupt payload: %w", err)
	}
	return secrets, nil
}

func encodePayload(secrets map[string]string) ([]byte, error) {
	return json.Marshal(secrets)
}
