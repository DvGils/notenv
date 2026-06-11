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
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

// app wires contract, config, and backend together for one command invocation.
type app struct {
	contract     *contract.File
	contractPath string
	namespace    string
	machine      string // this machine's stable id, naming the segments it writes
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
	machine, err := config.MachineID()
	if err != nil {
		return nil, err
	}
	return &app{
		contract:     cf,
		contractPath: filepath.Join(dir, contract.FileName),
		namespace:    eff.Namespace,
		machine:      machine,
		store:        &backend.RcloneStorage{Remote: eff.Remote, Base: eff.Base, Versioned: eff.Versioned},
		cache:        keyring.DefaultCache(),
		blobs:        blobcache.New(eff.BlobCacheTTL),
		cacheScope:   config.CacheScope(eff.Remote, eff.Base),
		cacheTTL:     eff.CacheTTL,
	}, nil
}

// secretsNamespace binds this command's namespace log to a master key.
func (a *app) secretsNamespace(mk *crypto.MasterKey) *secrets.Namespace {
	return secrets.For(a.store, a.namespace, mk, a.machine)
}

// withMaster resolves the master key and runs fn with it, recovering once from
// a stale cached master (another machine re-keyed) by dropping the cache and
// re-unlocking. Returns the master fn ran against.
func (a *app) withMaster(ctx context.Context, fn func(*crypto.MasterKey) error) (*crypto.MasterKey, error) {
	_, wasCached := a.cache.Get(a.cacheScope) // before master(), to know if it was already cached
	mk, err := a.master(ctx)
	if err != nil {
		return nil, err
	}
	if err = fn(mk); err != nil && wasCached {
		a.cache.Drop(a.cacheScope)
		if mk, err = a.master(ctx); err == nil {
			err = fn(mk)
		}
	}
	return mk, err
}

// foldState reads the namespace from storage and resolves its secrets in
// memory. Plaintext never touches disk. Returns the folded state and the master
// that opened it.
func (a *app) foldState(ctx context.Context) (*secrets.State, *crypto.MasterKey, error) {
	var state *secrets.State
	mk, err := a.withMaster(ctx, func(mk *crypto.MasterKey) error {
		return ui.Spin(fmt.Sprintf("Reading namespace %q", a.namespace), func() error {
			var ferr error
			state, ferr = a.secretsNamespace(mk).Fold(ctx)
			return ferr
		})
	})
	if err != nil {
		return nil, nil, err
	}
	return state, mk, nil
}

// fetchSecrets resolves the namespace's secrets for run/list. It serves a warm,
// fully-local copy from the folded-blob cache when both the blob and the master
// are cached; otherwise it folds from storage and repopulates the cache.
// refresh skips the cache to pull another machine's changes.
func (a *app) fetchSecrets(ctx context.Context, refresh bool) (map[string]string, error) {
	if !refresh {
		if cached, ok := a.cachedSecrets(); ok {
			return cached, nil
		}
	}
	state, mk, err := a.foldState(ctx)
	if err != nil {
		return nil, err
	}
	if !state.HasHistory() {
		return nil, fmt.Errorf("no secrets stored yet for namespace %q; use `notenv set KEY` first", a.namespace)
	}
	a.cacheFolded(mk, state.Secrets)
	reportConflicts(state.Conflicts)
	return state.Secrets, nil
}

// cachedSecrets opens the warm folded-blob cache with no network: it needs both
// the blob and the master already cached, and is a clean miss if either is
// absent or stale.
func (a *app) cachedSecrets() (map[string]string, bool) {
	cached, ok := a.blobs.Get(a.cacheScope, a.namespace)
	if !ok {
		return nil, false
	}
	rawMaster, ok := a.cache.Get(a.cacheScope)
	if !ok {
		return nil, false
	}
	mk, err := crypto.ParseMasterKey(rawMaster)
	if err != nil {
		return nil, false
	}
	plaintext, err := mk.Decrypt(cached)
	if err != nil {
		return nil, false
	}
	secrets, err := decodePayload(plaintext)
	if err != nil {
		return nil, false
	}
	return secrets, true
}

// cacheFolded stores the folded secrets as a single sealed blob, so the next
// run on this machine is instant. Best-effort: a cache failure never fails the
// command.
func (a *app) cacheFolded(mk *crypto.MasterKey, folded map[string]string) {
	plaintext, err := encodePayload(folded)
	if err != nil {
		return
	}
	if sealed, err := mk.Encrypt(plaintext); err == nil {
		_ = a.blobs.Put(a.cacheScope, a.namespace, sealed)
	}
}

// reportConflicts warns about keys written concurrently on more than one
// machine. The kept value is deterministic; the shadowed ones survive in their
// segments until the next compaction.
func reportConflicts(conflicts []secrets.Conflict) {
	for _, c := range conflicts {
		ui.Warnf("%q was set concurrently on more than one machine; kept machine %s's value (re-run `notenv set %s` to settle it)", c.Key, c.Winner, c.Key)
	}
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
