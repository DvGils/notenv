package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
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

func loadApp(ctx context.Context) (*app, error) {
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
	binding, err := config.ReadLocalBinding(dir)
	if err != nil {
		return nil, err
	}
	// Storage selection: --storage flag wins, else the project's local binding,
	// else the machine default / sole storage. The committed contract never
	// influences this.
	storageName := storageFlag
	if storageName == "" {
		storageName = binding.Storage
	}
	eff, err := config.Resolve(user, cf, dir, storageName)
	if err != nil {
		return nil, err
	}
	store := openStorage(eff)
	// The contract chooses the namespace — the thing that selects which secrets
	// reach a child process — so it is held to the checkout's local pin before
	// any key is touched (a first-use join of an existing namespace costs one
	// listing here; pinned checkouts skip storage entirely).
	if err := guardNamespace(ctx, store, dir, binding, eff.Namespace); err != nil {
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
		store:        store,
		cache:        keyring.DefaultCache(),
		blobs:        blobcache.New(eff.BlobCacheTTL),
		cacheScope:   eff.Scope(),
		cacheTTL:     eff.CacheTTL,
	}, nil
}

// vaultView is one verified read of the vault header: the trust root a
// command's folds and writes build on. Its manifest is what makes a fold
// trustworthy, so it is always read fresh from storage, never cached.
type vaultView struct {
	header *crypto.Header
	raw    []byte
	mk     *crypto.MasterKey
}

// view reads and authenticates the vault header under mk: parse, tag, vault
// continuity, rollback pin (advancing it when warranted), and that the header
// still wraps mk.
func (a *app) view(ctx context.Context, mk *crypto.MasterKey) (*vaultView, error) {
	v, err := a.vault()
	if err != nil {
		return nil, err
	}
	raw, err := v.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, errors.New("the vault's key header is gone from storage; refusing to proceed (recover it, e.g. `notenv key restore-backup`)")
	}
	if err != nil {
		return nil, err
	}
	h, err := crypto.ParseHeader(raw)
	if err != nil {
		return nil, err
	}
	if h.Recipient != mk.PublicKey() {
		return nil, fmt.Errorf("%w; re-run the command to unlock the current key", keymgmt.ErrEpochChanged)
	}
	if err := trustHeader(ctx, v, a.cacheScope, h, mk); err != nil {
		return nil, err
	}
	return &vaultView{header: h, raw: raw, mk: mk}, nil
}

// namespaceFor binds this command's namespace log to a verified vault view.
func (a *app) namespaceFor(view *vaultView) *secrets.Namespace {
	return secrets.For(a.store, a.namespace, view.mk, a.machine, view.header.Manifest)
}

// vault returns the backend's header-bearing side, which every store this app
// constructs implements (loadApp builds an RcloneStorage).
func (a *app) vault() (keymgmt.Vault, error) {
	v, ok := a.store.(keymgmt.Vault)
	if !ok {
		return nil, errors.New("backend does not support client-side crypto")
	}
	return v, nil
}

// appendGuarded writes one key change and records it in the vault manifest
// under the header compare-and-swap, which doubles as the confirmation that
// the master it was sealed under is still the vault's master. The same
// manifest write prunes folded entries whose objects are gone; both halves of
// the delta are idempotent under the swap's retry re-application (adopting
// in-flight strays is not, which is why that is compaction's job). On an
// epoch change (a concurrent rotation), it removes its own segment — leaving
// it would poison every fold once the old master is gone — drops the now-stale
// local caches, and reports what happened. The user re-runs the command, which
// unlocks the new master (running the pin checks) and writes cleanly.
func (a *app) appendGuarded(ctx context.Context, view *vaultView, prev *secrets.State, seq int, key, value string, deleted bool) (*secrets.State, error) {
	v, err := a.vault()
	if err != nil {
		return nil, err
	}
	updated, objKey, entry, err := a.namespaceFor(view).Append(ctx, prev, seq, key, value, deleted)
	if err != nil {
		return nil, err
	}
	delta := crypto.ManifestDelta{Add: map[string]crypto.ManifestEntry{objKey: entry}, Prune: prev.Prunable}
	h, err := keymgmt.UpdateManifest(ctx, v, view.mk, delta)
	if err != nil {
		_ = a.store.Delete(ctx, objKey)
		if errors.Is(err, keymgmt.ErrEpochChanged) {
			a.cache.Drop(a.cacheScope)
			a.blobs.Drop(a.cacheScope, a.namespace)
			return nil, fmt.Errorf("%w; the write was rolled back, nothing was stored. Re-run the command to write under the current key (verify the rotation is legitimate if it surprises you)", err)
		}
		return nil, fmt.Errorf("%w; the write was rolled back, nothing was stored — re-run the command", err)
	}
	pinCurrent(a.cacheScope, h, view.mk)
	return updated, nil
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
// memory. Plaintext never touches disk. Returns the folded state and the
// verified vault view it was folded under.
func (a *app) foldState(ctx context.Context) (*secrets.State, *vaultView, error) {
	var state *secrets.State
	var view *vaultView
	_, err := a.withMaster(ctx, func(mk *crypto.MasterKey) error {
		return ui.Spin(fmt.Sprintf("Reading namespace %q", a.namespace), func() error {
			var ferr error
			if view, ferr = a.view(ctx, mk); ferr != nil {
				return ferr
			}
			state, ferr = a.namespaceFor(view).Fold(ctx)
			return ferr
		})
	})
	if err != nil {
		return nil, nil, err
	}
	reportStrays(state)
	return state, view, nil
}

// reportStrays surfaces what a fold found around the manifest: in-flight
// writes it folded but the manifest doesn't record yet, and snapshots left by
// a compaction that crashed before recording them. Both are warnings, not
// errors — `notenv compact` settles them.
func reportStrays(state *secrets.State) {
	for _, key := range slices.Sorted(maps.Keys(state.Adoptable)) {
		ui.Warnf("found an in-flight write %s not yet recorded in the vault manifest; it is included, and `notenv compact` records it durably", key)
	}
	for _, key := range state.Strays {
		ui.Warnf("ignoring snapshot %s, which no compaction ever recorded (one likely crashed mid-run); `notenv compact` cleans it up", key)
	}
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
	state, view, err := a.foldState(ctx)
	if err != nil {
		return nil, err
	}
	if !state.HasHistory() {
		return nil, fmt.Errorf("no secrets stored yet for namespace %q; use `notenv set KEY` first", a.namespace)
	}
	a.cacheFolded(view.mk, state.Secrets)
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

// compactCommit returns the callback Compact uses to make its snapshot
// authoritative: the manifest swap, which doubles as the confirmation that mk
// is still the vault's master, with the local pin advanced on every success.
func (a *app) compactCommit(ctx context.Context, mk *crypto.MasterKey) func(crypto.ManifestDelta) error {
	return func(delta crypto.ManifestDelta) error {
		v, err := a.vault()
		if err != nil {
			return err
		}
		h, err := keymgmt.UpdateManifest(ctx, v, mk, delta)
		if err != nil {
			return err
		}
		pinCurrent(a.cacheScope, h, mk)
		return nil
	}
}

// compactNamespace folds the segment log into a fresh recorded snapshot. It
// re-reads the header first: the caller's view predates its own latest write,
// and a compaction must fold under the manifest that already records it.
func (a *app) compactNamespace(ctx context.Context, mk *crypto.MasterKey) error {
	view, err := a.view(ctx, mk)
	if err != nil {
		return err
	}
	return a.namespaceFor(view).Compact(ctx, a.compactCommit(ctx, view.mk))
}

// maybeCompact runs compactNamespace once enough segments have accumulated,
// keeping cold reads fast. priorSegments is the count from the fold this write
// was based on. Best-effort: the write already landed, so a compaction failure
// never fails the command.
func (a *app) maybeCompact(ctx context.Context, mk *crypto.MasterKey, priorSegments int) {
	if priorSegments+1 < secrets.DefaultCompactThreshold {
		return
	}
	if err := ui.Spin(fmt.Sprintf("Compacting namespace %q", a.namespace), func() error {
		return a.compactNamespace(ctx, mk)
	}); err != nil {
		ui.Warnf("auto-compaction skipped (harmless; run `notenv compact` later): %v", err)
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
	v, err := a.vault()
	if err != nil {
		return nil, err
	}
	mk, _, err := ensureMaster(ctx, v, a.cache, a.cacheScope, a.cacheTTL)
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
