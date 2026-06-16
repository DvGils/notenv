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
	"strings"
	"time"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/blobcache"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/crypto"
	"github.com/DvGils/notenv/internal/keymgmt"
	"github.com/DvGils/notenv/internal/keyring"
	"github.com/DvGils/notenv/internal/runner"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

// app wires contract, config, and backend together for one command invocation.
// contract is nil in projectless mode (--namespace): the vault is addressed
// directly, with no checkout to declare, rename, or narrow anything.
type app struct {
	contract     *contract.File
	contractPath string
	namespace    string
	store        backend.Backend
	cache        keyring.Cache
	blobs        blobcache.Cache
	cacheScope   string // length-prefixed remote+base (config.CacheScope): one key per storage base
	cacheTTL     time.Duration
	readOnly     string // non-empty: why mutating commands are refused (requireWritable)
	salvage      bool   // read past untrustable recorded objects (--skip-corrupt); set only by read-only surfaces
	sourceSpec   string // this storage as a NOTENV_STORAGE spec, so handoff can re-open it in the builder subprocess
}

// readOnlyReason returns why writes to a storage are refused, or "" when
// writable: the per-storage policy or the process-wide env switch.
func readOnlyReason(storageName string, readOnly bool) string {
	if readOnly {
		return fmt.Sprintf("storage %q is read-only (read_only = true in the machine config)", storageName)
	}
	if config.ReadOnlyEnv() {
		return "NOTENV_READONLY is set"
	}
	return ""
}

// requireWritable refuses a mutating command against read-only storage. The
// refusal is policy for cooperating clients, not containment: it exists so an
// honest agent can't destroy anything by accident.
func (a *app) requireWritable(action string) error {
	if a.readOnly == "" {
		return nil
	}
	return fmt.Errorf("%s; refusing to %s", a.readOnly, action)
}

// storageEnv points a process at a storage with no machine-config entry: a
// configured name, or a self-contained spec (local:/rclone:, see
// config.parseStorageSpec). It is how `handoff` points an agent at the
// ephemeral vault, and is independently useful for an agent or CI.
const storageEnv = "NOTENV_STORAGE"

// storageSelector resolves which storage selector wins: the explicit --storage
// flag, then NOTENV_STORAGE, then a caller-supplied fallback (a project's local
// binding). Empty means "let config pick the default or sole storage".
func storageSelector(fallback string) string {
	if storageFlag != "" {
		return storageFlag
	}
	if env := os.Getenv(storageEnv); env != "" {
		return env
	}
	return fallback
}

func loadApp(ctx context.Context) (*app, error) {
	if namespaceFlag != "" {
		return projectlessApp(ctx, storageSelector(""), namespaceFlag)
	}
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
	// Storage selection: --storage flag wins, then NOTENV_STORAGE (the env an
	// agent or CI is pointed at), then the project's local binding, then the
	// machine default / sole storage. The committed contract never influences it.
	eff, err := config.Resolve(user, cf, dir, storageSelector(binding.Storage))
	if err != nil {
		return nil, err
	}
	store := openStorage(eff)
	// The contract chooses the namespace (the thing that selects which secrets
	// reach a child process), so it is held to the checkout's local pin before
	// any key is touched (a first-use join of an existing namespace costs one
	// listing here; pinned checkouts skip storage entirely).
	if err := guardNamespace(ctx, store, dir, binding, eff.Namespace); err != nil {
		return nil, err
	}
	return &app{
		contract:     cf,
		contractPath: filepath.Join(dir, contract.FileName),
		namespace:    eff.Namespace,
		store:        store,
		cache:        keyring.DefaultCache(),
		blobs:        blobcache.New(eff.BlobCacheTTL),
		cacheScope:   eff.Scope(),
		cacheTTL:     eff.CacheTTL,
		readOnly:     readOnlyReason(eff.StorageName, eff.ReadOnly),
		sourceSpec:   storageSpec(eff),
	}, nil
}

// projectlessApp is loadApp for an explicitly named namespace (--namespace):
// the vault addressed directly. Storage selection
// is the explicit name or the machine default (there is no checkout to carry
// a binding), and first use of a namespace that already holds secrets is
// confirmed against the user-level acceptance record instead of a local pin.
func projectlessApp(ctx context.Context, storageName, namespace string) (*app, error) {
	user, err := config.LoadUser()
	if err != nil {
		return nil, err
	}
	eff, err := config.ResolveNamespace(user, storageName, namespace)
	if err != nil {
		return nil, err
	}
	store := openStorage(eff)
	if err := guardFlagNamespace(ctx, store, eff.Scope(), eff.Namespace); err != nil {
		return nil, err
	}
	return &app{
		namespace:  eff.Namespace,
		store:      store,
		cache:      keyring.DefaultCache(),
		blobs:      blobcache.New(eff.BlobCacheTTL),
		cacheScope: eff.Scope(),
		cacheTTL:   eff.CacheTTL,
		readOnly:   readOnlyReason(eff.StorageName, eff.ReadOnly),
		sourceSpec: storageSpec(eff),
	}, nil
}

// storageKey maps a declared env name to the key it is stored under; without
// a contract there is nothing to rename, so the name is the key.
func (a *app) storageKey(key string) string {
	if a.contract != nil {
		return a.contract.StorageKey(key)
	}
	return key
}

// buildEnv resolves the env the child runs with: the contract's declared vars
// when a project is loaded, otherwise every secret in the namespace under its
// storage key. A projectless run has no contract to narrow, rename, or
// require anything. The base is first stripped of notenv's own credential
// (stripCredentialEnv): the master-equivalent identity must never ride into a
// child notenv spawns.
func (a *app) buildEnv(base []string, secretMap map[string]string) ([]string, error) {
	base = stripCredentialEnv(base)
	if a.contract != nil {
		return a.contract.BuildEnv(base, secretMap)
	}
	env := base
	for _, key := range slices.Sorted(maps.Keys(secretMap)) {
		if !contract.ValidEnvName(key) {
			ui.Warnf("skipping %q: not a valid environment variable name", key)
			continue
		}
		env = append(env, key+"="+secretMap[key])
	}
	return env, nil
}

// stripCredentialEnv removes notenv's own credential (NOTENV_IDENTITY) from an
// environment handed to a child process. The identity decrypts the whole vault,
// so it must never propagate into a process notenv spawns, where an `env` dump
// or a crash reporter would leak it. Only NOTENV_IDENTITY is stripped: the other
// NOTENV_* vars are non-secret policy a nested notenv should keep inheriting.
// This stops the accidental leak, not a determined reader: a same-uid child can
// still read the value out of notenv's own /proc. The caller's slice is not
// mutated.
func stripCredentialEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if name, _, found := strings.Cut(kv, "="); found && name == identityEnv {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// injectedSecrets pairs each env var notenv injects with its value, the exact
// strings the output masker scrubs. With a contract, only resolved declared
// vars count (required-but-missing ones already failed buildEnv); without one,
// everything buildEnv injects.
func (a *app) injectedSecrets(secretMap map[string]string) []runner.Secret {
	var out []runner.Secret
	if a.contract != nil {
		for envKey := range a.contract.Secrets {
			if value, ok := secretMap[a.contract.StorageKey(envKey)]; ok {
				out = append(out, runner.Secret{Name: envKey, Value: value})
			}
		}
		return out
	}
	for key, value := range secretMap {
		if contract.ValidEnvName(key) {
			out = append(out, runner.Secret{Name: key, Value: value})
		}
	}
	return out
}

// vaultView is one verified read of the vault header: the trust root a
// command's reads and writes build on. Its manifest is what makes a read
// trustworthy, so it is always read fresh from storage, never cached.
type vaultView struct {
	header *crypto.Header
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
	if err := trustHeader(a.cacheScope, h, mk); err != nil {
		return nil, err
	}
	return &vaultView{header: h, mk: mk}, nil
}

// namespaceFor binds this command's namespace to a verified vault view.
func (a *app) namespaceFor(view *vaultView) *secrets.Namespace {
	return secrets.For(a.store, a.namespace, view.mk)
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

// writeNamespace applies writes to the namespace's blob and points the vault
// header at the new blob under the header compare-and-swap, which doubles as the
// confirmation that the master the blob was sealed under is still the vault's
// master. It is a read-modify-write: each attempt re-reads the current blob, so
// a writer that lost the swap race re-applies its change over the winner's and
// writes to different keys both survive (only same-key writes resolve
// last-writer-wins), writes a fresh, uniquely named blob, and swaps the header
// to it. On success the superseded generation (the blob that fell off the
// one-generation backup) is deleted; on an epoch change (a concurrent rotation)
// the orphaned blob is removed, the now-stale local caches are dropped, and the
// user re-runs, which unlocks the new master and writes cleanly.
func (a *app) writeNamespace(ctx context.Context, view *vaultView, writes []secrets.Write) (*secrets.State, error) {
	state, _, err := a.namespaceFor(view).Commit(ctx,
		func(cur *secrets.State) (*secrets.State, error) { return cur.Apply(writes), nil },
		func(h *crypto.Header) { pinCurrent(a.cacheScope, h, view.mk) })
	if err != nil {
		if errors.Is(err, backend.ErrCommitUncertain) {
			// The write may have landed; do not claim a rollback, and drop the warm
			// blob cache since the namespace state is now uncertain.
			a.blobs.Drop(a.cacheScope, a.namespace)
			return nil, fmt.Errorf("%w; it may have landed. Run `notenv doctor` to check, or `notenv key restore-backup` to revert, before relying on it", err)
		}
		if errors.Is(err, keymgmt.ErrEpochChanged) {
			a.cache.Drop(a.cacheScope)
			a.blobs.Drop(a.cacheScope, a.namespace)
			return nil, fmt.Errorf("%w; the write was rolled back, nothing was stored. Re-run the command to write under the current key (verify the rotation is legitimate if it surprises you)", err)
		}
		return nil, fmt.Errorf("%w; the write was rolled back, nothing was stored. Re-run the command", err)
	}
	return state, nil
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

// unlockView resolves the master and verifies the vault header (the trust root
// a write builds on) without reading the namespace blob. A write's Commit
// re-reads the blob itself under the swap, so commands that only need to write
// (not display prior state) use this instead of readState, saving a read.
func (a *app) unlockView(ctx context.Context) (*vaultView, error) {
	var view *vaultView
	_, err := a.withMaster(ctx, func(mk *crypto.MasterKey) error {
		v, err := a.view(ctx, mk)
		view = v
		return err
	})
	return view, err
}

// readState reads the namespace from storage and resolves its secrets in
// memory. Plaintext never touches disk. Returns the resolved state and the
// verified vault view it was read under.
func (a *app) readState(ctx context.Context) (*secrets.State, *vaultView, error) {
	var state *secrets.State
	var view *vaultView
	_, err := a.withMaster(ctx, func(mk *crypto.MasterKey) error {
		return ui.Spin(fmt.Sprintf("Reading namespace %q", a.namespace), func() error {
			var ferr error
			if view, ferr = a.view(ctx, mk); ferr != nil {
				return ferr
			}
			ns := a.namespaceFor(view)
			entry, _ := view.header.NamespaceEntry(a.namespace)
			if a.salvage {
				state, ferr = ns.ReadSalvage(ctx, entry)
			} else {
				state, ferr = ns.Read(ctx, entry)
			}
			return ferr
		})
	})
	if err != nil {
		return nil, nil, err
	}
	a.reportCorrupt(state)
	return state, view, nil
}

// reportCorrupt warns, loudly and per blob, about what a salvage read fell back
// past. The list is only ever populated under --skip-corrupt, so this is silent
// on a strict read. The framing is deliberate: the current blob may have
// reverted to its one-generation backup (losing the most recent write) or, with
// the backup also gone, resolved empty, so the user has to see exactly what was
// lost.
func (a *app) reportCorrupt(state *secrets.State) {
	for _, c := range state.Corrupt {
		ui.Warnf("salvage: read past untrustable blob %s (%s); namespace %q reverted to its last good backup or, if that is gone too, resolved empty. Recover from your remote's version history if it keeps one, or `notenv key evict %s` to rewrite the namespace from what survives", c.Blob, c.Reason, a.namespace, a.namespace)
	}
}

// resolved is a namespace's secrets as run/list consume them: the values plus
// each live key's advisory metadata.
type resolved struct {
	secrets map[string]string
	meta    map[string]secrets.Meta
}

// fetchSecrets resolves the namespace's secrets for run/list. It serves a warm,
// fully-local copy from the cached blob when both the blob and the master are
// cached; otherwise it reads from storage and repopulates the cache. refresh
// skips the cache to pull another machine's changes.
func (a *app) fetchSecrets(ctx context.Context, refresh bool) (*resolved, error) {
	// Honor the handoff session guard on the warm path too. The cold path enforces
	// it via master(), but a warm cache hit returns before reaching it, so without
	// this an in-session run could serve a vault other than the session's straight
	// from cache. The handed-off source vault is already protected (its master is
	// dropped and held out of the cache by the no-cache lease); this closes the same
	// rule for any other vault left warm in the cache.
	if err := sessionGuard(a.cacheScope); err != nil {
		return nil, err
	}
	// Salvage never touches the warm cache: serving a cached complete read would
	// defeat the request, and caching a degraded one would silently hand later
	// reads a state missing its dropped keys.
	if !refresh && !a.salvage {
		if cached, ok := a.cachedSecrets(); ok {
			return cached, nil
		}
	}
	state, view, err := a.readState(ctx)
	if err != nil {
		return nil, err
	}
	if !state.HasHistory() {
		return nil, fmt.Errorf("no secrets stored yet for namespace %q; use `notenv set KEY` first", a.namespace)
	}
	if !a.salvage {
		a.cacheState(view.mk, state)
	}
	return &resolved{secrets: state.Secrets, meta: state.Meta}, nil
}

// cacheEnvelope is what the warm cache stores: the sealed blob plus a MAC of it
// keyed by the master. age encryption is to the master's PUBLIC recipient, which
// the cleartext header exposes, so a sealed blob alone proves nothing about its
// origin (anyone who can write the cache dir could plant one that decrypts
// cleanly). The MAC is keyed by the master's secret material, which a
// cache-writing attacker does not have, so it binds a cache entry to a holder of
// the real master, and is taken over the entry's (scope, namespace) as well as
// its ciphertext (see cacheMACInput), so an entry cannot be replayed into another
// namespace's slot, restoring the fail-closed integrity every other read has.
type cacheEnvelope struct {
	MAC    string `json:"mac"`
	Sealed []byte `json:"sealed"`
}

// cacheMACInput binds a cache envelope's MAC to its (scope, namespace) slot, not
// just its ciphertext, so an entry copied into another namespace's cache file
// fails verification and falls through to the authenticated read, the same
// namespace binding the on-storage blob carries in its plaintext. The master-keyed
// MAC over this input is unforgeable without the master.
func cacheMACInput(scope, namespace string, sealed []byte) []byte {
	return append([]byte(scope+"\x00"+namespace+"\x00"), sealed...)
}

// cachedSecrets opens the warm local cache with no network: it needs both the
// cached blob and the master already cached, and is a clean miss if either is
// absent, stale, or fails its integrity check.
func (a *app) cachedSecrets() (*resolved, bool) {
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
	var env cacheEnvelope
	if err := json.Unmarshal(cached, &env); err != nil {
		return nil, false // old/foreign layout: treat as a miss and re-fetch
	}
	// Verify the entry is bound to this master AND to this namespace before
	// decrypting it: a forged, tampered, or cross-namespace-replayed blob fails here
	// and falls through to the authenticated read.
	if err := mk.CheckBlobMAC(cacheMACInput(a.cacheScope, a.namespace, env.Sealed), env.MAC); err != nil {
		return nil, false
	}
	plaintext, err := mk.Decrypt(env.Sealed)
	if err != nil {
		return nil, false
	}
	res, err := decodePayload(plaintext)
	if err != nil {
		return nil, false
	}
	return res, true
}

// cacheState stores the resolved secrets as a sealed blob plus a master-keyed
// MAC (see cacheEnvelope), so the next run on this machine is instant and a
// tampered cache cannot be served. Best-effort: a cache failure never fails the
// command.
func (a *app) cacheState(mk *crypto.MasterKey, state *secrets.State) {
	plaintext, err := encodePayload(state)
	if err != nil {
		return
	}
	sealed, err := mk.Encrypt(plaintext)
	if err != nil {
		return
	}
	mac, err := mk.BlobMAC(cacheMACInput(a.cacheScope, a.namespace, sealed))
	if err != nil {
		return
	}
	env, err := json.Marshal(cacheEnvelope{MAC: mac, Sealed: sealed})
	if err != nil {
		return
	}
	_ = a.blobs.Put(a.cacheScope, a.namespace, env)
}

// master returns the unwrapped master key: session cache first, then the
// header ceremony (unlock with the escrowed passphrase, or, on virgin
// storage, generate the key and write the header).
func (a *app) master(ctx context.Context) (*crypto.MasterKey, error) {
	if err := sessionGuard(a.cacheScope); err != nil {
		return nil, err
	}
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
	mk, _, err := ensureMaster(ctx, v, a.cache, a.cacheScope, a.cacheTTL, a.readOnly)
	return mk, err
}

// cachePayloadVersion stamps the local cache payload. The blob is machine-local
// with a short TTL, so a version mismatch is just a cache miss, but the check
// must be exact: without it, a blob in another layout could decode as an empty
// (or wrong) secret set instead of missing.
const cachePayloadVersion = 1

// cachePayload is the local cache layout: the secrets and their metadata,
// JSON-serialized, encrypted as one age message.
type cachePayload struct {
	Version int                     `json:"v"`
	Secrets map[string]string       `json:"secrets"`
	Meta    map[string]secrets.Meta `json:"meta,omitempty"`
}

func decodePayload(plaintext []byte) (*resolved, error) {
	var p cachePayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("corrupt payload: %w", err)
	}
	if p.Version != cachePayloadVersion {
		return nil, fmt.Errorf("cached payload v%d, want v%d", p.Version, cachePayloadVersion)
	}
	if p.Meta == nil {
		p.Meta = map[string]secrets.Meta{}
	}
	return &resolved{secrets: p.Secrets, meta: p.Meta}, nil
}

func encodePayload(state *secrets.State) ([]byte, error) {
	return json.Marshal(cachePayload{Version: cachePayloadVersion, Secrets: state.Secrets, Meta: state.Meta})
}
