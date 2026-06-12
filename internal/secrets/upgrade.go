package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/crypto"
)

// UpgradeObjects rewrites every payload object in the vault to the current
// format under mk — stamping each with the object key it lives under — and
// returns the manifest entries that record them. It is the one reader that
// accepts the previous payload format, used by `notenv key migrate`; normal
// reads reject anything but the current format. Idempotent: a re-run after a
// partial failure rewrites already-upgraded objects to the same bytes.
func UpgradeObjects(ctx context.Context, store backend.Backend, mk *crypto.MasterKey) (map[string]crypto.ManifestEntry, error) {
	keys, err := store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	entries := map[string]crypto.ManifestEntry{}
	for _, key := range keys {
		slash := strings.LastIndex(key, "/")
		if slash < 0 || !strings.HasSuffix(key, ".age") {
			continue // payload objects live under a namespace prefix
		}
		base := key[slash+1:]
		if !strings.HasPrefix(base, "seg-") && !strings.HasPrefix(base, "snap-") {
			continue
		}
		plain, err := upgradeOne(ctx, store, mk, key, strings.HasPrefix(base, "seg-"))
		if err != nil {
			return nil, err
		}
		mac, err := mk.ObjectMAC(plain)
		if err != nil {
			return nil, err
		}
		entries[key] = crypto.ManifestEntry{MAC: mac}
	}
	return entries, nil
}

// upgradeOne restamps a single object and writes it back, returning the
// upgraded plaintext.
func upgradeOne(ctx context.Context, store backend.Backend, mk *crypto.MasterKey, key string, isSeg bool) ([]byte, error) {
	blob, err := store.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	plain, err := mk.Decrypt(blob)
	if err != nil {
		return nil, fmt.Errorf("object %s: %w", key, err)
	}
	var out []byte
	if isSeg {
		var seg segment
		if err := json.Unmarshal(plain, &seg); err != nil {
			return nil, fmt.Errorf("corrupt object %s: %w", key, err)
		}
		if err := checkUpgradable(seg.Version, key); err != nil {
			return nil, err
		}
		seg.Version, seg.Object = formatVersion, key
		out = mustMarshal(seg)
	} else {
		var snap snapshot
		if err := json.Unmarshal(plain, &snap); err != nil {
			return nil, fmt.Errorf("corrupt object %s: %w", key, err)
		}
		if err := checkUpgradable(snap.Version, key); err != nil {
			return nil, err
		}
		snap.Version, snap.Object = formatVersion, key
		out = mustMarshal(snap)
	}
	sealed, err := mk.Encrypt(out)
	if err != nil {
		return nil, err
	}
	if err := putVerified(ctx, store, key, sealed); err != nil {
		return nil, err
	}
	return out, nil
}

// checkUpgradable accepts the formats the upgrade can read: the current one
// (idempotent re-run) and the one immediately before it.
func checkUpgradable(version int, key string) error {
	switch {
	case version > formatVersion:
		return fmt.Errorf("%s was written by a newer notenv (format v%d, this build understands up to v%d); upgrade notenv", key, version, formatVersion)
	case version < formatVersion-1:
		return fmt.Errorf("%s carries payload format v%d, which this notenv cannot upgrade; compact the namespace with the notenv version that wrote it first", key, version)
	}
	return nil
}
