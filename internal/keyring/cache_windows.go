//go:build windows

package keyring

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiCache stores master keys as DPAPI blobs under the user's local app
// data. The blob is ciphertext at rest under the user's login credentials
// (CryptProtectData, per-user scope), the same custody class the platform
// secret store provides for machine identities. The TTL is lazy: the expiry
// rides beside the blob (it is not a secret) and a stale read deletes the
// file and misses, rather than the entry vanishing at the deadline the way
// the Linux kernel keyring enforces. caching.md states the difference.
type dpapiCache struct{}

const cacheIsNull = false

func newCache() Cache { return dpapiCache{} }

func cachePath(scope string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(scope))
	return filepath.Join(base, "notenv", "keycache", hex.EncodeToString(sum[:16])), nil
}

func (dpapiCache) Get(scope string) (string, bool) {
	path, err := cachePath(scope)
	if err != nil {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	expiry, blob64, found := strings.Cut(strings.TrimSpace(string(raw)), "\n")
	if !found {
		dpapiCache{}.Drop(scope)
		return "", false
	}
	deadline, err := strconv.ParseInt(strings.TrimSpace(expiry), 10, 64)
	if err != nil || time.Now().UnixNano() >= deadline {
		dpapiCache{}.Drop(scope)
		return "", false
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob64))
	if err != nil {
		dpapiCache{}.Drop(scope)
		return "", false
	}
	plain, err := dpapiUnprotect(blob)
	if err != nil {
		dpapiCache{}.Drop(scope)
		return "", false
	}
	return string(plain), true
}

func (dpapiCache) Store(scope, masterKey string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	path, err := cachePath(scope)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	blob, err := dpapiProtect([]byte(masterKey))
	if err != nil {
		return err
	}
	// Nanosecond resolution, not seconds: a second-truncated deadline rounds a
	// short TTL down to its sub-second remainder, so an entry stored just before
	// a second boundary can read back already expired (now.Unix() == deadline).
	payload := fmt.Sprintf("%d\n%s\n", time.Now().Add(ttl).UnixNano(), base64.StdEncoding.EncodeToString(blob))
	return os.WriteFile(path, []byte(payload), 0o600)
}

func (dpapiCache) Drop(scope string) {
	if path, err := cachePath(scope); err == nil {
		_ = os.Remove(path)
	}
}

func dpapiProtect(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain))}
	if len(plain) > 0 {
		in.Data = &plain[0]
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(blob))}
	if len(blob) > 0 {
		in.Data = &blob[0]
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
