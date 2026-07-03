// Package local is a pure-Go backend over a directory: the zero-account,
// zero-dependency vault. It stores exactly the bytes and layout a remote does
// (header, transitions, namespace objects), so a local vault copied to a
// remote is byte-identical and the same trust machinery runs unchanged.
//
// Where rclone's header swap is a windowed best effort, this backend's is a
// true compare-and-swap: an advisory OS file lock (auto-released by the
// kernel if the process dies, so a crash can never wedge later writers)
// covers the read-compare-write, and same-machine writers are the only
// writers a local vault has. The lock is cooperative and same-machine only: a
// vault directory under Dropbox/syncthing/NFS gets no cross-machine
// exclusion: concurrent multi-machine use is what remotes are for.
package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/DvGils/notenv/internal/backend"
)

// Reserved object names, sourced from the backend package so the filter cannot
// drift between backends (the bug that let orphan cleanup delete the header on
// remotes). These are reachable only through the HeaderStore interface; List
// excludes them via backend.IsReserved.
const (
	headerObject       = backend.HeaderName
	headerBackupObject = backend.HeaderBackupName
	headerLockFile     = backend.HeaderLockName
	probeObject        = backend.ProbeName
	tmpPrefix          = backend.TempPrefix
)

// Storage is a vault in a local directory. The zero value is not usable;
// Path must be set (made absolute by the caller).
type Storage struct {
	Path string
}

var (
	_ backend.Backend     = (*Storage)(nil)
	_ backend.HeaderStore = (*Storage)(nil)
)

// Preflight creates the vault directory if needed, the local counterpart of
// "is the remote reachable".
func (s *Storage) Preflight(ctx context.Context) error {
	if err := os.MkdirAll(s.Path, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	return nil
}

// Probe round-trips a marker file so an unwritable or full disk fails here,
// with context, not at the first real `set`.
func (s *Storage) Probe(ctx context.Context) error {
	if err := s.Preflight(ctx); err != nil {
		return err
	}
	path := filepath.Join(s.Path, probeObject)
	marker := []byte("notenv storage probe (safe to delete)")
	if err := writeAtomic(path, marker); err != nil {
		return fmt.Errorf("probe write failed: %w", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("probe read-back failed: %w", err)
	}
	if !bytes.Equal(got, marker) {
		return errors.New("probe read back different content than written")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("probe cleanup failed: %w", err)
	}
	return nil
}

func (s *Storage) Get(ctx context.Context, key string) ([]byte, error) {
	path, err := s.objectPath(key)
	if err != nil {
		return nil, err
	}
	return readFileCapped(path, backend.MaxObjectBytes)
}

// readFileCapped reads at most max bytes from path, returning
// backend.ErrObjectTooLarge if the file holds more (so a hostile vault directory
// cannot OOM the process) and backend.ErrNotFound if it is absent. Memory is
// bounded to limit regardless of the file's real size.
func readFileCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, backend.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return backend.ReadCapped(f, limit)
}

// Put stores data at key. The write is a temp file in the same directory
// renamed into place, so a reader never sees a partial object, and both file
// and directory are synced so a committed write survives power loss.
func (s *Storage) Put(ctx context.Context, key string, data []byte) error {
	path, err := s.objectPath(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeAtomic(path, data)
}

func (s *Storage) Delete(ctx context.Context, key string) error {
	path, err := s.objectPath(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// maxListBytes caps the total object-key bytes one List accumulates, so a vault
// directory with a pathological number of entries cannot exhaust memory (the
// directory counterpart of the rclone backend's listing cap). A var so a test can
// lower it; production uses backend.MaxListBytes.
var maxListBytes = backend.MaxListBytes

// List returns base-relative keys of every object under prefix, recursively,
// sorted. Header artifacts and abandoned temp files are not objects and are
// never listed.
func (s *Storage) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	var total int64
	err := filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // vault directory not created yet: no objects
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.Path, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if backend.IsReserved(key) {
			return nil
		}
		if backend.WithinPrefix(key, prefix) {
			total += int64(len(key))
			if total > maxListBytes {
				return fmt.Errorf("%w (vault listing exceeds %d bytes)", backend.ErrObjectTooLarge, maxListBytes)
			}
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *Storage) GetHeader(ctx context.Context) ([]byte, error) {
	return readFileCapped(filepath.Join(s.Path, headerObject), backend.MaxHeaderBytes)
}

// PutHeader writes the header object unconditionally (recovery paths only;
// mutations go through SwapHeader). Atomic like every other write.
func (s *Storage) PutHeader(ctx context.Context, raw []byte) error {
	if err := os.MkdirAll(s.Path, 0o700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Path, headerObject), raw)
}

// SwapHeader is a true compare-and-swap: an exclusive OS file lock covers the
// read, the compare, and the write, so concurrent same-machine writers
// serialize completely: exactly one of any set of racing swaps against the
// same base succeeds.
func (s *Storage) SwapHeader(ctx context.Context, base, updated []byte) error {
	if err := os.MkdirAll(s.Path, 0o700); err != nil {
		return err
	}
	unlock, err := lockExclusive(filepath.Join(s.Path, headerLockFile))
	if err != nil {
		return fmt.Errorf("lock header for swap: %w", err)
	}
	defer unlock()

	current, err := s.GetHeader(ctx)
	if errors.Is(err, backend.ErrNotFound) {
		current = nil
	} else if err != nil {
		return fmt.Errorf("re-read header before write: %w", err)
	}
	if !bytes.Equal(current, base) {
		return backend.ErrHeaderChanged
	}
	return s.PutHeader(ctx, updated)
}

// BackupHeader copies the current header to its ".prev" sibling so a bad overwrite
// is recoverable. Like every backend it keeps its own backup. The safe-write
// protocol calls it ONLY when a header exists, so a missing header here is a race,
// not the virgin case, and is returned as an error: the write fails closed rather
// than overwrite without a recoverable copy.
func (s *Storage) BackupHeader(ctx context.Context) error {
	raw, err := s.GetHeader(ctx)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Path, headerBackupObject), raw)
}

// RestoreHeaderBackup copies the ".prev" backup back over the header,
// ErrNotFound when there is none.
func (s *Storage) RestoreHeaderBackup(ctx context.Context) error {
	raw, err := readFileCapped(filepath.Join(s.Path, headerBackupObject), backend.MaxHeaderBytes)
	if err != nil {
		return err
	}
	return s.PutHeader(ctx, raw)
}

// objectPath maps an object key to its file, refusing keys that could escape
// the vault directory: an absolute key, a backslash (a separator on Windows, so
// it could traverse there), or a ".." path component. Keys come from validated
// namespaces and generated object names, so this is a guard rail, not an
// expected path.
func (s *Storage) objectPath(key string) (string, error) {
	if key == "" || strings.HasPrefix(key, "/") || strings.ContainsRune(key, '\\') ||
		slices.Contains(strings.Split(key, "/"), "..") {
		return "", fmt.Errorf("invalid object key %q", key)
	}
	return filepath.Join(s.Path, filepath.FromSlash(key)), nil
}

// writeAtomic lands data at path via a same-directory temp file and rename:
// readers see the old bytes or the new bytes, never a partial write. File and
// directory are synced so the rename survives power loss; the directory sync
// is best-effort (not supported everywhere).
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return err
	}
	defer func() {
		if tmp != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		return err
	}
	tmp = nil
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
