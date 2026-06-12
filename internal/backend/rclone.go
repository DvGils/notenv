package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// rclone exit codes (see rclone docs): 3 = directory not found,
// 4 = file not found.
const (
	rcloneExitDirNotFound  = 3
	rcloneExitFileNotFound = 4
)

// RcloneStorage implements Backend by shelling out to a system rclone. This
// keeps the binary small and the dependency explicit; embedding the library
// is a possible later optimization.
type RcloneStorage struct {
	Remote string // rclone remote name, e.g. "b2"
	Base   string // path within the remote, e.g. "my-bucket/notenv"
	// Versioned: the remote retains old versions on overwrite (B2 does
	// natively), so the header's ".prev" backup copy (~3s server-side on B2)
	// is redundant and skipped (see BackupHeader).
	Versioned bool
}

// ErrRcloneMissing is returned when no rclone binary is on PATH.
var ErrRcloneMissing = errors.New("rclone not found in PATH")

// RcloneInstalled reports whether an rclone binary is available.
func RcloneInstalled() bool {
	_, err := exec.LookPath("rclone")
	return err == nil
}

// ListRemotes returns the names of the user's configured rclone remotes.
func ListRemotes(ctx context.Context) ([]string, error) {
	out, err := runRclone(ctx, nil, []string{"listremotes"})
	if err != nil {
		return nil, err
	}
	var remotes []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if name := strings.TrimSuffix(strings.TrimSpace(line), ":"); name != "" {
			remotes = append(remotes, name)
		}
	}
	return remotes, nil
}

// RemoteType returns a remote's backend type (for example "b2" or "s3").
// Reads the local rclone config only, no network.
func RemoteType(ctx context.Context, name string) (string, error) {
	out, err := runRclone(ctx, nil, []string{"listremotes", "--long"})
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		remote, kind, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && remote == name {
			return strings.TrimSpace(kind), nil
		}
	}
	return "", fmt.Errorf("rclone remote %q not found", name)
}

// CreateRemote drives `rclone config create` into the user's global rclone
// config. Params pass via argv: briefly visible in /proc to same-user
// processes, but with no shell nothing lands in history. Acceptable for
// bucket credentials, which guard only ciphertext; weigh it for SFTP/WebDAV
// passwords, which may guard a whole server (prefer key-based SFTP auth).
// Revisit if rclone grows a stdin-based config path.
func CreateRemote(ctx context.Context, name, kind string, params map[string]string) error {
	paths := []string{name, kind}
	for key, value := range params {
		paths = append(paths, key+"="+value)
	}
	_, err := runRclone(ctx, nil, []string{"config", "create"}, paths...)
	return err
}

// Preflight verifies rclone is installed and the remote exists.
func (s *RcloneStorage) Preflight(ctx context.Context) error {
	if !RcloneInstalled() {
		return fmt.Errorf("%w: install it (e.g. `pacman -S rclone`) and configure a remote with `rclone config`", ErrRcloneMissing)
	}
	remotes, err := ListRemotes(ctx)
	if err != nil {
		return err
	}
	for _, remote := range remotes {
		if remote == s.Remote {
			return nil
		}
	}
	return fmt.Errorf("rclone remote %q not found; create it with `rclone config`", s.Remote)
}

// Probe round-trips a marker object through the configured base path so a
// bad credential or bucket fails here, with context, not at the first
// real `set` days later.
func (s *RcloneStorage) Probe(ctx context.Context) error {
	path := s.basePath() + "/.notenv-probe"
	marker := []byte("notenv storage probe (safe to delete)")
	if _, err := runRclone(ctx, marker, []string{"rcat"}, path); err != nil {
		return fmt.Errorf("probe write failed: %w", err)
	}
	got, err := runRclone(ctx, nil, []string{"cat"}, path)
	if err != nil {
		return fmt.Errorf("probe read-back failed: %w", err)
	}
	if !bytes.Equal(got, marker) {
		return errors.New("probe read back different content than written")
	}
	if _, err := runRclone(ctx, nil, []string{"deletefile"}, path); err != nil {
		return fmt.Errorf("probe cleanup failed: %w", err)
	}
	return nil
}

func (s *RcloneStorage) Get(ctx context.Context, key string) ([]byte, error) {
	return s.catObject(ctx, s.objectPath(key))
}

// catObject downloads a single object, mapping both rclone's not-found exit
// and its empty-output directory quirk to ErrNotFound. `rclone cat` on a
// missing path treats it as a directory and concatenates its (zero) files
// (exit 0, empty output), and an empty result can never be a valid age blob.
func (s *RcloneStorage) catObject(ctx context.Context, path string) ([]byte, error) {
	out, err := runRclone(ctx, nil, []string{"cat"}, path)
	if err != nil {
		if isNotFoundExit(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (s *RcloneStorage) Put(ctx context.Context, key string, data []byte) error {
	_, err := runRclone(ctx, data, []string{"rcat"}, s.objectPath(key))
	return err
}

func (s *RcloneStorage) Delete(ctx context.Context, key string) error {
	if _, err := runRclone(ctx, nil, []string{"deletefile"}, s.objectPath(key)); err != nil {
		if isNotFoundLoose(err) {
			return nil // already gone
		}
		return err
	}
	return nil
}

// List returns base-relative keys of every object under prefix, recursively.
func (s *RcloneStorage) List(ctx context.Context, prefix string) ([]string, error) {
	root := s.basePath()
	clean := strings.Trim(prefix, "/")
	if clean != "" {
		root += "/" + clean
	}
	out, err := runRclone(ctx, nil, []string{"lsf", "-R", "--files-only"}, root)
	if err != nil {
		if isNotFoundExit(err) {
			return nil, nil // prefix doesn't exist yet, so no objects
		}
		return nil, err
	}
	var keys []string
	for line := range strings.SplitSeq(string(out), "\n") {
		rel := strings.TrimSpace(line)
		if rel == "" {
			continue
		}
		if clean != "" {
			rel = clean + "/" + rel
		}
		keys = append(keys, rel)
	}
	return keys, nil
}

const (
	headerObject       = ".header.json"
	headerBackupObject = headerObject + ".prev" // dot-prefixed: excluded by List's filter
)

func (s *RcloneStorage) GetHeader(ctx context.Context) ([]byte, error) {
	return s.catObject(ctx, s.basePath()+"/"+headerObject)
}

// PutHeader writes the header object. It does NOT back up first: the safe-write
// protocol (internal/keymgmt) calls BackupHeader before this, because a
// clobbered header locks the user out of every blob under it.
func (s *RcloneStorage) PutHeader(ctx context.Context, raw []byte) error {
	_, err := runRclone(ctx, raw, []string{"rcat"}, s.basePath()+"/"+headerObject)
	return err
}

// SwapHeader implements the compare-and-swap as read-compare-put-readback,
// which is the strongest rclone offers: object stores expose no conditional
// write through it. Two writers that both pass the compare inside the same
// sub-second window still last-write-wins; the read-back converts the loss
// into ErrHeaderChanged whenever the winner's bytes have already landed, and
// the one ordering it cannot see (our read-back completes before the winner's
// put) is recovered by the manifest's adoption path, never lost silently. A
// backend with native conditional writes can implement this atomically.
func (s *RcloneStorage) SwapHeader(ctx context.Context, base, updated []byte) error {
	current, err := s.GetHeader(ctx)
	if errors.Is(err, ErrNotFound) {
		current = nil
	} else if err != nil {
		return fmt.Errorf("re-read header before write: %w", err)
	}
	if !bytes.Equal(current, base) {
		return ErrHeaderChanged
	}
	if err := s.PutHeader(ctx, updated); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	readBack, err := s.GetHeader(ctx)
	if err != nil {
		return fmt.Errorf("read header back after write: %w", err)
	}
	if !bytes.Equal(readBack, updated) {
		return fmt.Errorf("%w (another writer landed over ours)", ErrHeaderChanged)
	}
	return nil
}

// BackupHeader copies the current header to its ".prev" sibling so a bad
// overwrite is recoverable. It is a no-op when the remote keeps native object
// versions (those versions are the backup) and when no header exists yet
// (nothing to preserve). Any other copy failure is returned so the caller can
// refuse to overwrite a header it couldn't back up.
func (s *RcloneStorage) BackupHeader(ctx context.Context) error {
	if s.Versioned {
		return nil
	}
	src := s.basePath() + "/" + headerObject
	dst := s.basePath() + "/" + headerBackupObject
	if _, err := runRclone(ctx, nil, []string{"copyto"}, src, dst); err != nil {
		if isNotFoundLoose(err) {
			return nil // no header yet, nothing to back up
		}
		return err
	}
	return nil
}

// RestoreHeaderBackup copies the ".prev" backup back over the header. Returns
// ErrNotFound when there is no backup to restore, including on versioned
// remotes, which keep no ".prev" (use rclone's version listing to recover a
// prior object version there).
func (s *RcloneStorage) RestoreHeaderBackup(ctx context.Context) error {
	if s.Versioned {
		return ErrNotFound
	}
	src := s.basePath() + "/" + headerBackupObject
	dst := s.basePath() + "/" + headerObject
	if _, err := runRclone(ctx, nil, []string{"copyto"}, src, dst); err != nil {
		if isNotFoundLoose(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (s *RcloneStorage) basePath() string {
	return s.Remote + ":" + strings.Trim(s.Base, "/")
}

func (s *RcloneStorage) objectPath(key string) string {
	return s.basePath() + "/" + key
}

// runRclone runs the binary with stdin (may be nil) and returns stdout.
// Errors include rclone's stderr for diagnosability. args holds the
// subcommand and flags (literals chosen by this package); paths holds the
// positional operands, which may embed user-influenced names, so the sink
// itself separates the two with an end-of-options marker. Upstream
// validation already keeps a leading dash out of every name that reaches
// here; this keeps the property local to the exec boundary instead of
// depending on a different package.
func runRclone(ctx context.Context, stdin []byte, args []string, paths ...string) ([]byte, error) {
	if len(paths) > 0 {
		args = append(append(slices.Clip(args), "--"), paths...)
	}
	cmd := exec.CommandContext(ctx, "rclone", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		return nil, &rcloneError{args: args, err: err, stderr: strings.TrimSpace(stderr.String())}
	}
	return stdout.Bytes(), nil
}

type rcloneError struct {
	args   []string
	err    error
	stderr string
}

func (e *rcloneError) Error() string {
	msg := fmt.Sprintf("rclone %s: %v", e.args[0], e.err)
	if e.stderr != "" {
		msg += "\n" + e.stderr
	}
	return msg
}

func (e *rcloneError) Unwrap() error { return e.err }

// isNotFoundExit reports rclone's dedicated not-found exit codes (3: directory,
// 4: file). This is the only not-found signal reads (cat, lsf) trust: a
// GetHeader not-found drives the virgin-storage decision in the key ceremony,
// and stderr text (which shifts across rclone versions and locales) must never
// be able to fake that.
func isNotFoundExit(err error) bool {
	re, ok := errors.AsType[*rcloneError](err)
	if !ok {
		return false
	}
	exit, ok := errors.AsType[*exec.ExitError](re.err)
	if !ok {
		return false
	}
	switch exit.ExitCode() {
	case rcloneExitDirNotFound, rcloneExitFileNotFound:
		return true
	}
	return false
}

// isNotFoundLoose additionally matches rclone's stderr text, for the
// subcommands that report a missing source with only a generic exit 1
// (`copyto`, `deletefile`). The looseness is acceptable there: a false match
// skips backing up a header that most likely doesn't exist, or re-deletes an
// already-missing object: housekeeping, never a trust decision.
func isNotFoundLoose(err error) bool {
	if isNotFoundExit(err) {
		return true
	}
	re, ok := errors.AsType[*rcloneError](err)
	if !ok {
		return false
	}
	return strings.Contains(re.stderr, "not found") || strings.Contains(re.stderr, "doesn't exist")
}
