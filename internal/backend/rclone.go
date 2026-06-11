package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	// natively), so the .prev backup copy (~3s server-side on B2) is
	// redundant and skipped.
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
	out, err := runRclone(ctx, nil, "listremotes")
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
	out, err := runRclone(ctx, nil, "listremotes", "--long")
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
// config. Params pass via argv: briefly visible in /proc, but with no shell
// nothing lands in history. This is acceptable because storage credentials
// only ever guard ciphertext. Revisit if rclone grows a stdin-based config
// path.
func CreateRemote(ctx context.Context, name, kind string, params map[string]string) error {
	args := []string{"config", "create", name, kind}
	for key, value := range params {
		args = append(args, key+"="+value)
	}
	_, err := runRclone(ctx, nil, args...)
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
	if _, err := runRclone(ctx, marker, "rcat", path); err != nil {
		return fmt.Errorf("probe write failed: %w", err)
	}
	got, err := runRclone(ctx, nil, "cat", path)
	if err != nil {
		return fmt.Errorf("probe read-back failed: %w", err)
	}
	if !bytes.Equal(got, marker) {
		return errors.New("probe read back different content than written")
	}
	if _, err := runRclone(ctx, nil, "deletefile", path); err != nil {
		return fmt.Errorf("probe cleanup failed: %w", err)
	}
	return nil
}

func (s *RcloneStorage) Get(ctx context.Context, namespace string) ([]byte, error) {
	return s.catObject(ctx, s.objectPath(namespace))
}

// catObject downloads a single object, mapping both rclone's not-found exit
// and its empty-output directory quirk to ErrNotFound. `rclone cat` on a
// missing path treats it as a directory and concatenates its (zero) files
// (exit 0, empty output), and an empty result can never be a valid age blob.
func (s *RcloneStorage) catObject(ctx context.Context, path string) ([]byte, error) {
	out, err := runRclone(ctx, nil, "cat", path)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (s *RcloneStorage) Put(ctx context.Context, namespace string, ciphertext []byte) error {
	path := s.objectPath(namespace)
	// Best-effort previous-version copy for remotes without native object
	// versioning. The ".prev" suffix keeps it out of List's "*.age" filter.
	if !s.Versioned {
		_, _ = runRclone(ctx, nil, "copyto", path, path+".prev")
	}
	_, err := runRclone(ctx, ciphertext, "rcat", path)
	return err
}

func (s *RcloneStorage) List(ctx context.Context) ([]string, error) {
	out, err := runRclone(ctx, nil, "lsf", "--files-only", s.basePath())
	if err != nil {
		if isNotFound(err) {
			return nil, nil // base dir doesn't exist yet, so no namespaces
		}
		return nil, err
	}
	var namespaces []string
	for line := range strings.SplitSeq(string(out), "\n") {
		name, ok := strings.CutSuffix(strings.TrimSpace(line), ".age")
		if !ok || strings.HasPrefix(name, ".") { // dot-objects (.header.json, .prev) aren't namespaces
			continue
		}
		namespaces = append(namespaces, name)
	}
	return namespaces, nil
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
// clobbered header locks the user out of every blob under it. Creation on
// virgin storage calls PutHeader directly (nothing to back up yet).
func (s *RcloneStorage) PutHeader(ctx context.Context, raw []byte) error {
	_, err := runRclone(ctx, raw, "rcat", s.basePath()+"/"+headerObject)
	return err
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
	if _, err := runRclone(ctx, nil, "copyto", src, dst); err != nil {
		if isNotFound(err) {
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
	if _, err := runRclone(ctx, nil, "copyto", src, dst); err != nil {
		if isNotFound(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (s *RcloneStorage) basePath() string {
	return s.Remote + ":" + strings.Trim(s.Base, "/")
}

func (s *RcloneStorage) objectPath(namespace string) string {
	return s.basePath() + "/" + namespace + ".age"
}

// runRclone runs the binary with stdin (may be nil) and returns stdout.
// Errors include rclone's stderr for diagnosability.
func runRclone(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
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

func isNotFound(err error) bool {
	re, ok := errors.AsType[*rcloneError](err)
	if !ok {
		return false
	}
	if exit, ok := errors.AsType[*exec.ExitError](re.err); ok {
		switch exit.ExitCode() {
		case rcloneExitDirNotFound, rcloneExitFileNotFound:
			return true
		}
	}
	// Exit code isn't always 3/4: a `copyto` whose source is missing reports a
	// generic exit 1 with a "doesn't exist" message, so match the text too.
	return strings.Contains(re.stderr, "not found") || strings.Contains(re.stderr, "doesn't exist")
}
