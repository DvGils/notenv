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
//
// There is no argv-free fix available: as of rclone v1.74 `config create`
// (and `config update`/`config password`) take parameter values only as argv;
// only `rclone obscure -` reads from stdin. Writing rclone.conf directly would
// avoid argv but breaks configs encrypted with RCLONE_CONFIG_PASS (which
// `config create` handles transparently), so it is rejected. The argv-free path
// for a user who wants it already exists in `notenv setup`: pick "I'll run
// rclone config myself" to type secrets at rclone's own stdin prompts, then
// point notenv at the remote.
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
	got, err := runRcloneCapped(ctx, MaxHeaderBytes, []string{"cat"}, path)
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
	return s.catObject(ctx, s.objectPath(key), MaxObjectBytes)
}

// catObject downloads a single object, reading at most max bytes so a hostile
// remote cannot OOM the process by serving a huge object (ErrObjectTooLarge past
// the cap). It maps both rclone's not-found exit and its empty-output directory
// quirk to ErrNotFound. `rclone cat` on a missing path treats it as a directory
// and concatenates its (zero) files (exit 0, empty output), and an empty result
// can never be a valid age blob.
func (s *RcloneStorage) catObject(ctx context.Context, path string, max int64) ([]byte, error) {
	out, err := runRcloneCapped(ctx, max, []string{"cat"}, path)
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
		// Modern rclone reports a missing target with a dedicated not-found exit, so
		// "already gone" is unambiguous and cheap.
		if isNotFoundExit(err) {
			return nil
		}
		// Older rclone (e.g. 1.60) instead exits with a generic code and "is a
		// directory or doesn't exist" for a missing target, so the exit code alone
		// cannot separate "already gone" from a real failure. Rather than match that
		// message (a genuine failure could carry similar text, and reporting a delete
		// that never happened is the dangerous direction), confirm the actual state:
		// Delete's postcondition is that the object is absent, so if it is already
		// gone the delete is satisfied. Unlike deletefile, cat reports a missing
		// object as a clean not-found on every rclone version, so Get is reliable
		// where the deletefile exit code is not. This runs only on the error path.
		if _, getErr := s.Get(ctx, key); errors.Is(getErr, ErrNotFound) {
			return nil
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
	// Cap the listing like any other read: a hostile remote could otherwise stream
	// an unbounded `lsf` output (millions of object names) and OOM the process.
	out, err := runRcloneCapped(ctx, MaxListBytes, []string{"lsf", "-R", "--files-only"}, root)
	if err != nil {
		if isNotFoundExit(err) {
			return nil, nil // prefix doesn't exist yet, so no objects
		}
		return nil, err
	}
	return keysFromLsf(out, clean), nil
}

// keysFromLsf turns `rclone lsf -R --files-only` output into base-relative keys,
// re-prefixing them when the listing was scoped, and drops reserved plumbing (the
// header, its backup, the probe). rclone returns those as ordinary files, unlike
// the local backend; routing the filter through IsReserved keeps the two List
// implementations from diverging (a divergence once let orphan cleanup delete the
// header). Split out from List so the filter is unit-testable without rclone.
func keysFromLsf(out []byte, clean string) []string {
	var keys []string
	for line := range strings.SplitSeq(string(out), "\n") {
		rel := strings.TrimSpace(line)
		if rel == "" {
			continue
		}
		if clean != "" {
			rel = clean + "/" + rel
		}
		if IsReserved(rel) {
			continue
		}
		keys = append(keys, rel)
	}
	return keys
}

// Header object names. These are reserved (see IsReserved); List excludes them.
const (
	headerObject       = HeaderName
	headerBackupObject = HeaderBackupName
)

func (s *RcloneStorage) GetHeader(ctx context.Context) ([]byte, error) {
	return s.catObject(ctx, s.basePath()+"/"+headerObject, MaxHeaderBytes)
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
// sub-second window still last-write-wins; the read-back converts the loss into
// ErrHeaderChanged whenever the winner's bytes have already landed, so the
// loser re-reads, re-applies, and retries (keymgmt.UpdateHeader), and its
// superseded blob is reclaimed as an orphan. A read-back that cannot confirm the
// write surfaces as ErrCommitUncertain (the put may have landed, so the caller
// must not roll back). A backend with native conditional writes can implement
// this atomically.
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
		// The Put returned success but we cannot read it back to confirm. It may
		// have landed, so the caller must not roll back a data object it wrote for
		// this header (see ErrCommitUncertain).
		return fmt.Errorf("%w: read header back after write: %v", ErrCommitUncertain, err)
	}
	if !bytes.Equal(readBack, updated) {
		return fmt.Errorf("%w (another writer landed over ours)", ErrHeaderChanged)
	}
	return nil
}

// BackupHeader copies the current header to its ".prev" sibling so a bad overwrite
// is recoverable (a server-side copy that moves no bytes through the client; a
// remote's own version history, if any, is an extra backstop, not a substitute).
// The safe-write protocol calls this ONLY when a header exists, so every copy
// failure is returned and the write is refused: a missing source here is a race,
// not the virgin case, and must not be read as "nothing to back up". Swallowing a
// "not found" was unsafe because rclone emits that text for non-absent failures
// too (e.g. "Source doesn't exist or is a directory and destination is a file").
func (s *RcloneStorage) BackupHeader(ctx context.Context) error {
	src := s.basePath() + "/" + headerObject
	dst := s.basePath() + "/" + headerBackupObject
	_, err := runRclone(ctx, nil, []string{"copyto"}, src, dst)
	return err
}

// RestoreHeaderBackup restores the ".prev" backup over the header. Returns
// ErrNotFound when there is no backup to restore (none has been written yet).
func (s *RcloneStorage) RestoreHeaderBackup(ctx context.Context) error {
	// Read the backup through cat (whose not-found is the trustworthy exit 3/4,
	// mapped to ErrNotFound by catObject) and write it back as the header, rather
	// than letting copyto decide: copyto reports a missing source over an existing
	// header as a generic exit 1, indistinguishable from a real copy failure, so it
	// cannot tell "no backup yet" from "restore failed". Reading then writing keeps
	// those apart; headers are tiny, so the extra round-trip is negligible on this
	// rare recovery path.
	prev, err := s.catObject(ctx, s.basePath()+"/"+headerBackupObject, MaxHeaderBytes)
	if err != nil {
		return err
	}
	return s.PutHeader(ctx, prev)
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
// positional operands, which may embed user-influenced names. The `--`
// end-of-options marker is what makes this sink safe on its own: everything
// after it is an operand, never a flag, whatever upstream did or did not
// validate. (The config layer also rejects a remote or base with a leading
// dash, a stray ':', or a control character, but that is defense in depth, not
// what this boundary relies on.)
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

// runRcloneCapped runs rclone for a read command (no stdin) and returns at most
// max bytes of stdout, with ErrObjectTooLarge if the child produces more. The
// child writes into a capped buffer that stops accumulating and cancels the
// command the instant the cap is passed, so a remote serving a multi-GB object
// can neither exhaust memory nor keep the transfer running. cmd.Run waits for the
// stdout copier to finish before returning, so reading cw.exceeded afterward is
// race-free.
func runRcloneCapped(ctx context.Context, max int64, args []string, paths ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if len(paths) > 0 {
		args = append(append(slices.Clip(args), "--"), paths...)
	}
	cmd := exec.CommandContext(ctx, "rclone", args...)
	cw := &cappedWriter{max: max, cancel: cancel}
	var stderr bytes.Buffer
	cmd.Stdout = cw
	cmd.Stderr = &stderr
	err := cmd.Run()
	if cw.exceeded {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrObjectTooLarge, max)
	}
	if err != nil {
		return nil, &rcloneError{args: args, err: err, stderr: strings.TrimSpace(stderr.String())}
	}
	return cw.buf.Bytes(), nil
}

// cappedWriter accumulates up to max bytes; the first write that would exceed max
// sets exceeded, cancels the command (to stop the transfer), and from then on
// discards rather than buffers, so memory stays bounded even as the killed child
// drains. It is written only by os/exec's single stdout-copy goroutine.
type cappedWriter struct {
	buf      bytes.Buffer
	max      int64
	exceeded bool
	cancel   context.CancelFunc
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.exceeded {
		return len(p), nil // already over the cap: discard while the child is killed
	}
	if int64(w.buf.Len())+int64(len(p)) > w.max {
		w.exceeded = true
		w.cancel()
		return len(p), nil
	}
	return w.buf.Write(p)
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
// 4: file). It is the ONLY not-found signal notenv trusts, never stderr text
// (which shifts across rclone versions and locales and could let a real failure
// masquerade as not-found, masking it). cat (reads, GetHeader, catObject) and
// deletefile (Delete) both return 3/4 for a genuinely missing object, so the exit
// code is sufficient and exact there. copyto is the exception: it reports a missing
// source over an existing destination as a generic exit 1, so the restore path does
// not classify copyto at all, it reads the backup through catObject instead.
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
