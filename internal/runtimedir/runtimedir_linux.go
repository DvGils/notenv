//go:build linux

package runtimedir

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// IsRAMBacked reports whether dir is a private, RAM-backed directory: it exists,
// is owned by the current user, denies all access to group and other (so nothing
// it holds is readable by another local user), and sits on a tmpfs or ramfs
// filesystem (so its contents live in RAM and never reach persistent disk). Any
// error or unmet condition yields false, so a caller fails safe: disable a cache,
// or ask before falling back to on-disk storage.
func IsRAMBacked(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false // readable or writable by group/other
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		return false // not owned by the current user
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return false
	}
	// f_type carries a 32-bit filesystem magic; compare as uint32 so the constants
	// (RAMFS_MAGIC has bit 31 set) behave the same on 32- and 64-bit arches.
	t := uint32(fs.Type)
	return t == uint32(unix.TMPFS_MAGIC) || t == uint32(unix.RAMFS_MAGIC)
}
