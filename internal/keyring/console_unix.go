//go:build !windows

package keyring

import "os"

// openConsole opens the controlling terminal for a hidden prompt, independent
// of what stdin is connected to.
func openConsole() (*os.File, error) {
	return os.Open("/dev/tty")
}
