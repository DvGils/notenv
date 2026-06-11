//go:build windows

package keyring

import "os"

// openConsole opens the console input buffer for a hidden prompt, independent
// of what stdin is connected to. CONIN$ is Windows' /dev/tty equivalent; it
// must be opened read-write because term.ReadPassword toggles the console
// mode on the handle, and SetConsoleMode needs write access.
func openConsole() (*os.File, error) {
	return os.OpenFile("CONIN$", os.O_RDWR, 0)
}
