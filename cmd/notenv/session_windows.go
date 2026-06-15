//go:build windows

package main

import "golang.org/x/sys/windows"

// pidAlive reports whether a process with this PID exists and has not exited.
// It opens the process for a limited-information query and reads its exit code;
// a still-running process reports STILL_ACTIVE.
func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true // opened but could not query: assume alive
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
