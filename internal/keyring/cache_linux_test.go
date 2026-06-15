//go:build linux

package keyring

import (
	"testing"
	"time"
)

// keyctl_set_timeout(..., 0) clears the timeout, so a positive sub-second TTL must
// never floor to 0: that would cache the master for the whole login session instead
// of the short lifetime the user configured.
func TestKeyTimeoutSecondsFloorsToOne(t *testing.T) {
	cases := map[time.Duration]int{
		1 * time.Millisecond:    1,
		500 * time.Millisecond:  1,
		999 * time.Millisecond:  1,
		1 * time.Second:         1,
		1500 * time.Millisecond: 1,
		90 * time.Second:        90,
		time.Hour:               3600,
	}
	for ttl, want := range cases {
		if got := keyTimeoutSeconds(ttl); got != want {
			t.Errorf("keyTimeoutSeconds(%v) = %d, want %d", ttl, got, want)
		}
	}
}
