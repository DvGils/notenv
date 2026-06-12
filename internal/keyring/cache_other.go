//go:build !linux && !darwin && !windows

package keyring

import "time"

// nullCache never caches: every Get misses, so every acquisition prompts.
// Degraded but correct, for platforms with no native store wired up.
type nullCache struct{}

const cacheIsNull = true

func newCache() Cache { return nullCache{} }

func (nullCache) Get(string) (string, bool)                 { return "", false }
func (nullCache) Store(string, string, time.Duration) error { return nil }
func (nullCache) Drop(string)                               {}
