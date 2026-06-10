//go:build !linux

package keyring

import "time"

// nullCache never caches: every Get misses, so every acquisition prompts.
// Degraded but correct; native macOS/Windows stores come later.
type nullCache struct{}

func newCache() Cache { return nullCache{} }

func (nullCache) Get(string) (string, bool)                 { return "", false }
func (nullCache) Store(string, string, time.Duration) error { return nil }
func (nullCache) Drop(string)                               {}
