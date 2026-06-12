// Package chaos wraps a backend.Backend and injects deterministic faults from a
// seed, for torture-testing code that must stay correct when storage misbehaves.
//
// The only fault modelled today is an interrupted upload: a Put fails *before*
// storing, so the write atomically never lands. That keeps an oracle exact (a
// failed write is simply a write that did not happen) while still exercising the
// recovery paths around partial progress: a compaction whose snapshot write is
// interrupted, a `set` whose segment never arrives, and so on.
package chaos

import (
	"context"
	"errors"
	"math/rand"

	"github.com/DvGils/notenv/internal/backend"
)

// Backend is a fault-injecting wrapper around another backend. It is
// deterministic for a given seed and not safe for concurrent use.
type Backend struct {
	inner   backend.Backend
	rng     *rand.Rand
	putFail float64
}

// Options configures the injected faults.
type Options struct {
	// PutFailRate is the probability in [0,1] that a Put fails before storing.
	PutFailRate float64
}

// New wraps inner with faults driven by seed.
func New(inner backend.Backend, seed int64, opts Options) *Backend {
	return &Backend{inner: inner, rng: rand.New(rand.NewSource(seed)), putFail: opts.PutFailRate}
}

// ErrInterrupted is returned by a Put the wrapper chooses to interrupt.
var ErrInterrupted = errors.New("chaos: interrupted upload")

func (b *Backend) Put(ctx context.Context, key string, data []byte) error {
	if b.putFail > 0 && b.rng.Float64() < b.putFail {
		return ErrInterrupted // fail before storing: the write never lands
	}
	return b.inner.Put(ctx, key, data)
}

func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	return b.inner.Get(ctx, key)
}

func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	return b.inner.List(ctx, prefix)
}

func (b *Backend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

var _ backend.Backend = (*Backend)(nil)
