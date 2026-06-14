package main

import (
	"context"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/backend/local"
	"github.com/DvGils/notenv/internal/config"
)

// vaultStorage is everything a command needs from a storage backend: the
// object store, the header side, and the connectivity checks.
type vaultStorage interface {
	backend.Backend
	backend.HeaderStore
	Preflight(context.Context) error
	Probe(context.Context) error
}

// openStorage builds the backend for a resolved storage: a local vault
// directory or an rclone remote, behind the same interface.
func openStorage(eff config.Effective) vaultStorage {
	if eff.Local() {
		return &local.Storage{Path: eff.Path}
	}
	return &backend.RcloneStorage{Remote: eff.Remote, Base: eff.Base}
}
