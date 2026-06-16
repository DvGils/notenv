// Package runtimedir reports whether a directory is RAM-backed scratch space, so
// a caller that promises secret material is "never written to persistent disk"
// can verify the location rather than trust XDG_RUNTIME_DIR to be the tmpfs the
// XDG spec says it should be. "RAM-only" is a Linux-only guarantee in notenv (see
// the threat model); off Linux there is no verified equivalent.
package runtimedir
