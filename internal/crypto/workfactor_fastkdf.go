//go:build fastkdf

package crypto

// scryptWorkFactor under `-tags fastkdf` is lowered to a near-instant cost so the
// test and fuzz suites are not dominated by scrypt (a single header at 2^19 costs
// ~hundreds of ms, and the suite creates and unlocks many). The work factor is a
// cost parameter, not a correctness one: the wrapping, unlocking, and cap logic are
// identical at any value, so a fast factor exercises the same code paths.
//
// This tag is for `go test` / `go test -fuzz` builds ONLY. A release build never
// carries it (it would weaken every passphrase slot), so production always uses the
// 19 in workfactor.go.
const scryptWorkFactor = 10
