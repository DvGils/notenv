//go:build !fastkdf

package crypto

// scryptWorkFactor is the scrypt cost (log2 of the iteration count) notenv wraps
// passphrase slots under, overriding age's default of 18. Each step up doubles
// both the time and the memory (~256 MB at 18) an offline guess costs, so 19 puts
// a cold unlock near two seconds and a brute-force guess behind ~512 MB of
// memory-hard work. Unlike a longer generated passphrase, which only strengthens
// the credentials notenv itself mints, the work factor raises the per-guess cost
// of every slot, including a user's own weak choice: the one credential notenv
// cannot make stronger any other way.
//
// Bumping it stays backward compatible (see suite.go): age records the work
// factor inside each wrapped blob, so a slot wrapped at 18 still opens, and a slot
// adopts the new cost the next time its passphrase is set or rotated. age's
// decrypt side accepts up to 2^22 by default; maxScryptWorkFactor clamps that.
//
// This is the production value, used by every build except `-tags fastkdf`, which
// is reserved for test and fuzz runs (see workfactor_fastkdf.go). A release build
// must never carry that tag; TestProductionScryptWorkFactor guards the value here.
const scryptWorkFactor = 19
