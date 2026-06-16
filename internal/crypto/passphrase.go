package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// ErrWrongPassphrase is returned when a passphrase does not match the
// ciphertext (or, for Header.Unlock, any key slot).
var ErrWrongPassphrase = errors.New("wrong passphrase")

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
// decrypt side accepts up to 2^22 by default, well above this.
const scryptWorkFactor = 19

// PassphraseCipher encrypts to an age scrypt recipient (symmetric,
// passphrase-derived). In the header model it wraps key-slot contents,
// not data blobs.
type PassphraseCipher struct {
	passphrase string
}

func NewPassphraseCipher(passphrase string) *PassphraseCipher {
	return &PassphraseCipher{passphrase: passphrase}
}

func (c *PassphraseCipher) Encrypt(plaintext []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(c.passphrase)
	if err != nil {
		return nil, fmt.Errorf("age recipient: %w", err)
	}
	recipient.SetWorkFactor(scryptWorkFactor)
	return encryptTo(plaintext, recipient)
}

func (c *PassphraseCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	identity, err := age.NewScryptIdentity(c.passphrase)
	if err != nil {
		return nil, fmt.Errorf("age identity: %w", err)
	}
	plaintext, err := decryptWith(ciphertext, identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, ErrWrongPassphrase
		}
		return nil, err
	}
	return plaintext, nil
}

func encryptTo(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	return buf.Bytes(), nil
}

func decryptWith(ciphertext []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return plaintext, nil
}
