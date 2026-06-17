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

// scryptWorkFactor (the scrypt cost notenv wraps passphrase slots under) is defined
// in workfactor.go / workfactor_fastkdf.go: production is 19, and a build with
// `-tags fastkdf` (test and fuzz runs only) lowers it so the suite is not dominated
// by scrypt. workfactor.go carries the rationale for 19.

// maxScryptWorkFactor bounds the scrypt cost notenv will spend opening a slot.
// age's decrypt side otherwise accepts up to 2^22 (minutes and gigabytes per
// attempt), so a storage-write attacker with no key could plant a slot stamped at
// a huge work factor and make the victim's next unlock burn that work, pre-auth,
// for every slot tried. age checks the embedded factor before running scrypt, so a
// slot above this cap is refused for free. It is scryptWorkFactor+1: every slot
// notenv writes is at or below the current factor, and the +1 lets a slot written
// one bump in the future still open on an older binary. A planted slot can never
// weaken security (its key is not a recipient of the master, so Unlock skips it);
// the cap only stops wasted work. A var, not a const, so a test can lower it
// without building costly high-factor fixtures.
var maxScryptWorkFactor = scryptWorkFactor + 1

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
	identity.SetMaxWorkFactor(maxScryptWorkFactor)
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
