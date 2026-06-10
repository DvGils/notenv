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

func encryptTo(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
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
