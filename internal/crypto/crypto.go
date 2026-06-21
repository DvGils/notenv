// Package crypto wraps age. Cipher is the encrypt/decrypt seam, satisfied by
// PassphraseCipher (symmetric, passphrase-derived, used to wrap key slots) and
// MasterKey (the random master that encrypts every blob).
package crypto

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}
